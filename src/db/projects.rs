use crate::db::Db;
use crate::domain::{new_id, now_rfc3339, Project, ScopeStatus};
use crate::scope::{Scope, ScopeRule};
use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};

#[derive(Debug, Clone)]
pub struct ScopeRevision {
    pub id: String,
    pub project_id: String,
    pub version: i64,
    pub scope: Scope,
    pub status: ScopeStatus,
    pub note: String,
    pub created_by: String,
    pub created_at: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<String>,
}

impl ScopeRevision {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "project_id": self.project_id,
            "version": self.version,
            "status": self.status.as_str(),
            "note": self.note,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "rules": self.scope.rules,
        })
    }
}

pub fn validate_project_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        anyhow::bail!("project name must be between 1 and 64 characters");
    }
    if name.starts_with('.') || name.contains('/') || name.contains('\\') || name.contains("..") {
        anyhow::bail!("project name contains unsupported path characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        anyhow::bail!("project name may contain letters, digits, '-', '_' and '.'");
    }
    if !name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        anyhow::bail!("project name must start with a letter or digit");
    }
    Ok(name.to_string())
}

fn map_project(row: &rusqlite::Row<'_>) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        client: row.get(2)?,
        description: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        source: row.get(6)?,
        source_project_id: row.get(7)?,
    })
}

fn map_scope_revision(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScopeRevision> {
    let rules_raw: String = row.get(3)?;
    let rules: Vec<ScopeRule> = serde_json::from_str(&rules_raw).unwrap_or_default();
    Ok(ScopeRevision {
        id: row.get(0)?,
        project_id: row.get(1)?,
        version: row.get(2)?,
        scope: Scope { rules },
        status: ScopeStatus::parse(&row.get::<_, String>(4)?).unwrap_or(ScopeStatus::Draft),
        note: row.get(5)?,
        created_by: row.get(6)?,
        created_at: row.get(7)?,
        approved_by: row.get(8)?,
        approved_at: row.get(9)?,
    })
}

impl Db {
    pub fn create_project(
        &self,
        name: &str,
        client: &str,
        description: &str,
        source: Option<&str>,
        source_project_id: Option<&str>,
        actor: &str,
    ) -> Result<Project> {
        let name = validate_project_name(name)?;
        let now = now_rfc3339();
        let project = Project {
            id: new_id("prj"),
            name,
            client: client.trim().to_string(),
            description: description.trim().to_string(),
            created_at: now.clone(),
            updated_at: now,
            source: source.map(str::to_string),
            source_project_id: source_project_id.map(str::to_string),
        };
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO projects(id, name, client, description, created_at, updated_at, source, source_project_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                project.id,
                project.name,
                project.client,
                project.description,
                project.created_at,
                project.updated_at,
                project.source,
                project.source_project_id
            ],
        )
        .with_context(|| format!("project '{}' already exists", project.name))?;
        drop(conn);
        self.create_scope_revision(
            &project.id,
            1,
            &Scope::default(),
            ScopeStatus::Draft,
            "initial scope",
            actor,
        )?;
        self.audit(
            actor,
            "project.create",
            "project",
            Some(&project.id),
            &serde_json::json!({"name": project.name, "source": project.source}),
        )?;
        Ok(project)
    }

    pub fn project_by_id(&self, id: &str) -> Result<Option<Project>> {
        let conn = self.connect()?;
        let project = conn
            .query_row(
                "SELECT id, name, client, description, created_at, updated_at, source, source_project_id
                 FROM projects WHERE id = ?1",
                params![id],
                map_project,
            )
            .optional()?;
        Ok(project)
    }

    pub fn project_by_name(&self, name: &str) -> Result<Option<Project>> {
        let conn = self.connect()?;
        let project = conn
            .query_row(
                "SELECT id, name, client, description, created_at, updated_at, source, source_project_id
                 FROM projects WHERE name = ?1",
                params![name],
                map_project,
            )
            .optional()?;
        Ok(project)
    }

    pub fn list_projects(&self, limit: u32, offset: u32) -> Result<(Vec<Project>, i64)> {
        let conn = self.connect()?;
        let total = conn.query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?;
        let mut stmt = conn.prepare(
            "SELECT id, name, client, description, created_at, updated_at, source, source_project_id
             FROM projects ORDER BY name COLLATE NOCASE LIMIT ?1 OFFSET ?2",
        )?;
        let items = stmt
            .query_map(params![limit, offset], map_project)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((items, total))
    }

    pub fn update_project_metadata(
        &self,
        project_id: &str,
        client: Option<&str>,
        description: Option<&str>,
    ) -> Result<Option<Project>> {
        let Some(existing) = self.project_by_id(project_id)? else {
            return Ok(None);
        };
        let conn = self.connect()?;
        conn.execute(
            "UPDATE projects SET client = ?1, description = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                client.unwrap_or(&existing.client),
                description.unwrap_or(&existing.description),
                now_rfc3339(),
                project_id
            ],
        )?;
        self.project_by_id(project_id)
    }

    pub fn create_scope_revision(
        &self,
        project_id: &str,
        version: i64,
        scope: &Scope,
        status: ScopeStatus,
        note: &str,
        actor: &str,
    ) -> Result<ScopeRevision> {
        let now = now_rfc3339();
        let revision = ScopeRevision {
            id: new_id("scr"),
            project_id: project_id.to_string(),
            version,
            scope: scope.clone(),
            status,
            note: note.to_string(),
            created_by: actor.to_string(),
            created_at: now,
            approved_by: None,
            approved_at: None,
        };
        let conn = self.connect()?;
        conn.execute(
            "INSERT INTO scope_revisions(id, project_id, version, rules, status, note, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                revision.id,
                revision.project_id,
                revision.version,
                serde_json::to_string(&revision.scope.rules)?,
                revision.status.as_str(),
                revision.note,
                revision.created_by,
                revision.created_at
            ],
        )?;
        Ok(revision)
    }

    pub fn current_scope(&self, project_id: &str) -> Result<Option<ScopeRevision>> {
        let conn = self.connect()?;
        let revision = conn
            .query_row(
                "SELECT id, project_id, version, rules, status, note, created_by, created_at,
                        approved_by, approved_at
                 FROM scope_revisions WHERE project_id = ?1 ORDER BY version DESC LIMIT 1",
                params![project_id],
                map_scope_revision,
            )
            .optional()?;
        Ok(revision)
    }

    pub fn scope_by_version(
        &self,
        project_id: &str,
        version: i64,
    ) -> Result<Option<ScopeRevision>> {
        let conn = self.connect()?;
        let revision = conn
            .query_row(
                "SELECT id, project_id, version, rules, status, note, created_by, created_at,
                        approved_by, approved_at
                 FROM scope_revisions WHERE project_id = ?1 AND version = ?2",
                params![project_id, version],
                map_scope_revision,
            )
            .optional()?;
        Ok(revision)
    }

    pub fn scope_by_id(&self, id: &str) -> Result<Option<ScopeRevision>> {
        let conn = self.connect()?;
        let revision = conn
            .query_row(
                "SELECT id, project_id, version, rules, status, note, created_by, created_at,
                        approved_by, approved_at
                 FROM scope_revisions WHERE id = ?1",
                params![id],
                map_scope_revision,
            )
            .optional()?;
        Ok(revision)
    }

    pub fn scope_revisions(&self, project_id: &str) -> Result<Vec<ScopeRevision>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare(
            "SELECT id, project_id, version, rules, status, note, created_by, created_at,
                    approved_by, approved_at
             FROM scope_revisions WHERE project_id = ?1 ORDER BY version DESC",
        )?;
        let items = stmt
            .query_map(params![project_id], map_scope_revision)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(items)
    }

    pub fn replace_scope(
        &self,
        project_id: &str,
        expected_version: Option<i64>,
        scope: &Scope,
        note: &str,
        actor: &str,
        approve: bool,
    ) -> Result<ScopeRevision> {
        let current = self
            .current_scope(project_id)?
            .context("project scope is missing")?;
        if let Some(expected) = expected_version {
            if expected != current.version {
                anyhow::bail!(
                    "scope version conflict: expected {expected}, current {}",
                    current.version
                );
            }
        }
        let status = if approve {
            ScopeStatus::Approved
        } else {
            ScopeStatus::Draft
        };
        let revision = self.create_scope_revision(
            project_id,
            current.version + 1,
            scope,
            status,
            note,
            actor,
        )?;
        if approve {
            self.mark_scope_approved(&revision.id, actor)?;
        }
        self.audit(
            actor,
            "scope.update",
            "project",
            Some(project_id),
            &serde_json::json!({
                "version": revision.version,
                "rules": revision.scope.rules.len(),
                "status": revision.status.as_str()
            }),
        )?;
        self.scope_by_id(&revision.id)?
            .context("scope revision disappeared")
    }

    pub fn mark_scope_approved(&self, revision_id: &str, actor: &str) -> Result<()> {
        let conn = self.connect()?;
        conn.execute(
            "UPDATE scope_revisions SET status = 'approved', approved_by = ?1, approved_at = ?2
             WHERE id = ?3",
            params![actor, now_rfc3339(), revision_id],
        )?;
        Ok(())
    }

    pub fn approve_scope(
        &self,
        project_id: &str,
        version: i64,
        actor: &str,
    ) -> Result<ScopeRevision> {
        let Some(revision) = self.scope_by_version(project_id, version)? else {
            anyhow::bail!("scope revision not found");
        };
        if revision.scope.rules.iter().all(|rule| rule.exclusion) {
            anyhow::bail!("cannot approve a scope without at least one allowed rule");
        }
        self.mark_scope_approved(&revision.id, actor)?;
        self.audit(
            actor,
            "scope.approve",
            "project",
            Some(project_id),
            &serde_json::json!({"version": version}),
        )?;
        self.scope_by_id(&revision.id)?
            .context("scope revision disappeared")
    }
}
