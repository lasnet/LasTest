(() => {
  "use strict";

  const state = {
    me: null,
    projects: [],
    projectId: "",
    project: null,
    dashboard: null,
    scope: null,
    scopeHistory: [],
    rules: [],
    taskTypes: [],
    jobs: [],
    view: "dashboard",
    poll: null,
    loading: false,
  };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function append(parent, ...children) {
    for (const child of children) {
      if (child === null || child === undefined) continue;
      parent.appendChild(child);
    }
    return parent;
  }

  function notice(message, kind = "info") {
    const node = $("#notice");
    if (!message) {
      node.hidden = true;
      node.textContent = "";
      return;
    }
    node.hidden = false;
    node.className = `notice ${kind}`;
    node.textContent = message;
  }

  function table(columns, rows, cellValue) {
    if (!rows || rows.length === 0) {
      return el("p", "No data for this view.", "empty");
    }
    const wrapper = el("div", null, "table-wrap");
    const tbl = el("table");
    const thead = el("thead");
    const headerRow = el("tr");
    for (const column of columns) headerRow.appendChild(el("th", column));
    thead.appendChild(headerRow);
    const tbody = el("tbody");
    for (const row of rows) {
      const tr = el("tr");
      for (const column of columns) {
        const td = el("td");
        const value = cellValue ? cellValue(row, column) : row[column];
        if (value instanceof Node) td.appendChild(value);
        else td.textContent = value === null || value === undefined ? "" : String(value);
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    append(tbl, thead, tbody);
    wrapper.appendChild(tbl);
    return wrapper;
  }

  async function api(path, options = {}) {
    const init = {
      method: options.method || "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      cache: "no-store",
    };
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    const response = await fetch(path, init);
    if (response.status === 401 && path !== "/api/auth/login") {
      showLogin();
      throw new Error("Session expired. Sign in again.");
    }
    const text = await response.text();
    let payload = null;
    try { payload = text ? JSON.parse(text) : null; } catch (_) { payload = { raw: text }; }
    if (!response.ok) {
      const message = payload?.error?.message || `HTTP ${response.status}`;
      const code = payload?.error?.code ? ` [${payload.error.code}]` : "";
      throw new Error(message + code);
    }
    return payload;
  }

  async function apiBytes(path) {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store" });
    if (response.status === 401) { showLogin(); throw new Error("Session expired."); }
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { const value = await response.json(); message = value?.error?.message || message; } catch (_) {}
      throw new Error(message);
    }
    return response.blob();
  }

  function showLogin() {
    $("#app-view").hidden = true;
    $("#login-view").hidden = false;
    $("#setup-form").hidden = true;
    $("#login-form").hidden = false;
    $("#login-password").value = "";
  }

  function showApp() {
    $("#login-view").hidden = true;
    $("#app-view").hidden = false;
    $("#current-user").textContent = `${state.me.username} · ${state.me.role}`;
    const admin = state.me.role === "admin";
    $$("[data-admin-only]").forEach((node) => { node.hidden = !admin; });
    const analyst = admin || state.me.role === "analyst";
    $("#new-project-button").hidden = !analyst;
    $("#submit-job-button").disabled = !analyst;
    $("#submit-chain-button").disabled = !analyst;
    $("#save-scope-button").disabled = !analyst;
    $("#save-approve-scope-button").disabled = !analyst;
    $("#approve-scope-button").disabled = !analyst;
  }

  async function boot() {
    try {
      const value = await api("/api/auth/me");
      state.me = value.user;
      showApp();
      await loadProjects();
      await loadTaskTypes();
      route();
    } catch (_) {
      showLogin();
      try {
        const setup = await api("/api/auth/setup");
        $("#setup-form").hidden = !setup.required;
        $("#login-form").hidden = setup.required;
      } catch (error) {
        $("#login-error").textContent = error.message;
      }
    }
  }

  async function loadProjects() {
    const value = await api("/api/projects?limit=500");
    state.projects = value.items || [];
    const select = $("#project-select");
    clear(select);
    select.appendChild(new Option("Select a project…", ""));
    for (const item of state.projects) {
      const project = item.project;
      const label = `${project.name}${item.scope_status ? ` · scope ${item.scope_status}` : ""}`;
      select.appendChild(new Option(label, project.id));
    }
    if (state.projectId && state.projects.some((item) => item.project.id === state.projectId)) {
      select.value = state.projectId;
      state.project = state.projects.find((item) => item.project.id === state.projectId).project;
    } else {
      state.projectId = "";
      state.project = null;
      select.value = "";
    }
  }

  async function loadTaskTypes() {
    try {
      const value = await api("/api/task-types");
      state.taskTypes = value.task_types || [];
      const select = $("#task-type");
      clear(select);
      for (const item of state.taskTypes) {
        const option = new Option(`${item.name} — ${item.title}${item.available ? "" : " (unavailable)"}`, item.name);
        select.appendChild(option);
      }
      const chain = new Option("chain.all_in_one — preset chain", "chain.all_in_one");
      select.appendChild(chain);
      renderTaskAvailability();
    } catch (error) {
      notice(error.message, "error");
    }
  }

  function renderTaskAvailability() {
    const name = $("#task-type").value;
    const info = state.taskTypes.find((item) => item.name === name);
    const node = $("#task-availability");
    if (!info) {
      node.textContent = name === "chain.all_in_one"
        ? "Creates linked subdomain, DNS, HTTP, URL, crawl and web-check stage jobs."
        : "";
      return;
    }
    node.textContent = info.available
      ? `${info.title}. Inputs: ${(info.inputs || []).join("; ")}`
      : `Unavailable: ${info.unavailable_reason}`;
  }

  async function selectProject(id) {
    state.projectId = id;
    state.project = state.projects.find((item) => item.project.id === id)?.project || null;
    state.dashboard = null;
    state.scope = null;
    state.rules = [];
    notice("");
    if (!id) {
      render();
      return;
    }
    try {
      await Promise.all([loadScope(), loadJobs()]);
      render();
    } catch (error) {
      notice(error.message, "error");
    }
  }

  function requireProject() {
    if (state.projectId) return true;
    notice("Select a project first.", "info");
    return false;
  }

  function route() {
    const hash = (location.hash || "#dashboard").replace("#", "");
    const allowed = ["dashboard", "scope", "scans", "assets", "findings", "reports", "users"];
    state.view = allowed.includes(hash) ? hash : "dashboard";
    if (state.view === "users" && state.me?.role !== "admin") state.view = "dashboard";
    $$("[data-view]").forEach((node) => { node.hidden = node.dataset.view !== state.view; });
    $$("[data-view-link]").forEach((node) => {
      node.classList.toggle("active", node.dataset.viewLink === state.view);
      node.setAttribute("aria-current", node.dataset.viewLink === state.view ? "page" : "false");
    });
    render();
    refreshCurrent();
  }

  function render() {
    renderScope();
    renderJobs();
    renderDashboard();
    renderFindings();
    renderAssets();
    if (state.view === "users") renderUsers();
  }

  async function refreshCurrent() {
    if (!state.projectId) return;
    try {
      if (["dashboard", "assets", "findings"].includes(state.view)) await loadDashboard();
      if (state.view === "scans") await loadJobs();
      if (state.view === "scope") await loadScope();
      if (state.view === "users") await loadAdmin();
    } catch (error) {
      notice(error.message, "error");
    }
  }

  async function loadDashboard() {
    if (!requireProject()) return;
    const value = await api(`/api/projects/${encodeURIComponent(state.projectId)}/dashboard`);
    state.dashboard = value;
    renderDashboard();
    renderAssets();
    renderFindings();
  }

  async function loadScope() {
    if (!requireProject()) return;
    const value = await api(`/api/projects/${encodeURIComponent(state.projectId)}/scope`);
    state.scope = value.scope;
    state.scopeHistory = value.history || [];
    state.rules = (value.scope.rules || []).map((rule) => ({ ...rule }));
    renderScope();
  }

  async function loadJobs() {
    if (!requireProject()) return;
    const value = await api(`/api/projects/${encodeURIComponent(state.projectId)}/jobs?limit=100`);
    state.jobs = value.items || [];
    renderJobs();
  }

  function renderScope() {
    const status = $("#scope-status");
    clear(status);
    if (!state.projectId) {
      status.appendChild(el("p", "Select a project to view its scope.", "empty"));
    } else if (!state.scope) {
      status.appendChild(el("p", "Loading scope…", "muted"));
    } else {
      const approved = state.scope.status === "approved";
      status.appendChild(el("h3", `Revision ${state.scope.version}`));
      const line = el("p");
      append(line,
        el("span", `Status: ${state.scope.status}`, approved ? "badge ok" : "badge warn"),
        el("span", ` Rules: ${state.rules.length}`, "badge"),
        el("span", ` Created: ${state.scope.created_at}`, "muted"));
      status.appendChild(line);
      if (!approved) {
        status.appendChild(el("p", "Scans are blocked until this revision is approved. Imported scope stays pending review and never authorizes traffic automatically.", "warn-text"));
      }
    }

    const rules = $("#scope-rules");
    clear(rules);
    if (!state.projectId) {
      rules.appendChild(el("p", "No project selected.", "empty"));
    } else if (state.rules.length === 0) {
      rules.appendChild(el("p", "No scope rules. Add an allowed rule before approving.", "empty"));
    } else {
      rules.appendChild(table(["Kind", "Value", "Effect", ""], state.rules, (rule, column) => {
        if (column === "Effect") return rule.exclusion ? "exclude" : "allow";
        if (column === "") {
          const button = el("button", "Remove", "link");
          button.type = "button";
          button.addEventListener("click", () => {
            state.rules = state.rules.filter((item) => item !== rule);
            renderScope();
          });
          return button;
        }
        return rule[column.toLowerCase()] ?? "";
      }));
    }

    const history = $("#scope-history");
    clear(history);
    if (!state.projectId) {
      history.appendChild(el("p", "No project selected.", "empty"));
    } else {
      history.appendChild(table(
        ["Version", "Status", "Created", "Approved"],
        state.scopeHistory || [],
        (revision, column) => {
          const map = {
            Version: revision.version,
            Status: revision.status,
            Created: revision.created_at,
            Approved: revision.approved_at || "",
          };
          return map[column] ?? "";
        },
      ));
    }
  }

  function renderJobs() {
    const node = $("#jobs-list");
    clear(node);
    if (!state.projectId) {
      node.appendChild(el("p", "Select a project to view jobs.", "empty"));
      return;
    }
    if (!state.jobs.length) {
      node.appendChild(el("p", "No jobs yet. Submit one above.", "empty"));
      return;
    }
    const list = el("div", null, "job-list");
    for (const job of state.jobs) {
      const card = el("article", null, "job-card");
      const head = el("div", null, "job-head");
      append(head,
        el("strong", job.task_type),
        el("span", job.status, `badge ${statusClass(job.status)}`));
      card.appendChild(head);
      const counters = job.counters || {};
      card.appendChild(el("p", `Targets ${counters.targets || 0} · processed ${counters.processed || 0} · skipped ${counters.skipped || 0} · errors ${counters.errors || 0}`, "muted"));
      if (job.error) card.appendChild(el("p", job.error, "error"));
      if (job.archived) card.appendChild(el("p", "Archived imported record; it is never executed.", "muted"));
      if (job.chain) card.appendChild(el("p", `Chain ${job.chain.name}: ${job.chain.status} · stage ${job.chain_order}`, "muted"));
      const actions = el("div", null, "button-row");
      if (job.status === "queued" || job.status === "running") {
        const cancel = el("button", "Cancel", "link");
        cancel.type = "button";
        cancel.addEventListener("click", async () => {
          try {
            await api(`/api/jobs/${encodeURIComponent(job.id)}/cancel`, { method: "POST", body: {} });
            await loadJobs();
          } catch (error) { notice(error.message, "error"); }
        });
        actions.appendChild(cancel);
      }
      if (job.artifacts?.length) {
        for (const artifact of job.artifacts) {
          const link = el("a", `${artifact.kind} (${artifact.size} B)`, "link");
          link.href = artifact.href;
          link.target = "_blank";
          link.rel = "noopener";
          actions.appendChild(link);
        }
      }
      if (actions.childElementCount) card.appendChild(actions);
      list.appendChild(card);
    }
    node.appendChild(list);
  }

  function statusClass(status) {
    if (status === "succeeded") return "ok";
    if (status === "partial" || status === "queued" || status === "running") return "warn";
    if (status === "failed" || status === "cancelled" || status === "interrupted") return "bad";
    return "";
  }

  function renderDashboard() {
    const empty = $("#dashboard-empty");
    const content = $("#dashboard-content");
    if (!state.projectId) {
      empty.hidden = false;
      empty.textContent = "Select a project to load dashboard data. No project is selected by default.";
      content.hidden = true;
      return;
    }
    if (!state.dashboard) {
      empty.hidden = false;
      empty.textContent = "Loading dashboard…";
      content.hidden = true;
      return;
    }
    empty.hidden = state.dashboard.data_status !== "empty";
    if (state.dashboard.data_status === "empty") {
      empty.textContent = "No observations yet. Approve scope and run a job to populate the dashboard.";
      content.hidden = true;
      return;
    }
    content.hidden = false;
    const metrics = $("#dashboard-metrics");
    clear(metrics);
    const data = state.dashboard.metrics;
    for (const [label, key] of [["Hosts", "hosts"], ["IPs", "ips"], ["URLs", "urls"], ["Open ports", "open_ports"], ["Findings", "findings"], ["Jobs", "jobs"]]) {
      const card = el("div", null, "metric");
      append(card, el("span", data[key] ?? 0, "metric-value"), el("span", label, "muted"));
      metrics.appendChild(card);
    }
    if (state.dashboard.data_status === "partial") {
      metrics.appendChild(el("p", "Some jobs completed partially. Review source errors below.", "warn-text"));
    }

    const jobsNode = $("#dashboard-jobs");
    clear(jobsNode);
    jobsNode.appendChild(table(["Task", "Status", "Finished"], state.dashboard.jobs || [], (job, column) => {
      if (column === "Task") return job.task_type;
      if (column === "Status") return job.status;
      return job.finished_at || job.created_at;
    }));

    const availability = $("#dashboard-availability");
    clear(availability);
    const worker = state.dashboard.worker || { state: "unknown" };
    availability.appendChild(el(
      "p",
      `Worker: ${worker.state}${worker.last_heartbeat ? ` · last heartbeat ${worker.last_heartbeat}` : ""}`,
      worker.state === "ready" ? "badge ok" : "badge warn",
    ));
    const unavailable = state.dashboard.availability?.unavailable || [];
    const errors = state.dashboard.availability?.recent_source_errors || {};
    if (!unavailable.length && !Object.keys(errors).length) {
      availability.appendChild(el("p", "All configured task types and sources are available.", "muted"));
    } else {
      const items = unavailable.map((item) => `${item.task_type}: ${item.reason}`);
      for (const [task, reason] of Object.entries(errors)) items.push(`${task}: ${reason}`);
      availability.appendChild(table(["Availability"], items.map((value) => ({ value }))));
    }

    const http = $("#dashboard-http");
    clear(http);
    http.appendChild(table(["URL", "Status", "Source", "Observed"], state.dashboard.recent_http || [], (row, column) => {
      if (column === "Status") return row.data?.status_code ?? "";
      if (column === "Source") return row.source;
      if (column === "Observed") return row.observed_at;
      return row.url;
    }));

    const ports = $("#dashboard-ports");
    clear(ports);
    ports.appendChild(table(["IP", "Port", "State", "Service"], state.dashboard.recent_ports || [], (row, column) => {
      if (column === "IP") return row.ip;
      if (column === "Port") return row.data?.port ?? "";
      if (column === "State") return row.data?.state ?? "";
      return row.data?.service || "";
    }));

    const coverage = $("#dashboard-coverage");
    clear(coverage);
    coverage.appendChild(table(["Rule", "Version", "Severity", "Evaluated", "Findings", "Not applicable"], state.dashboard.web_check_coverage || [], (row, column) => {
      const map = {
        Rule: row.id, Version: row.version, Severity: row.severity,
        Evaluated: row.evaluated, Findings: row.findings, "Not applicable": row.not_applicable,
      };
      return map[column] ?? "";
    }));
  }

  function renderAssets() {
    const dashboard = state.dashboard;
    for (const [id, key, columns] of [
      ["#assets-hosts", "hosts", ["Value", "First seen", "Last seen"]],
      ["#assets-ips", "ips", ["Value", "First seen", "Last seen"]],
      ["#assets-urls", "urls", ["Value", "First seen", "Last seen"]],
    ]) {
      const node = $(id);
      clear(node);
      if (!state.projectId) { node.appendChild(el("p", "Select a project.", "empty")); continue; }
      node.appendChild(table(columns, dashboard?.assets?.[key] || [], (row, column) => {
        if (column === "Value") return row.value;
        if (column === "First seen") return row.first_seen;
        return row.last_seen;
      }));
    }
  }

  function renderFindings() {
    const summary = $("#findings-summary");
    clear(summary);
    const counts = state.dashboard?.severity_counts || {};
    for (const severity of ["critical", "high", "medium", "low", "info", "unknown"]) {
      const card = el("div", null, "metric");
      append(card, el("span", counts[severity] || 0, "metric-value"), el("span", severity, "muted"));
      summary.appendChild(card);
    }
    const node = $("#findings-table");
    clear(node);
    if (!state.projectId) { node.appendChild(el("p", "Select a project.", "empty")); return; }
    node.appendChild(table(["Severity", "Rule", "Asset", "Title", "Last seen"], state.dashboard?.findings || [], (row, column) => {
      const map = { Severity: row.severity, Rule: row.rule_id, Asset: row.asset, Title: row.title, "Last seen": row.last_seen };
      return map[column] ?? "";
    }));
  }

  async function loadAdmin() {
    if (state.me?.role !== "admin") return;
    const users = await api("/api/users?limit=200");
    const audit = await api("/api/audit?limit=100");
    renderUsers(users.items || [], audit.items || []);
  }

  function renderUsers(users = [], audit = []) {
    const node = $("#users-list");
    if (!node) return;
    clear(node);
    node.appendChild(table(["Username", "Role", "Active", "Created", "Actions"], users, (user, column) => {
      if (column === "Role") return user.role;
      if (column === "Active") return user.is_active ? "yes" : "no";
      if (column === "Created") return user.created_at;
      if (column === "Actions") {
        const wrap = el("div", null, "button-row");
        const toggle = el("button", user.is_active ? "Deactivate" : "Activate", "link");
        toggle.type = "button";
        toggle.addEventListener("click", async () => {
          try {
            await api(`/api/users/${encodeURIComponent(user.id)}`, { method: "PATCH", body: { is_active: !user.is_active } });
            await loadAdmin();
          } catch (error) { $("#user-error").textContent = error.message; }
        });
        const promote = el("button", user.role === "admin" ? "Make viewer" : "Make admin", "link");
        promote.type = "button";
        promote.addEventListener("click", async () => {
          try {
            await api(`/api/users/${encodeURIComponent(user.id)}`, { method: "PATCH", body: { role: user.role === "admin" ? "viewer" : "admin" } });
            await loadAdmin();
          } catch (error) { $("#user-error").textContent = error.message; }
        });
        append(wrap, toggle, promote);
        return wrap;
      }
      return user[column.toLowerCase()] ?? "";
    }));
    const auditNode = $("#audit-list");
    if (auditNode) {
      clear(auditNode);
      auditNode.appendChild(table(["Time", "Actor", "Action", "Entity"], audit, (event, column) => {
        if (column === "Time") return event.created_at;
        if (column === "Actor") return event.actor;
        if (column === "Action") return event.action;
        return `${event.entity_type}${event.entity_id ? `: ${event.entity_id}` : ""}`;
      }));
    }
  }

  async function downloadReport(format) {
    if (!requireProject()) return;
    try {
      const blob = await apiBytes(`/api/projects/${encodeURIComponent(state.projectId)}/reports/${format}`);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${state.project?.name || "project"}-report.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      notice(`Exported ${format.toUpperCase()} report.`, "info");
    } catch (error) {
      notice(error.message, "error");
    }
  }

  $("#setup-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const error = $("#setup-error");
    const button = form.querySelector("button");
    error.textContent = "";
    button.disabled = true;
    try {
      const result = await api("/api/auth/setup", {
        method: "POST",
        body: {
          code: $("#setup-code").value,
          username: $("#setup-username").value,
          password: $("#setup-password").value,
        },
      });
      form.reset();
      showLogin();
      $("#login-username").value = result.user.username;
      const status = $("#login-status");
      status.textContent = "Administrator created. Sign in to continue.";
      status.hidden = false;
      $("#login-password").focus();
    } catch (err) {
      error.textContent = err.message;
    } finally {
      button.disabled = false;
    }
  });

  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const error = $("#login-error");
    error.textContent = "";
    $("#login-status").hidden = true;
    try {
      const value = await api("/api/auth/login", {
        method: "POST",
        body: {
          username: $("#login-username").value,
          password: $("#login-password").value,
        },
      });
      state.me = value.user;
      $("#login-password").value = "";
      showApp();
      await loadProjects();
      await loadTaskTypes();
      location.hash = "#dashboard";
      route();
    } catch (err) {
      error.textContent = err.message;
    }
  });

  $("#logout-button").addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST", body: {} }); } catch (_) {}
    state.me = null;
    state.projectId = "";
    state.project = null;
    state.dashboard = null;
    showLogin();
  });

  $("#project-select").addEventListener("change", (event) => selectProject(event.target.value));

  $("#new-project-button").addEventListener("click", () => {
    const panel = $("#new-project-panel");
    panel.hidden = !panel.hidden;
    if (!panel.hidden) $("#project-name").focus();
  });

  $("#new-project-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const value = await api("/api/projects", {
        method: "POST",
        body: {
          name: $("#project-name").value,
          client: $("#project-client").value,
          description: $("#project-description").value,
        },
      });
      $("#new-project-panel").hidden = true;
      $("#new-project-form").reset();
      await loadProjects();
      $("#project-select").value = value.project.id;
      await selectProject(value.project.id);
      notice("Project created. Add and approve scope before submitting scans.", "info");
    } catch (error) {
      notice(error.message, "error");
    }
  });

  $("#refresh-button").addEventListener("click", refreshCurrent);

  $("#add-rule-button").addEventListener("click", () => {
    const value = $("#rule-value").value.trim();
    if (!value) { $("#scope-error").textContent = "Enter a rule value."; return; }
    state.rules.push({
      kind: $("#rule-kind").value,
      value,
      exclusion: $("#rule-exclusion").checked,
      verified: true,
    });
    $("#rule-value").value = "";
    $("#rule-exclusion").checked = false;
    $("#scope-error").textContent = "";
    renderScope();
  });

  async function saveScope(approve) {
    if (!requireProject()) return;
    $("#scope-error").textContent = "";
    try {
      await api(`/api/projects/${encodeURIComponent(state.projectId)}/scope`, {
        method: "PUT",
        body: {
          rules: state.rules,
          expected_version: state.scope?.version,
          note: $("#scope-note").value,
          approve,
        },
      });
      $("#scope-note").value = "";
      await loadScope();
      await loadProjects();
      notice(approve ? "Scope revision approved." : "Scope draft saved. Approval is still required.", "info");
    } catch (error) {
      $("#scope-error").textContent = error.message;
    }
  }

  $("#save-scope-button").addEventListener("click", () => saveScope(false));
  $("#save-approve-scope-button").addEventListener("click", () => saveScope(true));
  $("#approve-scope-button").addEventListener("click", async () => {
    if (!state.scope) return;
    try {
      await api(`/api/projects/${encodeURIComponent(state.projectId)}/scope/${state.scope.version}/approve`, { method: "POST", body: {} });
      await loadScope();
      await loadProjects();
      notice("Scope revision approved.", "info");
    } catch (error) {
      $("#scope-error").textContent = error.message;
    }
  });

  $("#task-type").addEventListener("change", renderTaskAvailability);

  $("#submit-job-button").addEventListener("click", async () => {
    if (!requireProject()) return;
    $("#scan-error").textContent = "";
    let params;
    try { params = JSON.parse($("#task-params").value || "{}"); }
    catch (err) { $("#scan-error").textContent = `Parameters must be valid JSON: ${err.message}`; return; }
    try {
      await api(`/api/projects/${encodeURIComponent(state.projectId)}/jobs`, {
        method: "POST",
        body: {
          task_type: $("#task-type").value,
          params,
          idempotency_key: $("#idempotency-key").value || null,
        },
      });
      $("#idempotency-key").value = "";
      await loadJobs();
      notice("Job submitted.", "info");
    } catch (error) {
      $("#scan-error").textContent = error.message;
    }
  });

  $("#submit-chain-button").addEventListener("click", async () => {
    if (!requireProject()) return;
    $("#scan-error").textContent = "";
    let params = {};
    try { params = JSON.parse($("#task-params").value || "{}"); }
    catch (err) { $("#scan-error").textContent = `Parameters must be valid JSON: ${err.message}`; return; }
    try {
      await api(`/api/projects/${encodeURIComponent(state.projectId)}/chains`, {
        method: "POST",
        body: {
          domains: params.domains || [],
          targets: params.targets || [],
          idempotency_key: $("#idempotency-key").value || null,
        },
      });
      $("#idempotency-key").value = "";
      await loadJobs();
      notice("Chain submitted.", "info");
    } catch (error) {
      $("#scan-error").textContent = error.message;
    }
  });

  $("#user-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    $("#user-error").textContent = "";
    try {
      await api("/api/users", {
        method: "POST",
        body: {
          username: $("#user-username").value,
          password: $("#user-password").value,
          role: $("#user-role").value,
        },
      });
      $("#user-form").reset();
      await loadAdmin();
    } catch (error) {
      $("#user-error").textContent = error.message;
    }
  });

  $("#export-json-button").addEventListener("click", () => downloadReport("json"));
  $("#export-csv-button").addEventListener("click", () => downloadReport("csv"));

  window.addEventListener("hashchange", route);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refreshCurrent();
  });

  state.poll = setInterval(() => {
    if (document.hidden || !state.projectId) return;
    if (state.view === "dashboard" || state.view === "scans") refreshCurrent();
  }, 5000);

  boot();
})();
