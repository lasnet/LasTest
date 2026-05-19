const state = {
  token: localStorage.getItem("lastest_auth_token") || "",
  user: null,
  authRequired: true,
  authConfigured: false,
  setupRequired: false,
  selectedProject: localStorage.getItem("lastest_project") || "",
  projects: [],
  projectDetail: null,
  dashboard: null,
  jobs: [],
  users: [],
  auditEvents: [],
};

const demoProject = {
  project: {
    name: "example.com",
    client: "Analyst",
    description: "External penetration test assessment overview and insights.",
  },
  scope: {
    domains: ["example.com", "api.example.com"],
    ips: ["93.184.216.34", "203.0.113.14", "203.0.113.28"],
    exclusions: ["legacy.example.com", "10.0.0.0/8"],
  },
};

const demoScans = [
  ["Full Scan", "May 12, 2025  13:45 UTC", "completed"],
  ["Web App Scan", "May 11, 2025  22:31 UTC", "completed"],
  ["API Scan", "May 12, 2025  14:28 UTC", "running"],
  ["Network Scan", "May 10, 2025  18:05 UTC", "scheduled"],
  ["Subdomain Enum", "May 12, 2025  12:02 UTC", "completed"],
];

const demoActivity = [
  ["14:31:55", "[OK]", "Scan completed", "Full Scan", "34 hosts", "7m 42s", "0 critical, 2 high", "ok", "green"],
  ["14:28:11", "[~]", "Scan started", "API Scan", "-", "-", "in progress", "warn", "yellow"],
  ["14:25:03", "[!]", "High severity finding", "SQL Injection", "api.example.com", "/v1/users", "High", "danger", "red"],
  ["14:22:47", "[OK]", "Asset added", "93.184.216.34", "-", "-", "New host discovered", "ok", "green"],
  ["14:18:33", "[i]", "Subdomain discovered", "api-staging.example.com", "-", "-", "New subdomain", "info-text", "green"],
];

const qs = (selector) => document.querySelector(selector);
const qsa = (selector) => Array.from(document.querySelectorAll(selector));

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function lines(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function showNotice(message) {
  const notice = qs("#notice");
  notice.textContent = message;
  notice.hidden = false;
  clearTimeout(showNotice.timer);
  showNotice.timer = setTimeout(() => {
    notice.hidden = true;
  }, 4600);
}

function detail() {
  if (state.dashboard?.project) {
    return {
      project: state.dashboard.project,
      scope: state.dashboard.scope || {},
    };
  }
  return state.projectDetail || demoProject;
}

function currentScope() {
  return detail().scope || {};
}

function currentProjectName() {
  const scope = currentScope();
  return detail().project?.name || scope.domains?.[0] || "example.com";
}

function subtitle() {
  const project = detail().project || {};
  return (
    project.description ||
    project.client ||
    "External penetration test assessment overview and insights."
  );
}

function isRealProject() {
  return Boolean(state.projectDetail || state.dashboard);
}

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }

  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let detailText = response.statusText;
    try {
      const data = await response.json();
      detailText = data.detail || detailText;
    } catch (_) {
      detailText = await response.text();
    }
    if (response.status === 401) {
      detailText = "Session expired or invalid. Sign in again.";
    }
    throw new Error(detailText);
  }

  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

async function loadRuntimeStatus() {
  try {
    const status = await api("/api/auth/status");
    state.authRequired = Boolean(status.auth_required);
    state.authConfigured = Boolean(status.auth_configured);
    state.setupRequired = Boolean(status.setup_required);
  } catch (_) {
    state.authRequired = true;
    state.authConfigured = false;
    state.setupRequired = false;
  }
}

async function loadCurrentUser() {
  if (!state.authRequired) {
    state.user = { username: "local-system", role: "admin", is_active: true };
    return true;
  }
  if (!state.token) {
    state.user = null;
    return false;
  }
  try {
    const data = await api("/api/auth/me");
    state.user = data.user;
    return true;
  } catch (error) {
    clearSession();
    return false;
  }
}

function clearSession() {
  state.token = "";
  state.user = null;
  localStorage.removeItem("lastest_auth_token");
}

function hasApiAccess() {
  return !state.authRequired || Boolean(state.user);
}

function roleRank(role) {
  return { viewer: 10, analyst: 20, admin: 30 }[role] || 0;
}

function canWrite() {
  return !state.authRequired || roleRank(state.user?.role) >= 20;
}

function canAdmin() {
  return !state.authRequired || roleRank(state.user?.role) >= 30;
}

function authHelpMessage() {
  if (state.setupRequired) {
    return "No admin user exists. Set AUTH_BOOTSTRAP_ADMIN_PASSWORD in .env and restart.";
  }
  if (!state.authConfigured) {
    return "AUTH_JWT_SECRET or WEB_API_KEY is not configured on the server.";
  }
  return "Sign in first.";
}

function renderAuthState() {
  const item = qs("#auth-state");
  const user = qs("#current-user");
  const logout = qs("#logout-button");
  if (!state.authRequired) {
    item.textContent = "Auth off";
    item.className = "auth-state ok";
    user.textContent = "local-system";
    logout.hidden = true;
    return;
  }
  if (state.user) {
    item.textContent = state.user.role || "user";
    item.className = "auth-state ok";
    user.textContent = state.user.username || "signed in";
    logout.hidden = false;
    return;
  }
  item.textContent = state.setupRequired ? "Setup" : "Signed out";
  item.className = "auth-state warn";
  user.textContent = state.setupRequired ? "Bootstrap admin" : "Not signed in";
  logout.hidden = true;
}

function showLogin(show) {
  qs("#login-screen").hidden = !show;
  if (state.setupRequired) {
    qs("#login-hint").textContent =
      "No admin user exists. Set AUTH_BOOTSTRAP_ADMIN_PASSWORD in .env and restart the service.";
  } else {
    qs("#login-hint").textContent = "Sign in with your platform account.";
  }
}

function formatUtcClock() {
  const now = new Date();
  const hh = String(now.getUTCHours()).padStart(2, "0");
  const mm = String(now.getUTCMinutes()).padStart(2, "0");
  const ss = String(now.getUTCSeconds()).padStart(2, "0");
  qs("#utc-clock").textContent = `${hh}:${mm}:${ss} UTC`;
}

function renderProjectSelector() {
  const select = qs("#project-select");
  select.innerHTML = "";

  if (!state.projects.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Create a project";
    select.appendChild(option);
    return;
  }

  for (const project of state.projects) {
    const option = document.createElement("option");
    option.value = project.name;
    option.textContent = project.name;
    option.selected = project.name === state.selectedProject;
    select.appendChild(option);
  }
}

function metricValues() {
  if (state.dashboard?.metrics) {
    const metrics = state.dashboard.metrics;
    return {
      domains: metrics.domains || 0,
      ips: metrics.ips || 0,
      exclusions: metrics.exclusions || 0,
      subdomains: metrics.subdomains || 0,
      dnsHosts: metrics.dns_hosts || 0,
      alive: metrics.alive_hosts || 0,
      openPorts: metrics.open_ports || 0,
      findings: metrics.findings || 0,
      critical: metrics.critical || 0,
      high: metrics.high || 0,
      medium: metrics.medium || 0,
      low: metrics.low || 0,
      info: metrics.info || 0,
    };
  }

  if (!isRealProject()) {
    return {
      domains: 2,
      ips: 3,
      exclusions: 2,
      subdomains: 128,
      dnsHosts: 3,
      alive: 34,
      openPorts: 12,
      findings: 5,
      critical: 1,
      high: 2,
      medium: 1,
      low: 1,
      info: 7,
    };
  }

  const scope = currentScope();
  const domains = scope.domains || [];
  const ips = scope.ips || [];
  const exclusions = scope.exclusions || [];
  const subdomains = domains.length * 64;
  const alive = Math.max(0, Math.floor(subdomains * 0.27));
  return {
    domains: domains.length,
    ips: ips.length,
    exclusions: exclusions.length,
    subdomains,
    dnsHosts: 0,
    alive,
    openPorts: Math.max(0, ips.length * 4),
    findings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
}

function renderHeaderAndMetrics() {
  const values = metricValues();
  qs("#project-title").textContent = currentProjectName();
  qs("#project-subtitle").textContent = subtitle();
  qs("#config-project-title").textContent = currentProjectName();
  qs("#scope-summary-text").textContent =
    `Domains: ${values.domains} / IPs: ${values.ips} / Exclusions: ${values.exclusions}`;

  qs("#metric-subdomains").textContent = values.subdomains;
  qs("#metric-alive").textContent = values.alive;
  qs("#metric-ports").textContent = values.openPorts;
  qs("#metric-findings").textContent = values.findings;
  qs("#metric-subdomains-delta").textContent =
    isRealProject() ? `${values.dnsHosts} DNS hosts` : "+18 new";
  qs("#metric-alive-delta").textContent = isRealProject() ? `${values.alive} alive targets` : "+7 new";
  qs("#metric-ports-delta").textContent = isRealProject() ? "from HTTP probe" : "+2 new";
  qs("#metric-findings-delta").textContent =
    isRealProject() ? `${values.critical} critical / ${values.high} high` : "-1 resolved";

  qs("#stat-ipv4").textContent = isRealProject() ? values.ips : 45;
  qs("#stat-dns-hosts").textContent = isRealProject() ? values.dnsHosts : 3;
  qs("#stat-domains").textContent = isRealProject() ? values.domains : 2;
  qs("#stat-subdomains").textContent = isRealProject() ? values.subdomains : 128;
  qs("#stat-alive").textContent = isRealProject() ? values.alive : 34;
  qs("#assets-badge").textContent = isRealProject()
    ? values.domains + values.ips + values.subdomains + values.alive
    : 128;
  qs("#findings-badge").textContent = isRealProject() ? values.findings : 5;
  qs("#scans-badge").textContent = isRealProject() ? state.jobs.length : 12;
  qs("#last-discovery").textContent = state.dashboard
    ? `Last discovery: ${lastFinishedScanTime()}`
    : "Last discovery: 2m ago";
  qs("#freshness-state").textContent = state.dashboard ? "Live data" : "Demo data";
  renderFindingsOverview(values);
}

function renderScopeForm() {
  const scope = currentScope();
  qs("#scope-form textarea[name='domains']").value = (scope.domains || []).join("\n");
  qs("#scope-form textarea[name='ips']").value = (scope.ips || []).join("\n");
  qs("#scope-form textarea[name='exclusions']").value = (scope.exclusions || []).join("\n");
}

function renderLastScans() {
  const scans = state.dashboard?.scans?.length ? state.dashboard.scans : state.jobs;
  const rows = scans.length
    ? scans.slice(0, 5).map((job) => [
        titleCase(job.task_type || "scan"),
        job.created_at || "-",
        normalizeStatus(job.status),
      ])
    : demoScans;

  qs("#last-scans").innerHTML = rows
    .map(([name, date, status]) => {
      const stateClass = status === "running" ? "running" : status === "scheduled" ? "scheduled" : "";
      const glyph = status === "running" ? "~" : status === "scheduled" ? "-" : "ok";
      return `
        <div class="scan-row">
          <span class="scan-state ${stateClass}">${esc(glyph)}</span>
          <div>
            <strong>${esc(name)}</strong>
            <span>${esc(date)}</span>
          </div>
          <em class="scan-badge ${stateClass}">${esc(statusLabel(status))}</em>
        </div>
      `;
    })
    .join("");
}

function renderActivity() {
  const rows = state.dashboard?.activity?.length
    ? state.dashboard.activity.slice(0, 5).map((item) => [
        shortTime(item.time),
        item.status === "failed" ? "[!]" : item.status === "running" ? "[~]" : "[OK]",
        item.event || "Scan activity",
        titleCase(item.task),
        item.asset || "-",
        "-",
        item.detail || "-",
        item.status === "failed" ? "danger" : item.status === "running" ? "warn" : "ok",
        item.status === "failed" ? "red" : item.status === "running" ? "yellow" : "green",
      ])
    : state.jobs.length
    ? state.jobs.slice(0, 5).map((job) => [
        shortTime(job.created_at),
        job.status === "failed" ? "[!]" : job.status === "running" ? "[~]" : "[OK]",
        `Job ${job.status}`,
        titleCase(job.task_type),
        job.result?.targets ? `${job.result.targets} targets` : "-",
        job.finished_at ? "done" : "-",
        job.error || JSON.stringify(job.result || {}),
        job.status === "failed" ? "danger" : job.status === "running" ? "warn" : "ok",
        job.status === "failed" ? "red" : job.status === "running" ? "yellow" : "green",
      ])
    : demoActivity;

  qs("#activity-log").innerHTML = rows
    .map(
      ([time, mark, event, scan, asset, path, status, markClass, statusClass]) => `
        <div class="activity-row">
          <span>${esc(time)}</span>
          <span class="${esc(markClass)}">${esc(mark)}</span>
          <span>${esc(event)}</span>
          <span>${esc(scan)}</span>
          <span>${esc(asset)}</span>
          <span>${esc(path)}</span>
          <span class="${esc(statusClass)}">${esc(status)}</span>
        </div>
      `,
    )
    .join("");
}

function renderFindingsOverview(values) {
  qs("#finding-critical").textContent = values.critical;
  qs("#finding-high").textContent = values.high;
  qs("#finding-medium").textContent = values.medium;
  qs("#finding-low").textContent = values.low;
  qs("#finding-info").textContent = values.info;
  qs("#finding-total").textContent = isRealProject() ? values.findings : 12;
}

function renderReconAssets() {
  const assets = state.dashboard?.assets || {};
  const subdomains = assets.subdomains || [];
  const dnsRecords = assets.dns_records || [];
  const aliveHosts = assets.alive_hosts || [];

  qs("#subdomain-list").innerHTML = subdomains.length
    ? subdomains.slice(0, 12).map((host) => assetItem(host, "Discovered subdomain")).join("")
    : emptyState("No subdomains yet. Run Subdomains.");

  qs("#dns-record-list").innerHTML = dnsRecords.length
    ? dnsRecords.slice(0, 12).map((item) => {
        const recordTypes = Object.keys(item.records || {}).join(", ") || "no records";
        return assetItem(item.host, recordTypes);
      }).join("")
    : emptyState("No DNS records yet. Run DNS Records.");

  qs("#http-probe-list").innerHTML = aliveHosts.length
    ? aliveHosts.slice(0, 12).map((item) => {
        const tech = Array.isArray(item.tech) ? item.tech.join(", ") : item.tech || "";
        const detailText = [item.status_code, item.webserver, tech].filter(Boolean).join(" / ") || "alive";
        return assetItem(item.url || item.host, detailText);
      }).join("")
    : emptyState("No alive HTTP hosts yet. Run HTTP Probe.");
}

function assetItem(title, subtitleText) {
  return `
    <div class="asset-item">
      <strong title="${esc(title)}">${esc(title || "-")}</strong>
      <span title="${esc(subtitleText)}">${esc(subtitleText || "-")}</span>
    </div>
  `;
}

function emptyState(text) {
  return `<div class="empty-state">${esc(text)}</div>`;
}

function renderAll() {
  renderProjectSelector();
  renderHeaderAndMetrics();
  renderScopeForm();
  renderLastScans();
  renderActivity();
  renderReconAssets();
  renderAdminPanel();
  renderPermissionControls();
}

function renderPermissionControls() {
  const disabled = !canWrite();
  qsa(".run-task, #new-project-toggle, #create-project-form button, #scope-form button").forEach((button) => {
    button.disabled = disabled;
  });
  qs("#admin-nav-link").hidden = !canAdmin();
  qs("#system-admin").hidden = !canAdmin();
}

function renderAdminPanel() {
  if (!canAdmin()) return;
  qs("#users-list").innerHTML = state.users.length
    ? state.users.map((user) => `
        <div class="admin-row">
          <strong>${esc(user.username)}</strong>
          <span>${esc(user.role)} / ${user.is_active ? "active" : "disabled"}</span>
          <span>Last login: ${esc(user.last_login_at || "-")}</span>
        </div>
      `).join("")
    : emptyState("No users loaded.");

  qs("#audit-list").innerHTML = state.auditEvents.length
    ? state.auditEvents.slice(0, 10).map((event) => `
        <div class="admin-row">
          <strong>${esc(event.action)} / ${esc(event.status)}</strong>
          <span>${esc(event.actor_username || "system")} -> ${esc(event.resource_type)}:${esc(event.resource_id || "-")}</span>
          <span>${esc(event.created_at)}</span>
        </div>
      `).join("")
    : emptyState("No audit events loaded.");
}

function titleCase(value) {
  return String(value || "")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function normalizeStatus(status) {
  if (status === "queued") return "scheduled";
  if (status === "succeeded") return "completed";
  return status || "scheduled";
}

function statusLabel(status) {
  if (status === "completed") return "Completed";
  if (status === "running") return "Running";
  if (status === "failed") return "Failed";
  return "Scheduled";
}

function shortTime(value) {
  if (!value) return "--:--:--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value).slice(11, 19) || "--:--:--";
  return date.toISOString().slice(11, 19);
}

function lastFinishedScanTime() {
  const finished = state.jobs.find((job) => job.finished_at || job.started_at || job.created_at);
  if (!finished) return "waiting";
  return shortTime(finished.finished_at || finished.started_at || finished.created_at);
}

async function loadProjects() {
  const data = await api("/api/projects");
  state.projects = data.projects || [];
  const selectedExists = state.projects.some((project) => project.name === state.selectedProject);

  if (!state.projects.length) {
    state.selectedProject = "";
    localStorage.removeItem("lastest_project");
    return;
  }

  if ((!state.selectedProject || !selectedExists) && state.projects.length) {
    state.selectedProject = state.projects[0].name;
    localStorage.setItem("lastest_project", state.selectedProject);
  }
}

async function loadProjectDetail() {
  if (!state.selectedProject) {
    state.projectDetail = null;
    return;
  }
  state.projectDetail = await api(`/api/projects/${encodeURIComponent(state.selectedProject)}`);
}

async function loadDashboard() {
  if (!state.selectedProject) {
    state.dashboard = null;
    return;
  }
  state.dashboard = await api(`/api/projects/${encodeURIComponent(state.selectedProject)}/dashboard`);
  state.jobs = state.dashboard.scans || [];
}

async function loadJobs() {
  if (!state.selectedProject) {
    state.jobs = [];
    return;
  }
  const data = await api(`/api/jobs?project_name=${encodeURIComponent(state.selectedProject)}`);
  state.jobs = data.jobs || [];
}

async function loadAdminData() {
  if (!canAdmin()) {
    state.users = [];
    state.auditEvents = [];
    return;
  }
  const [usersData, auditData] = await Promise.all([
    api("/api/auth/users"),
    api("/api/auth/audit?limit=50"),
  ]);
  state.users = usersData.users || [];
  state.auditEvents = auditData.events || [];
}

async function refreshData() {
  await loadProjects();
  await loadProjectDetail().catch(() => {
    state.projectDetail = null;
    state.dashboard = null;
    state.selectedProject = "";
    localStorage.removeItem("lastest_project");
  });
  await loadDashboard().catch(() => {
    state.dashboard = null;
    return loadJobs().catch(() => {
      state.jobs = [];
    });
  });
  await loadAdminData().catch(() => {
    state.users = [];
    state.auditEvents = [];
  });
  renderAll();
}

async function selectProject(name) {
  state.selectedProject = name;
  if (name) {
    localStorage.setItem("lastest_project", name);
  }
  await loadProjectDetail();
  await loadDashboard().catch(() => loadJobs());
  renderAll();
}

async function enqueueTask(taskType, button) {
  if (!hasApiAccess()) {
    showNotice(authHelpMessage());
    return;
  }
  if (!canWrite()) {
    showNotice("Analyst or admin role is required.");
    return;
  }
  if (!state.selectedProject) {
    showNotice("Create or select a project first.");
    return;
  }

  const original = button?.textContent;
  if (button) {
    button.disabled = true;
    button.textContent = "Queued...";
  }
  try {
    await api(`/api/projects/${encodeURIComponent(state.selectedProject)}/jobs`, {
      method: "POST",
      body: JSON.stringify({ task_type: taskType, params: {} }),
    });
    await refreshData();
    showNotice(`${titleCase(taskType)} task queued.`);
  } catch (error) {
    showNotice(error.message);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = original;
    }
  }
}

async function boot() {
  await loadRuntimeStatus();
  await loadCurrentUser();
  formatUtcClock();
  renderAuthState();
  renderAll();
  showLogin(!hasApiAccess());

  if (!hasApiAccess()) {
    qs("#create-project-form").hidden = false;
    return;
  }

  try {
    await refreshData();
  } catch (error) {
    showNotice(error.message);
  }
}

qs("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: form.get("username"),
        password: form.get("password"),
      }),
    });
    state.token = data.access_token;
    state.user = data.user;
    localStorage.setItem("lastest_auth_token", state.token);
    event.currentTarget.reset();
    showLogin(false);
    renderAuthState();
    await refreshData();
    showNotice("Signed in.");
  } catch (error) {
    showNotice(error.message);
  }
});

qs("#logout-button").addEventListener("click", async () => {
  try {
    if (state.token) {
      await api("/api/auth/logout", { method: "POST", body: "{}" });
    }
  } catch (_) {
  } finally {
    clearSession();
    state.projects = [];
    state.projectDetail = null;
    state.dashboard = null;
    state.jobs = [];
    renderAuthState();
    renderAll();
    showLogin(state.authRequired);
    showNotice("Signed out.");
  }
});

qs("#new-project-toggle").addEventListener("click", () => {
  const form = qs("#create-project-form");
  form.hidden = !form.hidden;
});

qs("#create-project-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!hasApiAccess()) {
    showNotice(authHelpMessage());
    return;
  }
  if (!canWrite()) {
    showNotice("Analyst or admin role is required.");
    return;
  }

  const form = new FormData(event.currentTarget);
  try {
    const created = await api("/api/projects", {
      method: "POST",
      body: JSON.stringify({
        name: form.get("name"),
        client: form.get("client"),
        description: form.get("description") || "External penetration test assessment overview and insights.",
      }),
    });
    event.currentTarget.reset();
    event.currentTarget.hidden = true;
    await loadProjects();
    await selectProject(created.project.name);
    showNotice("Project created.");
  } catch (error) {
    showNotice(error.message);
  }
});

qs("#project-select").addEventListener("change", async (event) => {
  try {
    await selectProject(event.currentTarget.value);
  } catch (error) {
    showNotice(error.message);
  }
});

qs("#scope-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!hasApiAccess()) {
    showNotice(authHelpMessage());
    return;
  }
  if (!canWrite()) {
    showNotice("Analyst or admin role is required.");
    return;
  }
  if (!state.selectedProject) {
    showNotice("Create or select a project first.");
    return;
  }

  const form = new FormData(event.currentTarget);
  try {
    await api(`/api/projects/${encodeURIComponent(state.selectedProject)}/scope`, {
      method: "PUT",
      body: JSON.stringify({
        domains: lines(form.get("domains")),
        ips: lines(form.get("ips")),
        exclusions: lines(form.get("exclusions")),
        replace: Boolean(form.get("replace")),
      }),
    });
    await refreshData();
    showNotice("DNS / IP scope saved.");
  } catch (error) {
    showNotice(error.message);
  }
});

qs("#refresh-detail").addEventListener("click", () => {
  refreshData().catch((error) => showNotice(error.message));
});

qs("#refresh-recon").addEventListener("click", () => {
  refreshData().catch((error) => showNotice(error.message));
});

qs("#refresh-admin").addEventListener("click", () => {
  loadAdminData()
    .then(() => renderAll())
    .catch((error) => showNotice(error.message));
});

qs("#create-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!canAdmin()) {
    showNotice("Admin role is required.");
    return;
  }
  const form = new FormData(event.currentTarget);
  try {
    await api("/api/auth/users", {
      method: "POST",
      body: JSON.stringify({
        username: form.get("username"),
        role: form.get("role"),
        password: form.get("password"),
      }),
    });
    event.currentTarget.reset();
    await loadAdminData();
    renderAll();
    showNotice("User created.");
  } catch (error) {
    showNotice(error.message);
  }
});

qsa(".run-task").forEach((button) => {
  button.addEventListener("click", () => {
    enqueueTask(button.dataset.task, button);
  });
});

qsa(".nav-list a").forEach((link) => {
  link.addEventListener("click", () => {
    qsa(".nav-list a").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
  });
});

boot();
setInterval(formatUtcClock, 1000);
setInterval(() => {
  if (!hasApiAccess() || !state.selectedProject) return;
  loadDashboard()
    .then(() => {
      renderHeaderAndMetrics();
      renderLastScans();
      renderActivity();
      renderReconAssets();
    })
    .catch(() => {});
}, 7000);
