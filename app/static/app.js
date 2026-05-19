const state = {
  apiKey: localStorage.getItem("lastest_api_key") || "",
  selectedProject: localStorage.getItem("lastest_project") || "",
  projects: [],
  projectDetail: null,
  jobs: [],
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
  return Boolean(state.projectDetail);
}

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  if (state.apiKey) {
    headers["X-API-Key"] = state.apiKey;
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
    throw new Error(detailText);
  }

  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    return response.json();
  }
  return response.text();
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
    option.textContent = "example.com";
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
  if (!isRealProject()) {
    return {
      domains: 2,
      ips: 3,
      exclusions: 2,
      subdomains: 128,
      alive: 34,
      openPorts: 12,
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
    alive,
    openPorts: Math.max(0, ips.length * 4),
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
  qs("#metric-subdomains-delta").textContent =
    isRealProject() ? `+${Math.max(values.domains, 0)} in scope` : "+18 new";
  qs("#metric-alive-delta").textContent = isRealProject() ? `${values.alive} calculated` : "+7 new";

  qs("#stat-ipv4").textContent = values.ips || 45;
  qs("#stat-domains").textContent = values.domains || 2;
  qs("#stat-subdomains").textContent = values.subdomains || 128;
  qs("#stat-alive").textContent = values.alive || 34;
  qs("#assets-badge").textContent = Math.max(values.domains + values.ips, 0) || 128;
}

function renderScopeForm() {
  const scope = currentScope();
  qs("#scope-form textarea[name='domains']").value = (scope.domains || []).join("\n");
  qs("#scope-form textarea[name='ips']").value = (scope.ips || []).join("\n");
}

function renderLastScans() {
  const rows = state.jobs.length
    ? state.jobs.slice(0, 5).map((job) => [
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
  const rows = state.jobs.length
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

function renderAll() {
  renderProjectSelector();
  renderHeaderAndMetrics();
  renderScopeForm();
  renderLastScans();
  renderActivity();
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

async function loadProjects() {
  const data = await api("/api/projects");
  state.projects = data.projects || [];
  const selectedExists = state.projects.some((project) => project.name === state.selectedProject);

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

async function loadJobs() {
  if (!state.selectedProject) {
    state.jobs = [];
    return;
  }
  const data = await api(`/api/jobs?project_name=${encodeURIComponent(state.selectedProject)}`);
  state.jobs = data.jobs || [];
}

async function refreshData() {
  await loadProjects();
  await loadProjectDetail().catch(() => {
    state.projectDetail = null;
    state.selectedProject = "";
    localStorage.removeItem("lastest_project");
  });
  await loadJobs().catch(() => {
    state.jobs = [];
  });
  renderAll();
}

async function selectProject(name) {
  state.selectedProject = name;
  if (name) {
    localStorage.setItem("lastest_project", name);
  }
  await loadProjectDetail();
  await loadJobs();
  renderAll();
}

async function boot() {
  qs("#api-key").value = state.apiKey;
  formatUtcClock();
  renderAll();

  if (!state.apiKey) {
    return;
  }

  try {
    await refreshData();
  } catch (error) {
    showNotice(error.message);
  }
}

qs("#api-key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.apiKey = qs("#api-key").value.trim();
  localStorage.setItem("lastest_api_key", state.apiKey);
  await boot();
  showNotice("API key saved.");
});

qs("#new-project-toggle").addEventListener("click", () => {
  const form = qs("#create-project-form");
  form.hidden = !form.hidden;
});

qs("#create-project-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.apiKey) {
    showNotice("Set X-API-Key first.");
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

qsa(".nav-list a").forEach((link) => {
  link.addEventListener("click", () => {
    qsa(".nav-list a").forEach((item) => item.classList.remove("active"));
    link.classList.add("active");
  });
});

boot();
setInterval(formatUtcClock, 1000);
setInterval(() => {
  if (!state.apiKey || !state.selectedProject) return;
  loadJobs()
    .then(() => {
      renderLastScans();
      renderActivity();
    })
    .catch(() => {});
}, 7000);
