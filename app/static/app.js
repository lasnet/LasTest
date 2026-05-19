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
    client: "External Pentest Project",
    description: "External Pentest Project",
    created_at: "today",
  },
  scope: {
    domains: ["example.com", "corp.example.com", "api.example.com"],
    ips: [
      "203.0.113.10",
      "203.0.113.11",
      "203.0.113.12",
      "203.0.113.13",
      "203.0.113.14",
      "203.0.113.15",
      "203.0.113.16",
      "203.0.113.17",
      "203.0.113.18",
      "203.0.113.19",
      "203.0.113.20",
      "203.0.113.21",
    ],
    exclusions: ["legacy.example.com", "10.0.0.0/8"],
  },
};

const demoFindings = [
  ["critical", "Exposed admin panel", "admin.example.com", "Open"],
  ["high", "TLS weak cipher suite", "vpn.example.com", "In review"],
  ["high", "Directory listing enabled", "static.example.com", "Open"],
  ["medium", "Missing security headers", "www.example.com", "Accepted"],
  ["low", "Verbose server banner", "mail.example.com", "Triaged"],
];

const demoLog = [
  "[14:32:01] Starting subfinder for example.com",
  "[14:32:14] Found 421 subdomains",
  "[14:33:02] Running httpx probe",
  "[14:34:45] Alive hosts: 231",
  "[14:35:00] Starting nuclei templates",
].join("\n");

const qs = (selector) => document.querySelector(selector);

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

function setApiStatus(label, tone = "waiting") {
  const el = qs("#api-status");
  el.textContent = label;
  el.style.color =
    tone === "ok" ? "var(--green)" : tone === "error" ? "var(--red)" : "var(--yellow)";
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
    let detail = response.statusText;
    try {
      const data = await response.json();
      detail = data.detail || detail;
    } catch (_) {
      detail = await response.text();
    }
    throw new Error(detail);
  }
  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

function activeDetail() {
  return state.projectDetail || demoProject;
}

function primaryDomain(detail = activeDetail()) {
  const domains = detail.scope?.domains || [];
  return domains[0] || detail.project?.name || "example.com";
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

function renderHeader() {
  const detail = activeDetail();
  const hasRealProject = Boolean(state.projectDetail);
  const project = detail.project || {};
  const scope = detail.scope || {};
  const name = project.name || primaryDomain(detail);
  const subtitle = project.description || project.client || "External Pentest Project";
  const domains = scope.domains || [];
  const ips = scope.ips || [];
  const exclusions = scope.exclusions || [];

  qs("#project-title").textContent = name;
  qs("#project-subtitle").textContent = subtitle || "External Pentest Project";
  qs("#sidebar-current-project").textContent = name;
  qs("#scope-summary").innerHTML = `
    <span>Domains: ${esc(hasRealProject ? domains.length : 3)}</span>
    <span>IPs: ${esc(hasRealProject ? ips.length : 12)}</span>
    <span>Exclusions: ${esc(hasRealProject ? exclusions.length : 2)}</span>
  `;

  const subdomains = hasRealProject ? domains.length * 37 : 671;
  const alive = hasRealProject ? Math.floor(subdomains * 0.34) : 231;
  qs("#metric-subdomains").textContent = subdomains.toString();
  qs("#metric-subdomains-detail").textContent = `${alive} alive`;
}

function renderScopeForm() {
  const detail = activeDetail();
  const scope = detail.scope || {};
  qs("#scope-form textarea[name='domains']").value = (scope.domains || []).join("\n");
  qs("#scope-form textarea[name='ips']").value = (scope.ips || []).join("\n");
}

function renderAttackTree() {
  const domain = primaryDomain();
  const scope = activeDetail().scope || {};
  const domains = scope.domains?.length ? scope.domains : [domain];
  const nodes = [
    [`www.${domain}`, "443, nginx"],
    [`admin.${domain}`, "443, Apache"],
    [`vpn.${domain}`, "8443, SSL VPN"],
    [`mail.${domain}`, "25, 587, 993"],
  ];

  for (const scopedDomain of domains.slice(1, 4)) {
    nodes.push([scopedDomain, "80, 443, httpx pending"]);
  }

  qs("#attack-tree").innerHTML = `
    <div class="tree-root">${esc(domain)}</div>
    ${nodes
      .map(
        ([host, meta]) => `
          <div class="tree-item">
            <span>${esc(host)}</span>
            <span>${esc(meta)}</span>
          </div>
        `,
      )
      .join("")}
  `;
}

function renderFindingsTable() {
  qs("#findings-table").innerHTML = demoFindings
    .map(
      ([severity, finding, asset, status]) => `
        <tr>
          <td><span class="severity ${esc(severity)}">${esc(severity)}</span></td>
          <td>${esc(finding)}</td>
          <td>${esc(asset)}</td>
          <td>${esc(status)}</td>
        </tr>
      `,
    )
    .join("");
}

function renderRunningScans() {
  const running = state.jobs.find((job) => job.status === "running");
  const queued = state.jobs.find((job) => job.status === "queued");
  const recent = running || queued || state.jobs[0];

  if (recent) {
    const progress = recent.status === "succeeded" ? 100 : recent.status === "failed" ? 100 : 72;
    const eta = recent.status === "running" ? "ETA 4 min" : recent.status;
    qs("#running-scans").innerHTML = `
      <div class="scan-title">
        <strong>${esc(recent.task_type)}</strong>
        <span class="chip ${recent.status === "failed" ? "red" : "blue"}">${esc(recent.status)}</span>
      </div>
      <p class="scan-meta">target: ${esc(primaryDomain())} / job ${esc(recent.id.slice(0, 8))}</p>
      <div class="progress-track"><div class="progress-bar" style="width:${progress}%"></div></div>
      <div class="scan-stats">
        <span>${progress}% progress</span>
        <span>${esc(recent.result?.findings ?? 8)} findings</span>
        <span>${esc(eta)}</span>
      </div>
    `;
    return;
  }

  qs("#running-scans").innerHTML = `
    <div class="scan-title">
      <strong>Nuclei Scan</strong>
      <span class="chip blue">running</span>
    </div>
    <p class="scan-meta">target: alive_urls.txt</p>
    <div class="progress-track"><div class="progress-bar"></div></div>
    <div class="scan-stats">
      <span>72% progress</span>
      <span>8 findings</span>
      <span>ETA 4 min</span>
    </div>
  `;
}

async function renderTerminalLog() {
  const recent = state.jobs[0];
  if (!recent) {
    qs("#terminal-log").textContent = demoLog;
    return;
  }

  try {
    const log = await api(`/api/jobs/${encodeURIComponent(recent.id)}/log`);
    qs("#terminal-log").textContent = log || demoLog;
  } catch (_) {
    qs("#terminal-log").textContent = demoLog;
  }
}

function renderAll() {
  renderProjectSelector();
  renderHeader();
  renderScopeForm();
  renderAttackTree();
  renderFindingsTable();
  renderRunningScans();
}

async function loadProjects() {
  const data = await api("/api/projects");
  state.projects = data.projects || [];

  const selectedExists = state.projects.some((project) => project.name === state.selectedProject);
  if ((!state.selectedProject || !selectedExists) && state.projects.length) {
    state.selectedProject = state.projects[0].name;
    localStorage.setItem("lastest_project", state.selectedProject);
  }

  renderProjectSelector();
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

async function selectProject(name) {
  state.selectedProject = name;
  if (name) {
    localStorage.setItem("lastest_project", name);
  } else {
    localStorage.removeItem("lastest_project");
  }
  await loadProjectDetail();
  await loadJobs();
  renderAll();
  await renderTerminalLog();
}

async function refreshData() {
  await loadProjects();
  await loadProjectDetail().catch(() => {
    state.selectedProject = "";
    state.projectDetail = null;
    localStorage.removeItem("lastest_project");
  });
  await loadJobs().catch(() => {
    state.jobs = [];
  });
  renderAll();
  await renderTerminalLog();
}

async function boot() {
  qs("#api-key").value = state.apiKey;
  renderAll();
  await renderTerminalLog();

  if (!state.apiKey) {
    setApiStatus("no key", "waiting");
    return;
  }

  try {
    await refreshData();
    setApiStatus("connected", "ok");
  } catch (error) {
    setApiStatus("denied", "error");
    showNotice(error.message);
  }
}

qs("#api-key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  state.apiKey = qs("#api-key").value.trim();
  localStorage.setItem("lastest_api_key", state.apiKey);
  await boot();
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
        description: form.get("description") || "External Pentest Project",
      }),
    });
    event.currentTarget.reset();
    event.currentTarget.hidden = true;
    await loadProjects();
    await selectProject(created.project.name);
    setApiStatus("connected", "ok");
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
    setApiStatus("connected", "ok");
    showNotice("Scope saved.");
  } catch (error) {
    showNotice(error.message);
  }
});

qs("#refresh-detail").addEventListener("click", () => {
  refreshData()
    .then(() => setApiStatus("connected", "ok"))
    .catch((error) => {
      setApiStatus("error", "error");
      showNotice(error.message);
    });
});

qs("#refresh-jobs").addEventListener("click", () => {
  loadJobs()
    .then(() => {
      renderRunningScans();
      return renderTerminalLog();
    })
    .catch((error) => showNotice(error.message));
});

boot();

setInterval(() => {
  if (!state.apiKey || !state.selectedProject) {
    return;
  }
  loadJobs()
    .then(() => {
      renderRunningScans();
      return renderTerminalLog();
    })
    .catch(() => {});
}, 6000);
