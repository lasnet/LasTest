const state = {
  apiKey: localStorage.getItem("lastest_api_key") || "",
  selectedProject: localStorage.getItem("lastest_project") || "",
  tasks: [],
};

const qs = (selector) => document.querySelector(selector);

function showNotice(message) {
  const notice = qs("#notice");
  notice.textContent = message;
  notice.hidden = false;
  clearTimeout(showNotice.timer);
  showNotice.timer = setTimeout(() => {
    notice.hidden = true;
  }, 4500);
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

function lines(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderProjects(projects) {
  const root = qs("#projects-list");
  root.innerHTML = "";
  if (!projects.length) {
    root.innerHTML = '<p class="muted">No projects yet.</p>';
    return;
  }

  for (const project of projects) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `row secondary ${project.name === state.selectedProject ? "active" : ""}`;
    row.innerHTML = `
      <span class="row-head">
        <strong>${esc(project.name)}</strong>
        <span class="meta">${esc(project.domains_count)} domains</span>
      </span>
      <span class="meta">${esc(project.client || "no client")} - ${esc(project.ips_count)} IPs</span>
    `;
    row.addEventListener("click", () => selectProject(project.name));
    root.appendChild(row);
  }
}

async function loadProjects() {
  const data = await api("/api/projects");
  renderProjects(data.projects || []);
}

async function selectProject(name) {
  state.selectedProject = name;
  localStorage.setItem("lastest_project", name);
  await loadProjectDetail();
  await loadProjects();
  await loadJobs();
}

async function loadProjectDetail() {
  if (!state.selectedProject) {
    return;
  }
  const data = await api(`/api/projects/${encodeURIComponent(state.selectedProject)}`);
  const project = data.project || {};
  const scope = data.scope || {};
  qs("#project-title").textContent = project.name || state.selectedProject;
  qs("#project-detail").innerHTML = `
    <div><strong>Client:</strong> ${esc(project.client || "-")}</div>
    <div><strong>Description:</strong> ${esc(project.description || "-")}</div>
    <div><strong>Created:</strong> ${esc(project.created_at || "-")}</div>
    <div><strong>Domains:</strong> ${esc((scope.domains || []).join(", ") || "-")}</div>
    <div><strong>IPs:</strong> ${esc((scope.ips || []).join(", ") || "-")}</div>
  `;
  qs("#scope-form textarea[name='domains']").value = (scope.domains || []).join("\n");
  qs("#scope-form textarea[name='ips']").value = (scope.ips || []).join("\n");
}

function renderTasks(tasks) {
  const root = qs("#task-list");
  root.innerHTML = "";
  for (const task of tasks) {
    const row = document.createElement("div");
    row.className = "row";
    const missing = task.missing_tools.length ? `Missing: ${task.missing_tools.join(", ")}` : "Ready";
    row.innerHTML = `
      <div class="row-head">
        <strong>${esc(task.title)}</strong>
        <button type="button" ${task.available ? "" : "disabled"}>Run</button>
      </div>
      <span class="meta">${esc(task.description)}</span>
      <span class="meta">${esc(missing)}</span>
    `;
    row.querySelector("button").addEventListener("click", () => createJob(task.task_type));
    root.appendChild(row);
  }
}

async function loadTools() {
  const data = await api("/api/tools");
  state.tasks = data.tasks || [];
  renderTasks(state.tasks);
}

async function createJob(taskType) {
  if (!state.selectedProject) {
    showNotice("Select a project first.");
    return;
  }
  const payload = { task_type: taskType, params: {} };
  if (taskType === "nuclei") {
    payload.params.severities = "critical,high,medium";
  }
  const job = await api(`/api/projects/${encodeURIComponent(state.selectedProject)}/jobs`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  showNotice(`Job queued: ${job.id}`);
  await loadJobs();
}

function renderJobs(jobs) {
  const root = qs("#jobs-list");
  root.innerHTML = "";
  if (!jobs.length) {
    root.innerHTML = '<p class="muted">No jobs yet.</p>';
    return;
  }
  for (const job of jobs) {
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <div class="row-head">
        <strong>${esc(job.task_type)}</strong>
        <span class="status ${esc(job.status)}">${esc(job.status)}</span>
      </div>
      <span class="meta">${esc(job.project_name)} - ${esc(job.created_at)}</span>
      <div class="row-head">
        <span class="meta">${esc(job.error || JSON.stringify(job.result || {}))}</span>
        <button type="button" class="secondary">Log</button>
      </div>
    `;
    row.querySelector("button").addEventListener("click", () => loadJobLog(job.id));
    root.appendChild(row);
  }
}

async function loadJobs() {
  const query = state.selectedProject ? `?project_name=${encodeURIComponent(state.selectedProject)}` : "";
  const data = await api(`/api/jobs${query}`);
  renderJobs(data.jobs || []);
}

async function loadJobLog(jobId) {
  const text = await api(`/api/jobs/${encodeURIComponent(jobId)}/log`);
  const pre = qs("#job-log");
  pre.textContent = text || "No log output.";
  pre.hidden = false;
}

async function boot() {
  qs("#api-key").value = state.apiKey;
  await loadTools();
  await loadProjects();
  if (state.selectedProject) {
    await loadProjectDetail().catch(() => {
      state.selectedProject = "";
      localStorage.removeItem("lastest_project");
    });
  }
  await loadJobs();
}

qs("#api-key-form").addEventListener("submit", (event) => {
  event.preventDefault();
  state.apiKey = qs("#api-key").value.trim();
  localStorage.setItem("lastest_api_key", state.apiKey);
  showNotice("API key saved.");
  boot().catch((error) => showNotice(error.message));
});

qs("#create-project-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const project = await api("/api/projects", {
      method: "POST",
      body: JSON.stringify({
        name: form.get("name"),
        client: form.get("client"),
        description: form.get("description"),
      }),
    });
    event.currentTarget.reset();
    await selectProject(project.project.name);
  } catch (error) {
    showNotice(error.message);
  }
});

qs("#scope-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.selectedProject) {
    showNotice("Select a project first.");
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
    await loadProjectDetail();
    await loadProjects();
    showNotice("Scope saved.");
  } catch (error) {
    showNotice(error.message);
  }
});

qs("#refresh-projects").addEventListener("click", () => loadProjects().catch((error) => showNotice(error.message)));
qs("#refresh-detail").addEventListener("click", () => loadProjectDetail().catch((error) => showNotice(error.message)));
qs("#refresh-jobs").addEventListener("click", () => loadJobs().catch((error) => showNotice(error.message)));

boot().catch((error) => showNotice(error.message));
setInterval(() => {
  if (state.apiKey || location.hostname === "localhost") {
    loadJobs().catch(() => {});
  }
}, 5000);
