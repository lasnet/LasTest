(() => {
  "use strict";

  const state = {
    me: null,
    projects: [],
    projectId: "",
    project: null,
    dashboard: null,
    assets: null,
    assetsQuery: "",
    assetsOffset: 0,
    assetsLoading: false,
    assetsRequest: 0,
    assetFilters: { technology: "", provider: "", category: "" },
    candidates: null,
    candidatesQuery: "",
    candidateFilters: { source: "", dns_status: "", ip_match: "", scope_status: "", confidence: "", interest: "" },
    candidatesOffset: 0,
    candidatesLoading: false,
    candidatesRequest: 0,
    candidateDetail: null,
    assetDetail: null,
    providers: {},
    discoveryHttpEnrichment: false,
    targetCatalog: null,
    candidateDetailRequest: 0,
    assetDetailRequest: 0,
    deleteAsset: null,
    assetDeleting: false,
    scope: null,
    scopeHistory: [],
    rules: [],
    scopeSaving: false,
    taskTypes: [],
    jobs: [],
    view: "dashboard",
    poll: null,
    loading: false,
  };

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));
  const dateLabel = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeZone: "UTC" });
  const timeLabel = new Intl.DateTimeFormat("en-GB", { timeStyle: "medium", timeZone: "UTC" });
  const countLabel = new Intl.NumberFormat("en");
  const dateColumns = new Set(["Time", "Finished", "Observed", "First seen", "Last seen", "Created", "Approved"]);
  const numberColumns = new Set(["HTTP status", "Port", "Evaluated", "Findings", "Not applicable"]);
  const wrapColumns = new Set(["URL", "Value", "Reason", "Title", "Asset", "Entity"]);
  const severityStyles = { critical: "bad", high: "bad", medium: "warn" };
  const assetMetrics = [["Hosts", "hosts"], ["IP addresses", "ips"], ["URLs", "urls"]];
  const dashboardMetrics = [...assetMetrics, ["Open ports", "open_ports"], ["Findings", "findings"], ["Jobs", "jobs"]];

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

  let noticeTimer;
  function notice(message, kind = "info") {
    clearTimeout(noticeTimer);
    const node = $("#notice");
    if (!message) {
      node.hidden = true;
      node.textContent = "";
      return;
    }
    node.hidden = false;
    node.className = `notice ${kind}`;
    node.textContent = message;
    noticeTimer = setTimeout(() => {
      node.hidden = true;
      node.textContent = "";
    }, 10000);
  }

  function displayTime(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return el("span", value);
    const time = el("time", dateLabel.format(date), "table-time");
    time.dateTime = value;
    time.title = value;
    time.appendChild(el("span", `${timeLabel.format(date)} UTC`));
    return time;
  }

  function table(columns, rows, cellValue, rowClass) {
    if (!rows || rows.length === 0) {
      return el("p", "No data for this view.", "empty");
    }
    const wrapper = el("div", null, "table-wrap");
    const compactRows = columns.length > 3;
    if (compactRows) wrapper.classList.add("table-wide");
    const tbl = el("table");
    const thead = el("thead");
    const headerRow = el("tr");
    for (const column of columns) {
      const heading = el("th", column, numberColumns.has(column) ? "table-number" : "");
      heading.scope = "col";
      headerRow.appendChild(heading);
    }
    thead.appendChild(headerRow);
    const tbody = el("tbody");
    if (compactRows) {
      tbl.setAttribute("role", "table");
      thead.setAttribute("role", "rowgroup");
      tbody.setAttribute("role", "rowgroup");
      headerRow.setAttribute("role", "row");
      for (const heading of headerRow.children) heading.setAttribute("role", "columnheader");
    }
    for (const row of rows) {
      const tr = el("tr", null, rowClass ? rowClass(row) : "");
      if (compactRows) tr.setAttribute("role", "row");
      for (const column of columns) {
        const td = el("td");
        if (numberColumns.has(column)) td.classList.add("table-number");
        if (wrapColumns.has(column)) td.classList.add("table-wrap-text");
        if (compactRows) {
          td.setAttribute("role", "cell");
          td.dataset.label = column;
          if (column) {
            const label = el("span", column, "compact-cell-label");
            label.setAttribute("aria-hidden", "true");
            td.appendChild(label);
          }
        }
        const value = cellValue ? cellValue(row, column) : row[column];
        if (value instanceof Node) td.appendChild(value);
        else if (value && dateColumns.has(column)) td.appendChild(displayTime(value));
        else if (value && column === "Severity") {
          td.appendChild(el("span", value, `badge ${severityStyles[value] || ""}`));
        } else if (value && column === "Status" && statusClass(value)) {
          td.appendChild(el("span", value, `badge ${statusClass(value)}`));
        } else {
          td.append(value === null || value === undefined || value === "" ? "—" : String(value));
        }
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
    $("#loading-view").hidden = true;
    notice("");
    $("#app-view").hidden = true;
    $("#login-view").hidden = false;
    $("#setup-form").hidden = true;
    $("#login-form").hidden = false;
    $("#login-password").value = "";
  }

  function showApp() {
    $("#loading-view").hidden = true;
    selectedModules.clear();
    scanChoices.clear();
    scanParams.clear();
    submissionKeys.clear();
    state.projectId = "";
    state.project = null;
    state.dashboard = null;
    state.scope = null;
    state.scopeHistory = [];
    state.rules = [];
    state.jobs = [];
    $("#scope-note").value = "";
    $("#login-view").hidden = true;
    $("#app-view").hidden = false;
    $("#current-user").replaceChildren(
      el("span", state.me.username),
      el("span", state.me.role, "account-role"),
    );
    const admin = state.me.role === "admin";
    $$("[data-admin-only]").forEach((node) => { node.hidden = !admin; });
    const analyst = admin || state.me.role === "analyst";
    $("#new-project-button").hidden = !analyst;
    $("#start-scanning-button").disabled = true;
    $("#save-approve-scope-button").disabled = !analyst;
    $("#add-rule-button").disabled = !analyst;
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
    if (!state.projectId) {
      try {
        state.projectId = localStorage.getItem(projectStorageKey()) || "";
      } catch {
        // The selector still works when browser storage is unavailable.
      }
    }
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
      rememberProject();
    }
    renderProjectCaption();
  }

  function projectStorageKey() {
    return `lastest.project.${state.me.id || state.me.username}`;
  }

  function rememberProject() {
    try {
      if (state.projectId) localStorage.setItem(projectStorageKey(), state.projectId);
      else localStorage.removeItem(projectStorageKey());
    } catch {
      // Keep the current selection in memory when storage is unavailable.
    }
  }

  function renderProjectCaption() {
    const item = state.projects.find(({ project }) => project.id === state.projectId);
    $("#project-name-label").textContent = item?.project.name ?? "Select a project…";
    $("#project-scope-label").textContent = item?.scope_status
      ? `Scope ${item.scope_status.replaceAll("_", " ")}`
      : "Project";
  }

  async function loadTaskTypes() {
    try {
      const value = await api("/api/task-types");
      state.taskTypes = value.task_types || [];
      state.providers = value.providers || {};
      renderScanModules();
      renderProviderCatalog();
    } catch (error) { notice(error.message, "error"); }
  }

  async function selectProject(id) {
    state.projectId = id;
    state.assets = null;
    state.assetsQuery = "";
    state.assetsOffset = 0;
    state.assetsRequest++;
    state.assetsLoading = false;
    state.candidates = null;
    state.candidatesQuery = "";
    state.candidatesOffset = 0;
    state.candidatesRequest++;
    state.candidatesLoading = false;
    state.candidateDetail = null;
    state.assetDetail = null;
    state.candidateDetailRequest++;
    state.assetDetailRequest++;
    for (const id of ["candidate-detail-dialog", "asset-detail-dialog"]) $("#" + id).close();
    state.assetFilters = { technology: "", provider: "", category: "" };
    state.candidateFilters = { source: "", dns_status: "", ip_match: "", scope_status: "", confidence: "", interest: "" };
    for (const input of $$("#assets-filter-technology, #assets-filter-provider, #assets-filter-category, #candidates-source, #candidates-dns, #candidates-ip-match, #candidates-scope, #candidates-confidence, #candidates-interest")) input.value = "";
    clearTimeout(assetsSearchTimer);
    clearTimeout(candidatesSearchTimer);
    $("#assets-search").value = "";
    $("#candidates-search").value = "";
    selectedModules.clear();
    scanParams.clear();
    state.targetCatalog = null;
    state.discoveryHttpEnrichment = false;
    targetSelections.clear();
    settingsTargetIds = new Set();
    for (const dialog of ["scan-module-dialog", "asset-target-dialog", "asset-readiness-dialog"]) $("#" + dialog).close();
    rememberProject();
    state.project = state.projects.find((item) => item.project.id === id)?.project || null;
    state.dashboard = null;
    state.scope = null;
    state.scopeHistory = [];
    state.rules = [];
    state.jobs = [];
    $("#scope-note").value = "";
    $("#scope-search").value = "";
    $("#scope-error").textContent = "";
    $("#scan-error").textContent = "";
    renderProjectCaption();
    notice("");
    render();
    if (!id) return;
    try {
      const requests = [loadScope(), loadJobs()];
      if (["dashboard", "assets", "findings"].includes(state.view)) requests.push(loadDashboard());
      await Promise.all(requests);
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
    $$("[data-view-heading]").forEach((node) => { node.hidden = node.dataset.viewHeading !== state.view; });
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
    renderScanModules();
    renderDashboard();
    renderFindings();
    renderAssets();
    renderCandidates();
    renderProviderCatalog();
    if (state.view === "users") renderUsers();
  }

  async function refreshCurrent() {
    if (!state.projectId) return;
    try {
      if (["dashboard", "assets", "findings"].includes(state.view)) await loadDashboard();
      if (state.view === "assets") await loadCandidates();
      if (state.view === "scans") await Promise.all([loadJobs(), loadScope()]);
      if (state.view === "scope") await loadScope();
      if (state.view === "users") await loadAdmin();
    } catch (error) {
      notice(error.message, "error");
    }
  }

  async function loadDashboard(refreshAssets = true) {
    if (!requireProject()) return;
    const projectId = state.projectId;
    const value = await api(`/api/projects/${encodeURIComponent(projectId)}/dashboard`);
    if (projectId !== state.projectId) return;
    state.dashboard = value;
    renderDashboard();
    renderAssets();
    renderFindings();
    if (refreshAssets && state.view === "assets") await loadAssets();
  }

  async function loadScope() {
    if (!requireProject() || scopeHasChanges() || state.scopeSaving) return;
    const projectId = state.projectId;
    const value = await api(`/api/projects/${encodeURIComponent(projectId)}/scope`);
    if (state.projectId !== projectId || scopeHasChanges() || state.scopeSaving) return;
    if (state.scope && value.scope.version < state.scope.version) return;
    applyScope(value.scope);
    state.scopeHistory = value.history || [];
    renderScope();
  }

  function applyScope(scope) {
    state.scope = scope;
    state.rules = (scope.rules || []).map((rule) => ({ ...rule }));
  }

  function scopeChanges() {
    const saved = state.scope?.rules || [];
    return {
      added: state.rules.filter((rule) => !saved.some((item) => sameRule(item, rule))).length,
      removed: saved.filter((rule) => !state.rules.some((item) => sameRule(item, rule))).length,
    };
  }

  function sameRule(left, right) {
    return left.kind === right.kind && left.value === right.value && Boolean(left.exclusion) === Boolean(right.exclusion);
  }

  function scopeHasChanges() {
    const { added, removed } = scopeChanges();
    return added > 0 || removed > 0 || Boolean($("#scope-note").value.trim());
  }

  const scopeTypes = { exact_domain: "DNS Name", subdomain_tree: "DNS Name (including subdomains)", ip: "IP address", cidr: "Network" };
  const recordsObserver = new ResizeObserver(() => {
    const wrapper = $("#scope-rules .table-wrap");
    if (!wrapper) return;
    const rows = Array.from(wrapper.querySelectorAll("tbody tr")).slice(0, 5);
    const heading = wrapper.querySelector("thead");
    const headerHeight = getComputedStyle(heading).position === "absolute" ? 0 : heading.getBoundingClientRect().height;
    wrapper.style.maxHeight = `${headerHeight + rows.reduce((height, row) => height + row.getBoundingClientRect().height, 0) + 2}px`;
  });

  async function loadJobs() {
    if (!requireProject()) return;
    const projectId = state.projectId;
    const value = await api(`/api/projects/${encodeURIComponent(projectId)}/jobs?limit=100`);
    if (state.projectId !== projectId) return;
    state.jobs = value.items || [];
    renderJobs();
  }

  function renderScope() {
    recordsObserver.disconnect();
    const rules = $("#scope-rules");
    clear(rules);
    const query = $("#scope-search").value.trim().toLocaleLowerCase();
    const filtered = state.rules.filter((rule) =>
      [scopeTypes[rule.kind], rule.value, rule.exclusion ? "exclude" : "allow"]
        .some((value) => value.toLocaleLowerCase().includes(query)));
    if (!state.projectId) {
      rules.appendChild(el("p", "Select a project to view its records.", "empty"));
    } else if (!state.scope) {
      rules.appendChild(el("p", "Loading records…", "muted"));
    } else if (!filtered.length) {
      rules.appendChild(el("p", query ? "No matching records." : "No records. Add an allowed record to get started.", "empty"));
    } else {
      rules.appendChild(table(["Type", "Value", "Effect", ""], filtered, (rule, column) => {
        if (column === "Type") return scopeTypes[rule.kind];
        if (column === "Value") return rule.value;
        if (column === "Effect") return el("span", rule.exclusion ? "exclude" : "allow", rule.exclusion ? "badge bad" : "badge ok");
        const button = el("button", "−", "secondary record-remove");
        button.setAttribute("aria-label", `Remove ${rule.value}`);
        button.title = `Remove ${rule.value}`;
        button.type = "button";
        button.disabled = state.scopeSaving || state.me?.role === "viewer";
        button.addEventListener("click", () => {
          state.rules = state.rules.filter((item) => item !== rule);
          renderScope();
        });
        return button;
      }, (rule) => (state.scope.rules || []).some((saved) => sameRule(saved, rule)) ? "" : "record-pending"));
    }
    const recordTable = rules.querySelector("table");
    if (recordTable) {
      rules.querySelector(".table-wrap").tabIndex = 0;
      recordsObserver.observe(recordTable);
    }
    updateScopeControls();
    updateScanLaunch();

    const history = $("#scope-history");
    clear(history);
    if (!state.projectId) {
      history.appendChild(el("p", "No project selected.", "empty"));
    } else {
      history.appendChild(table(
        ["Version", "Status", "Created", "Note"],
        state.scopeHistory || [],
        (revision, column) => {
          const map = {
            Version: revision.version,
            Status: revision.status,
            Created: revision.created_at,
            Note: revision.note || "—",
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
      const module = scanModules.find((item) => item.tasks.includes(job.task_type));
      const heading = el("div");
      if (module) heading.appendChild(el("p", module.title, "muted"));
      heading.appendChild(el("strong", job.task_type));
      const status = el("span", job.status === "partial" ? "Completed with errors" : job.status,
        `badge ${statusClass(job.status)}`);
      status.title = job.status;
      append(head, heading, status);
      card.appendChild(head);
      if (job.finished_at) {
        card.appendChild(append(el("p", "Finished ", "muted"), displayTime(job.finished_at)));
      }
      const counters = job.counters || {};
      const details = el("dl", null, "job-counters");
      for (const [label, count] of [["Targets", counters.targets], ["Processed", counters.processed], ["Skipped", counters.skipped], ["Errors", counters.errors]]) {
        details.appendChild(append(el("div"), el("dt", label), el("dd", countLabel.format(count || 0))));
      }
      card.appendChild(details);
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
    if (status === "partial" || status === "queued" || status === "running" || status === "pending_review") return "warn";
    if (status === "failed" || status === "cancelled" || status === "interrupted") return "bad";
    return "";
  }

  function renderMetric(label, count, tone) {
    return append(el("div", null, `metric tone-${tone}`),
      el("span", label, "metric-label"),
      el("span", countLabel.format(count), "metric-value"));
  }

  function renderAssetChart(data) {
    const values = assetMetrics.map(([, key]) => data[key] ?? 0);
    const peak = Math.max(5, ...values);
    const magnitude = 10 ** Math.floor(Math.log10(peak / 5));
    const step = magnitude * [1, 2, 5, 10].find((factor) => factor * magnitude * 5 >= peak);
    const ceiling = Math.ceil(peak / step) * step;
    const chart = el("div", null, "asset-chart");
    chart.style.setProperty("--asset-axis-width", `${countLabel.format(ceiling).length + 3}ch`);
    const axis = el("div", null, "asset-axis");
    axis.setAttribute("aria-hidden", "true");
    for (let tick = ceiling; tick >= 0; tick -= step) {
      axis.appendChild(el("span", countLabel.format(tick), "asset-tick"));
    }
    const columns = el("div", null, "asset-columns");
    assetMetrics.forEach(([label, key], index) => {
      const value = values[index];
      const column = el("div", null, `asset-column tone-${key}`);
      const bar = el("div", null, "asset-bar");
      bar.style.height = `${value / ceiling * 100}%`;
      bar.appendChild(el("span", countLabel.format(value), "asset-value"));
      append(columns, append(column, bar, el("span", label, "asset-label")));
    });
    $("#dashboard-asset-chart").replaceChildren(append(chart, axis, columns));
  }

  function renderDashboard() {
    const empty = $("#dashboard-empty");
    const content = $("#dashboard-content");
    if (!state.projectId) {
      empty.hidden = false;
      empty.replaceChildren(el("h2", "Choose a project"), el("p", "Use the project selector to see its jobs, assets and findings."));
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
      empty.replaceChildren(el("h2", "No observations yet"), el("p", "Approve the project scope and run a scan to see results here."));
      content.hidden = true;
      return;
    }
    content.hidden = false;
    const metrics = $("#dashboard-metrics");
    const data = state.dashboard.metrics;
    metrics.replaceChildren(...dashboardMetrics.map(([label, key]) => renderMetric(label, data[key] ?? 0, key)));
    renderAssetChart(data);
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
    $("#dashboard-worker").replaceChildren(
      el("span", `Worker: ${worker.state}`, worker.state === "ready" ? "badge ok" : "badge warn"),
    );
    if (worker.last_heartbeat) {
      availability.appendChild(el("p", `Last heartbeat ${worker.last_heartbeat}`, "worker-heartbeat muted"));
    }
    const unavailable = state.dashboard.availability?.unavailable || [];
    const errors = state.dashboard.availability?.recent_source_errors || {};
    if (!unavailable.length && !Object.keys(errors).length) {
      availability.appendChild(el("p", "All configured task types and sources are available.", "muted"));
    } else {
      const items = unavailable.map((item) => ({ "Source": item.task_type, "Reason": item.reason }));
      for (const [task, reason] of Object.entries(errors)) items.push({ "Source": task, "Reason": reason });
      availability.appendChild(table(["Source", "Reason"], items));
    }

    const http = $("#dashboard-http");
    clear(http);
    http.appendChild(table(["URL", "HTTP status", "Source", "Observed"], state.dashboard.recent_http || [], (row, column) => {
      if (column === "HTTP status") {
        const code = row.data?.status_code;
        return code ? el("span", code, `badge ${code >= 500 ? "bad" : code >= 400 ? "warn" : "ok"}`) : "";
      }
      if (column === "Source") return row.source;
      if (column === "Observed") return row.observed_at;
      return row.url;
    }));

    const ports = $("#dashboard-ports");
    clear(ports);
    ports.appendChild(table(["IP", "Port", "State", "Service"], state.dashboard.recent_ports || [], (row, column) => {
      if (column === "IP") return row.ip;
      if (column === "Port") return row.data?.port ?? "";
      if (column === "State") {
        const status = row.data?.state;
        return status ? el("span", status, `badge ${status === "open" ? "ok" : status === "timeout" ? "warn" : ""}`) : "";
      }
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

  async function loadAssets() {
    if (!state.projectId) return;
    const projectId = state.projectId;
    const request = ++state.assetsRequest;
    const params = new URLSearchParams({ q: state.assetsQuery, offset: state.assetsOffset });
    if (state.assetFilters.technology) params.set("technology", state.assetFilters.technology);
    if (state.assetFilters.provider) params.set("provider", state.assetFilters.provider);
    if (state.assetFilters.category) params.set("category", state.assetFilters.category);
    state.assetsLoading = true;
    $("#assets-error").textContent = "";
    renderAssets();
    try {
      const value = await api(`/api/projects/${encodeURIComponent(projectId)}/assets?${params}`);
      if (request !== state.assetsRequest || projectId !== state.projectId) return;
      state.assets = value;
      state.assetsOffset = value.offset;
    } catch (error) {
      if (request !== state.assetsRequest || projectId !== state.projectId) return;
      state.assets = null;
      $("#assets-error").textContent = error.message;
    } finally {
      if (request === state.assetsRequest && projectId === state.projectId) {
        state.assetsLoading = false;
        renderAssets();
      }
    }
  }

  function renderAssets() {
    const node = $("#assets-inventory");
    clear(node);
    const data = state.assets;
    $("#assets-search").disabled = !state.projectId;
    if (!state.projectId) node.appendChild(el("p", "Select a project.", "empty"));
    else if (state.assetsLoading) node.appendChild(el("p", "Loading assets…", "empty"));
    else node.appendChild(table(["Hosts", "IP addresses", "Groups", "Confidence / interest", "Last seen", "Actions"], data?.items || [], (row, column) => {
      if (column === "Hosts") return row.host;
      if (column === "IP addresses") {
        const addresses = el("div");
        for (const ip of row.ips) addresses.appendChild(el("div", ip));
        return addresses;
      }
      if (column === "Groups") return (row.groups || []).join(", ") || "unknown";
      if (column === "Confidence / interest") return row.confidence
        ? `${row.confidence} / ${row.interest || "unknown"}` : "unknown";
      if (column === "Last seen") return row.last_seen;
      const wrap = el("div", null, "button-row");
      const details = el("button", "Details", "link");
      details.type = "button";
      details.addEventListener("click", () => openAssetDetail(row.id));
      const button = el("button", "×", "icon-button asset-delete");
      button.type = "button";
      const label = row.host || row.ips.join(", ");
      button.setAttribute("aria-label", `Delete ${label}`);
      button.title = state.me?.role === "viewer" ? "Analyst permission required" : `Delete ${label}`;
      button.disabled = state.me?.role === "viewer" || state.assetDeleting;
      button.addEventListener("click", () => {
        state.deleteAsset = { ...row, projectId: state.projectId };
        $("#delete-asset-error").textContent = "";
        $("#delete-asset-description").textContent = row.kind === "host"
          ? `Delete ${label}, its URL records, observations and findings from this project? IP address records will be kept, including shared IPs. Job history and evidence files remain. Future scans may discover this host again.`
          : `Delete ${label} and its observations and findings from this project? Job history and evidence files remain. Future scans may discover this IP again.`;
        $("#delete-asset-dialog").showModal();
      });
      append(wrap, details, button);
      return wrap;
    }));
    const total = data?.total || 0;
    const disabled = !state.projectId || !data || state.assetsLoading;
    $("#assets-previous").disabled = disabled || state.assetsOffset === 0;
    $("#assets-next").disabled = disabled || state.assetsOffset + 10 >= total;
    $("#assets-page-status").textContent = state.assetsLoading ? "Loading…" : total
      ? `${state.assetsOffset + 1}–${Math.min(state.assetsOffset + 10, total)} of ${total} · Page ${state.assetsOffset / 10 + 1} of ${Math.ceil(total / 10)}` : "0 records";
    for (const format of ["txt", "csv"]) $("#assets-export-" + format).disabled = disabled || total === 0;
    const urls = $("#assets-urls");
    clear(urls);
    urls.appendChild(table(["Value", "Last seen"], state.dashboard?.assets?.urls || [], (row, column) => column === "Value" ? row.value : row.last_seen));
  }

  async function downloadAssets(format) {
    if (!requireProject()) return;
    const projectId = state.projectId;
    const name = state.project?.name || "project";
    try {
      const params = new URLSearchParams({ q: state.assetsQuery });
      if (state.assetFilters.technology) params.set("technology", state.assetFilters.technology);
      if (state.assetFilters.provider) params.set("provider", state.assetFilters.provider);
      if (state.assetFilters.category) params.set("category", state.assetFilters.category);
      const blob = await apiBytes(`/api/projects/${encodeURIComponent(projectId)}/assets/export/${format}?${params}`);
      const url = URL.createObjectURL(blob);
      const link = el("a");
      link.href = url;
      link.download = `${name}-assets.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      notice(`Exported ${format.toUpperCase()} assets.`, "info");
    } catch (error) { notice(error.message, "error"); }
  }

  async function downloadCandidates(format) {
    if (!requireProject()) return;
    const projectId = state.projectId;
    const name = state.project?.name || "project";
    try {
      const params = new URLSearchParams({ q: state.candidatesQuery });
      for (const [key, value] of Object.entries(state.candidateFilters)) if (value) params.set(key, value);
      const blob = await apiBytes(`/api/projects/${encodeURIComponent(projectId)}/discovery/export/${format}?${params}`);
      const url = URL.createObjectURL(blob);
      const link = el("a");
      link.href = url;
      link.download = `${name}-candidates.${format}`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      notice(`Exported ${format.toUpperCase()} candidates.`, "info");
    } catch (error) { notice(error.message, "error"); }
  }

  function addCandidateToScope() {
    const host = $("#candidate-add-scope").dataset.host || "";
    if (!requireProject() || !host || state.scopeSaving || state.me?.role === "viewer") return;
    if ($("#candidate-detail-dialog").dataset.projectId !== state.projectId) {
      notice("The selected project changed. Reopen the candidate from the current project.", "error");
      return;
    }
    if (!state.scope) { notice("Load the project Scope before adding a name.", "error"); return; }
    if (state.rules.some((rule) => rule.kind === "exact_domain" && rule.value === host && !rule.exclusion)) {
      notice(`${host} is already in the Scope editor.`, "info");
      return;
    }
    // This only edits the unsaved Scope draft; saving and approval stay explicit.
    state.rules.push({ kind: "exact_domain", value: host, exclusion: false, verified: true });
    $("#candidate-detail-dialog").close();
    location.hash = "#scope";
    updateScopeControls();
    renderScope();
    notice(`${host} was added to the Scope editor. Review and save the revision to approve it.`, "info");
  }

  async function loadCandidates() {
    if (!state.projectId) return;
    const projectId = state.projectId;
    const request = ++state.candidatesRequest;
    const params = new URLSearchParams({ q: state.candidatesQuery, offset: state.candidatesOffset, limit: 10 });
    for (const [key, value] of Object.entries(state.candidateFilters)) if (value) params.set(key, value);
    state.candidatesLoading = true;
    $("#candidates-error").textContent = "";
    renderCandidates();
    try {
      const value = await api(`/api/projects/${encodeURIComponent(projectId)}/discovery/candidates?${params}`);
      if (request !== state.candidatesRequest || projectId !== state.projectId) return;
      state.candidates = value;
      state.candidatesOffset = value.offset;
    } catch (error) {
      if (request !== state.candidatesRequest || projectId !== state.projectId) return;
      state.candidates = null;
      $("#candidates-error").textContent = error.message;
    } finally {
      if (request === state.candidatesRequest && projectId === state.projectId) {
        state.candidatesLoading = false;
        renderCandidates();
        renderProviderCatalog();
      }
    }
  }

  function renderProviderCatalog() {
    const node = $("#provider-catalog");
    if (!node) return;
    const providers = state.providers || {};
    const parts = [];
    for (const [name, provider] of Object.entries(providers)) {
      if (!provider) continue;
      const stateLabel = provider.configured ? "configured" : "not configured";
      const mode = provider.mode ? ` (${provider.mode})` : "";
      parts.push(`${name.replaceAll("_", " ")}: ${stateLabel}${mode}`);
    }
    node.textContent = parts.length ? `Provider integration: ${parts.join(" · ")}` : "";
  }

  function renderCandidates() {
    const node = $("#candidates-inventory");
    clear(node);
    const data = state.candidates;
    if (!state.projectId) node.appendChild(el("p", "Select a project.", "empty"));
    else if (state.candidatesLoading) node.appendChild(el("p", "Loading candidates…", "empty"));
    else if (!data?.items?.length) {
      node.appendChild(el("p", "No candidates match these filters yet. Run Asset Discovery from Scans using this project's Assets.", "empty"));
    } else {
      node.appendChild(table(["Host", "Sources", "DNS", "IP match", "Scope", "Confidence / interest", "Last seen", "Details"], data.items, (row, column) => {
        if (column === "Host") return row.hostname;
        if (column === "Sources") return (row.sources || []).join(", ");
        if (column === "DNS") return row.dns_status;
        if (column === "IP match") return row.ip_match;
        if (column === "Scope") return row.current_scope_status === row.scope_status_at_check
          ? row.current_scope_status
          : `${row.current_scope_status} (checked as ${row.scope_status_at_check})`;
        if (column === "Confidence / interest") return `${row.confidence || "unknown"} / ${row.interest || "unknown"}`;
        if (column === "Last seen") return row.last_seen;
        const button = el("button", "Details", "link");
        button.type = "button";
        button.addEventListener("click", () => openCandidateDetail(row.id));
        return button;
      }));
    }
    const total = data?.total || 0;
    const disabled = !state.projectId || !data || state.candidatesLoading;
    $("#candidates-previous").disabled = disabled || state.candidatesOffset === 0;
    $("#candidates-next").disabled = disabled || state.candidatesOffset + 10 >= total;
    $("#candidates-page-status").textContent = state.candidatesLoading ? "Loading…" : total
      ? `${state.candidatesOffset + 1}–${Math.min(state.candidatesOffset + 10, total)} of ${total}` : "0 candidates";
    for (const format of ["json", "csv"]) $("#candidates-export-" + format).disabled = !state.projectId || total === 0;
  }

  async function openCandidateDetail(candidateId) {
    if (!state.projectId) return;
    const projectId = state.projectId;
    const request = ++state.candidateDetailRequest;
    $("#candidate-add-scope").disabled = true;
    $("#candidate-add-scope").dataset.host = "";
    $("#candidate-detail-error").textContent = "";
    $("#candidate-detail-content").replaceChildren(el("p", "Loading candidate details…", "empty"));
    $("#candidate-detail-dialog").dataset.projectId = projectId;
    $("#candidate-detail-dialog").showModal();
    try {
      const value = await api(`/api/projects/${encodeURIComponent(projectId)}/discovery/candidates/${encodeURIComponent(candidateId)}`);
      if (projectId !== state.projectId || request !== state.candidateDetailRequest || !$("#candidate-detail-dialog").open) return;
      state.candidateDetail = value.candidate;
      renderCandidateDetail(value.candidate);
    } catch (error) {
      if (projectId === state.projectId && request === state.candidateDetailRequest) $("#candidate-detail-error").textContent = error.message;
    }
  }

  function renderCandidateDetail(candidate) {
    const content = $("#candidate-detail-content");
    clear(content);
    $("#candidate-detail-title").textContent = candidate.hostname || "Candidate";
    const summary = el("div", null, "details-grid");
    const fields = {
      "DNS status": candidate.dns_status,
      "Source IP match": candidate.ip_match,
      "Scope at check": candidate.scope_status_at_check,
      "Current Scope": candidate.current_scope_status,
      "Addresses": (candidate.addresses || []).join(", ") || "none",
      "Sources": (candidate.sources || []).join(", "),
      "First seen": candidate.first_seen,
      "Last checked": candidate.last_checked_at || "not checked",
    };
    for (const [label, value] of Object.entries(fields)) {
      summary.appendChild(el("span", label, "muted"));
      summary.appendChild(el("strong", value || "unknown"));
    }
    content.appendChild(summary);
    const classification = candidate.classification;
    if (classification) {
      content.appendChild(el("h3", "Classification"));
      content.appendChild(el("p", `Confidence ${classification.confidence} · interest ${classification.interest} · groups ${(classification.groups || []).join(", ")} · categories ${(classification.categories || []).join(", ")}`));
      const reasons = (classification.reasons || []).map((reason) => `${reason.claim}: ${reason.basis}`);
      if (reasons.length) content.appendChild(el("ul", null, "details-list")).append(...reasons.map((reason) => el("li", reason)));
    }
    if (candidate.enrichment) {
      content.appendChild(el("h3", "Latest enrichment"));
      content.appendChild(el("p", `Saved ${candidate.enrichment.created_at} · format ${candidate.enrichment.format_version}`));
    }
    content.appendChild(el("h3", "Evidence history"));
    const evidence = candidate.evidence || [];
    if (!evidence.length) content.appendChild(el("p", "No evidence stored.", "empty"));
    for (const item of evidence) {
      const box = el("article", null, "evidence-row");
      box.appendChild(el("strong", `${item.source} · ${item.data_type} · ${item.observed_at}`));
      box.appendChild(el("p", `${item.dns_status || "no DNS status"} · IP match ${item.ip_match || "unknown"} · source IP ${item.source_ip || "n/a"}${item.reason ? ` · ${item.reason}` : ""}${item.error ? ` · ${item.error}` : ""}`, "muted"));
      if (item.details && Object.keys(item.details).length) {
        const pre = el("pre", JSON.stringify(item.details, null, 2), "details-json");
        const raw = el("details");
        append(raw, el("summary", "Raw evidence"), pre);
        box.appendChild(raw);
      }
      content.appendChild(box);
    }
    const add = $("#candidate-add-scope");
    add.disabled = state.me?.role === "viewer" || candidate.current_scope_status === "allowed";
    add.title = add.disabled ? "Already in Scope or Analyst permission required" : "Add this name to the Scope editor without saving";
    add.dataset.host = candidate.hostname || "";
  }

  async function openAssetDetail(assetId) {
    if (!state.projectId) return;
    const projectId = state.projectId;
    const request = ++state.assetDetailRequest;
    $("#asset-detail-error").textContent = "";
    $("#asset-detail-content").replaceChildren(el("p", "Loading asset details…", "empty"));
    $("#asset-detail-dialog").showModal();
    try {
      const value = await api(`/api/projects/${encodeURIComponent(projectId)}/assets/${encodeURIComponent(assetId)}`);
      if (projectId !== state.projectId || request !== state.assetDetailRequest || !$("#asset-detail-dialog").open) return;
      renderAssetDetail(value.asset);
    } catch (error) {
      if (projectId === state.projectId && request === state.assetDetailRequest) $("#asset-detail-error").textContent = error.message;
    }
  }

  function renderAssetDetail(asset) {
    const content = $("#asset-detail-content");
    clear(content);
    $("#asset-detail-title").textContent = asset.value || "Asset details";
    content.appendChild(el("p", `${asset.kind} · first seen ${asset.first_seen} · last seen ${asset.last_seen}`, "muted"));
    const addresses = asset.addresses || asset.enrichment?.data?.dns?.addresses || asset.candidate?.addresses || [];
    if (addresses.length) content.appendChild(el("p", `IP addresses: ${addresses.join(", ")}`));
    if (asset.sources?.length) content.appendChild(el("p", `Sources: ${asset.sources.join(", ")}`, "muted"));
    const classification = asset.classification;
    if (classification) {
      content.appendChild(el("h3", "Classification"));
      content.appendChild(el("p", `Confidence ${classification.confidence} · interest ${classification.interest}`));
      content.appendChild(el("p", `Groups: ${(classification.groups || []).join(", ") || "unknown"}`));
      content.appendChild(el("p", `Categories: ${(classification.categories || []).join(", ") || "none"}`));
      const reasons = classification.reasons || [];
      if (reasons.length) content.appendChild(el("ul", null, "details-list")).append(...reasons.map((reason) => el("li", `${reason.claim}: ${reason.basis}`)));
      const hints = classification.surface_hints || [];
      if (hints.length) content.appendChild(el("p", `Surface hints: ${hints.map((hint) => hint.name).join(", ")}`));
    }
    const technologies = asset.technologies || [];
    if (technologies.length) content.appendChild(el("h3", "Detected technologies"));
    for (const tech of technologies) {
      content.appendChild(el("p", `${tech.name}${tech.versions?.length ? " · " + tech.versions.join(", ") : tech.version ? " · " + tech.version : ""}`));
      const evidence = tech.evidence || [];
      if (Array.isArray(evidence) && evidence.length) content.appendChild(el("ul", null, "details-list")).append(...evidence.map((item) => el("li", `${item.source}: ${item.evidence}`)));
    }
    if ((asset.dns || []).length) content.appendChild(el("h3", "DNS"));
    if ((asset.dns || []).length) content.appendChild(table(["Source", "Type", "Value", "Observed"], asset.dns || [], (row, column) => column === "Source" ? row.source : column === "Type" ? row.data?.record_type || row.kind : column === "Value" ? row.data?.value || row.data?.name || "" : row.observed_at));
    if ((asset.http || []).length) content.appendChild(el("h3", "HTTP services"));
    if ((asset.http || []).length) content.appendChild(table(["URL", "Status", "Title", "Server"], asset.http || [], (row, column) => {
      const data = row.data || {};
      return column === "URL" ? data.url : column === "Status" ? data.status_code : column === "Title" ? data.title : data.server;
    }));
    if (asset.ports?.confirmed?.length || asset.ports?.passive_reported?.length || asset.services?.length) {
      content.appendChild(el("h3", "Ports"));
      content.appendChild(el("p", `Confirmed: ${(asset.ports?.confirmed || []).length} · passive reported: ${(asset.ports?.passive_reported || []).join(", ") || "none"}`));
    }
    if (asset.ports?.confirmed?.length) content.appendChild(table(["IP address", "Port", "State"], asset.ports.confirmed, (row, column) => column === "IP address" ? row.asset : column === "Port" ? row.data?.port : row.data?.state));
    if (asset.services?.length) content.appendChild(table(["Port", "Service", "Product", "Version"], asset.services, (row, column) => row.data?.[column.toLowerCase()]));
    if (asset.network?.organization || asset.network?.asn || asset.network?.country) {
      content.appendChild(el("h3", "Network"));
      content.appendChild(el("p", `Organization: ${asset.network?.organization || "unknown"} · ASN: ${asset.network?.asn || "unknown"} · country: ${asset.network?.country || "unknown"}`));
    }
    if (!classification && !technologies.length && !asset.http?.length && !asset.dns?.length && !asset.services?.length) {
      content.appendChild(el("p", "No enrichment stored yet. Run Asset Discovery to collect and classify information about this Asset.", "muted"));
    }
    if (asset.candidate) {
      content.appendChild(el("h3", "Provenance"));
      content.appendChild(el("p", `Candidate ${asset.candidate.hostname} · DNS ${asset.candidate.dns_status} · IP match ${asset.candidate.ip_match} · sources ${(asset.candidate.sources || []).join(", ")}`));
    }
  }

  function renderFindings() {
    const summary = $("#findings-summary");
    clear(summary);
    const counts = state.dashboard?.severity_counts || {};
    for (const severity of ["critical", "high", "medium", "low", "info", "unknown"]) {
      summary.appendChild(renderMetric(severity, counts[severity] || 0, severity));
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

  const menuButton = $("#menu-button");
  menuButton.addEventListener("click", () => {
    menuButton.setAttribute("aria-expanded", String(menuButton.getAttribute("aria-expanded") !== "true"));
  });
  $("#sidebar-menu").addEventListener("click", (event) => {
    if (event.target.closest("[data-view-link]") && menuButton.getAttribute("aria-expanded") === "true") {
      menuButton.focus();
      menuButton.setAttribute("aria-expanded", "false");
    }
  });
  $(".sidebar").addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menuButton.getAttribute("aria-expanded") === "true") {
      menuButton.focus();
      menuButton.setAttribute("aria-expanded", "false");
    }
  });

  $("#logout-button").addEventListener("click", async () => {
    menuButton.setAttribute("aria-expanded", "false");
    try { await api("/api/auth/logout", { method: "POST", body: {} }); } catch (_) {}
    state.me = null;
    state.projectId = "";
    state.project = null;
    state.dashboard = null;
    state.scope = null;
    state.scopeHistory = [];
    state.rules = [];
    state.jobs = [];
    $("#scope-note").value = "";
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

  function updateScopeControls() {
    const editable = Boolean(state.scope) && state.me?.role !== "viewer" && !state.scopeSaving;
    for (const id of ["rule-kind", "rule-value", "rule-exclusion", "add-rule-button", "scope-note", "save-approve-scope-button"]) {
      $(`#${id}`).disabled = !editable;
    }
    $("#cancel-scope-button").disabled = !editable || !scopeHasChanges();
    $("#project-select").disabled = state.scopeSaving;
  }

  function updateRecordHint() {
    const hints = {
      exact_domain: ["example.com", "DNS name, for example example.com."],
      ip: ["203.0.113.10", "IPv4 or IPv6 address, for example 203.0.113.10 or 2001:db8::1."],
      cidr: ["203.0.113.0/24", "Network with prefix length, for example 203.0.113.0/24 or 2001:db8::/32."],
    };
    const [placeholder, hint] = hints[$("#rule-kind").value];
    $("#rule-value").placeholder = placeholder;
    $("#rule-value-hint").textContent = hint;
    $("#rule-value").setCustomValidity("");
  }

  function normalizedRecordValue(kind, value) {
    if (kind !== "exact_domain") return value;
    let hostname;
    if (/[/\\:@?#%\s]/u.test(value) || value.startsWith("*.")) {
      throw new Error("Enter a DNS name such as example.com, without a URL or wildcard.");
    }
    try { hostname = new URL(`https://${value}`).hostname.replace(/\.$/, ""); }
    catch { throw new Error("Enter a valid DNS name such as example.com."); }
    const labels = hostname.split(".");
    if (hostname.length > 253 || !labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
      || (hostname !== "localhost" && (labels.length < 2 || /^\d+$/.test(labels.at(-1))))) {
      throw new Error("Enter a complete DNS name such as example.com.");
    }
    return hostname;
  }

  $("#rule-kind").addEventListener("change", updateRecordHint);
  $("#rule-value").addEventListener("input", () => $("#rule-value").setCustomValidity(""));
  $("#scope-search").addEventListener("input", renderScope);
  $("#scope-note").addEventListener("input", updateScopeControls);
  $("#add-rule-button").addEventListener("click", () => {
    if (!state.scope || state.scopeSaving || state.me?.role === "viewer") return;
    const input = $("#rule-value");
    try {
      const value = input.value.trim();
      if (!value) throw new Error("Enter a record value.");
      const rule = {
        kind: $("#rule-kind").value,
        value: normalizedRecordValue($("#rule-kind").value, value),
        exclusion: $("#rule-exclusion").checked,
        verified: true,
      };
      if (state.rules.some((item) => sameRule(item, rule))) throw new Error("This record is already in the list.");
      state.rules.push(rule);
      input.value = "";
      $("#rule-exclusion").checked = false;
      $("#scope-search").value = "";
      $("#scope-error").textContent = "";
      renderScope();
      const scroller = $("#scope-rules .table-wrap");
      if (scroller) scroller.scrollTop = scroller.scrollHeight;
    } catch (error) {
      $("#scope-error").textContent = error.message;
      input.setCustomValidity(error.message);
      input.reportValidity();
    }
  });

  const cancelDialog = $("#cancel-scope-dialog");
  $("#cancel-scope-button").addEventListener("click", () => {
    const { added, removed } = scopeChanges();
    const note = $("#scope-note").value.trim() ? " The revision note will also be discarded." : "";
    $("#cancel-scope-description").textContent =
      `Discard ${added + removed} record changes? This will undo the additions (${added}) and removals (${removed}).${note}`;
    cancelDialog.showModal();
  });
  cancelDialog.addEventListener("close", () => {
    if (cancelDialog.returnValue !== "discard") return;
    applyScope(state.scope);
    $("#scope-note").value = "";
    $("#rule-value").value = "";
    $("#rule-exclusion").checked = false;
    $("#scope-search").value = "";
    $("#scope-error").textContent = "";
    $("#rule-value").setCustomValidity("");
    renderScope();
  });

  async function saveScope() {
    if (!state.scope || state.scopeSaving || !requireProject()) return;
    const projectId = state.projectId;
    const rules = state.rules.map(({ kind, value, exclusion, verified }) => ({ kind, value, exclusion, verified }));
    state.scopeSaving = true;
    renderScope();
    $("#scope-error").textContent = "";
    try {
      const value = await api(`/api/projects/${encodeURIComponent(projectId)}/scope`, {
        method: "PUT",
        body: { rules, expected_version: state.scope.version, note: $("#scope-note").value, approve: true },
      });
      if (state.projectId !== projectId) return;
      applyScope(value.scope);
      $("#scope-note").value = "";
      notice("The records have been successfully added.", "success");
      await loadProjects();
      state.scopeSaving = false;
      await loadScope();
    } catch (error) {
      $("#scope-error").textContent = error.message;
    } finally {
      state.scopeSaving = false;
      renderScope();
    }
  }

  $("#save-approve-scope-button").addEventListener("click", saveScope);
  updateRecordHint();

  const scanModules = [
    { id: "subdomains", title: "Subdomain Enumeration", family: "recon", mode: "Passive Recon", tone: "green",
      tasks: ["subdomains.subfinder", "subdomains.discover", "dns.records", "dns.wordlist"],
      description: "Find subdomains with Subfinder, Certificate Transparency or a DNS wordlist, and query DNS records for names in Scope. Only names with confirmed A/AAAA records are added to Assets. Names without addresses stay in job artifacts. Scope exclusions apply.",
      planned: "Subdomain-only ffuf. Subfinder and dnsmap wordlist discovery are available." },
    { id: "assets", title: "Asset Discovery", family: "recon", mode: "Passive Recon", tone: "yellow",
      tasks: ["reverse.ip"],
      description: "Enrich project Assets using their DNS names and IP addresses, passive reverse-IP sources, DNS verification and local classification.",
      planned: "hakrevdns, theHarvester and WhatWeb. ASN and cloud-storage discovery are planned." },
    { id: "crawling", title: "Web Crawling", family: "recon", mode: "Active Recon", tone: "orange",
      tasks: ["urls.passive", "http.crawl", "paths.discover"],
      description: "Collect URLs from public archives, crawl HTML links, or discover paths using the current bounded Rust modules. Archive collection is passive; crawling and path discovery send requests to approved targets.",
      planned: "gau, waybackurls and Katana, including a future JavaScript-rendering option." },
    { id: "http", title: "HTTP Probing", family: "recon", mode: "Active Recon", tone: "blue",
      tasks: ["http.probe"],
      description: "Check approved domains or URLs for HTTP reachability, status codes, response headers and technology hints. Requests and redirects follow the current scope and network policy.",
      planned: "httpx integration." },
    { id: "ports", title: "Port Scanning", family: "recon", mode: "Active Recon", tone: "purple",
      tasks: ["tcp.connect", "nmap.profile"],
      description: "Scan IP addresses from selected project Assets with native TCP connect or the optional unprivileged Nmap service profile. Choose a port preset or enter ports separated by commas in settings.",
      planned: "Nmap presets for web ports, the 1,000 most common ports, and OS/service information after discovering open ports." },
    { id: "network-vulnerabilities", title: "Network Vulnerability", family: "vulnerability", mode: "Active checks", tone: "pink", tasks: [],
      description: "Network vulnerability integrations are planned. This card will become selectable when an executable task is available.",
      planned: "sqlmap, Nmap vulnerability scripts and Nuclei. The sqlmap placement is retained from the product plan; its target remains a web application." },
    { id: "web-vulnerabilities", title: "WEB Vulnerability", family: "vulnerability", mode: "Active checks", tone: "neutral",
      tasks: ["web.checks"],
      description: "Run the implemented versioned HTTP/TLS checks for HSTS, certificate expiry and Secure cookies. The current checks are native Rust implementations.",
      planned: "Nmap web-vulnerability scripts, Nikto and Nuclei." },
  ];
  const selectedModules = new Set();
  const scanChoices = new Map();
  const scanParams = new Map();
  const submissionKeys = new Map();
  let scanning = false;
  let preparingScans = false;
  const targetSelections = new Map();
  let settingsTargetIds = new Set();
  let targetPickerDraft = new Set();
  let targetPickerRows = [];
  let targetPickerOffset = 0;
  let settingsModule = null;

  function moduleTasks(module) {
    return module.tasks.map((name) => state.taskTypes.find((task) => task.name === name)).filter(Boolean);
  }

  function svgIcon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "icon");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS(svg.namespaceURI, "use");
    use.setAttribute("href", `#icon-${name}`);
    svg.appendChild(use);
    return svg;
  }

  function renderScanModules() {
    for (const module of scanModules) {
      const available = moduleTasks(module).filter((task) => task.available);
      if (available.length && !scanChoices.has(module.id)) {
        const preferred = module.id === "crawling" ? "http.crawl" : module.id === "ports" ? "tcp.connect" : available[0].name;
        scanChoices.set(module.id, new Set([available.find((task) => task.name === preferred)?.name || available[0].name]));
      }
    }
    for (const family of ["recon", "vulnerability"]) {
      const container = $(`#${family}-modules`);
      clear(container);
      for (const module of scanModules.filter((item) => item.family === family)) {
        const available = moduleTasks(module).some((task) => task.available);
        const card = el("article", null, `scan-module scan-tone-${module.tone}`);
        card.classList.toggle("is-selected", selectedModules.has(module.id));
        const tools = el("div", null, "scan-module-tools");
        for (const [icon, action, label] of [["info", "info", "Information"], ["settings", "settings", "Settings"]]) {
          const button = el("button", null, "scan-card-action");
          button.type = "button";
          button.setAttribute("aria-label", `${label} for ${module.title}`);
          button.appendChild(svgIcon(icon));
          button.addEventListener("click", () => openScanDialog(module, action));
          tools.appendChild(button);
        }
        const label = el("label", null, "scan-module-choice");
        const checkbox = el("input");
        checkbox.type = "checkbox";
        checkbox.checked = selectedModules.has(module.id);
        checkbox.disabled = !available || scanning || state.me?.role === "viewer";
        checkbox.setAttribute("aria-label", `Select ${module.title}`);
        const title = el("span", module.title.replace(" ", "\n"), "scan-module-title");
        const mode = el("span", available ? (module.id === "assets" ? (state.discoveryHttpEnrichment ? "DNS + Active HTTP" : "Passive sources + DNS") : module.mode) : "Not available yet", "scan-module-mode");
        append(label, checkbox, title, mode);
        checkbox.addEventListener("change", () => {
          if (checkbox.checked) selectedModules.add(module.id);
          else selectedModules.delete(module.id);
          card.classList.toggle("is-selected", checkbox.checked);
          updateScanLaunch();
        });
        append(card, tools, label);
        container.appendChild(card);
      }
    }
    updateScanLaunch();
  }

  function updateScanLaunch() {
    const ready = state.scope?.status === "approved";
    const titles = scanModules.filter((module) => selectedModules.has(module.id)).map((module) => module.title);
    $("#start-scanning-button").disabled = scanning || preparingScans || !state.projectId || !selectedModules.size || state.me?.role === "viewer";
    $("#start-scanning-button").textContent = scanning ? "Submitting…" : "Start scanning";
    $("#scan-selection-status").textContent = !state.projectId ? "Select a project to start scanning."
      : !state.scope ? "Loading project scope…"
      : !ready ? "Approve the project scope before starting."
      : titles.length ? `Selected: ${titles.join(", ")}` : "Select one or more techniques.";
  }

  const scanFieldLabels = {
    domains: "Domains", targets: "Targets", domain: "Domain", ips: "IP addresses",
    sources: "Sources", resolve: "Resolve IP addresses", providers: "Providers",
    record_types: "DNS record types", wordlist: "Wordlist", concurrency: "Parallel workers", words: "Wordlist", mode: "Scan mode", seeds: "Starting URLs",
    base_urls: "Base URLs", ports: "TCP ports", max_pages: "Maximum pages",
    max_depth: "Maximum depth", proxy_profile: "SOCKS5 profile", cookie_names: "Session cookie names", limit: "Maximum URLs",
  };

  const scanTargetFields = new Set(["domains", "domain", "targets", "ips", "seeds", "base_urls"]);

  function scopeScanDomains() {
    const rules = state.scope?.rules || [];
    return [...new Set(rules.filter((rule) => !rule.exclusion && ["exact_domain", "subdomain_tree"].includes(rule.kind)
      && !rules.some((excluded) => excluded.exclusion && (excluded.kind === "exact_domain" ? excluded.value === rule.value
        : excluded.kind === "subdomain_tree" && (rule.value === excluded.value || rule.value.endsWith(`.${excluded.value}`)))))
      .map((rule) => rule.value))];
  }

  function hiddenScanField(task, key) {
    return scanTargetFields.has(key) || (task.name === "http.probe" && key === "mode") || (task.name === "subdomains.subfinder" && ["sources", "resolve"].includes(key))
      || (task.name === "subdomains.discover" && key === "providers")
      || (task.name === "reverse.ip" && key === "providers")
      || (task.name === "dns.wordlist" && key === "words");
  }

  function defaultScanParams(task) {
    const params = { ...(scanParams.get(task.name) || {}) };
    const domains = scopeScanDomains();
    if (task.name === "reverse.ip" && !params.sources) params.sources = ["ptr", "shodan_internetdb"];
    if (scanModules.find((module) => module.id === "subdomains").tasks.includes(task.name)) {
      for (const key of Object.keys(task.params_schema.properties || {})) {
        if (key === "domain") params.domain = domains[0] || "";
        else if (["domains", "targets"].includes(key)) params[key] = domains;
      }
    }
    return params;
  }

  function savedTargetIds(module) {
    if (!targetSelections.has(module.id)) {
      let ids = [];
      try { ids = JSON.parse(localStorage.getItem(`lastest.targets.${state.projectId}.${module.id}`) || "[]"); } catch (_) {}
      targetSelections.set(module.id, new Set(Array.isArray(ids) ? ids.filter((id) => typeof id === "string") : []));
    }
    return targetSelections.get(module.id);
  }

  async function targetCatalog() {
    const projectId = state.projectId;
    const data = await api(`/api/projects/${encodeURIComponent(projectId)}/assets/targets`);
    if (state.projectId !== projectId) throw new Error("Project changed. Select targets in the current project.");
    state.targetCatalog = data;
    return data;
  }

  function readinessMessage(data) {
    if (data.next === "scope_empty") return "Add DNS names, IP addresses or Networks to project Scope first.";
    if (data.next === "approve_scope") return "Approve the project Scope before starting scans.";
    if (data.next === "enumerate_subdomains") return "Assets are empty and Scope contains DNS names. Run Subdomain Enumeration first to populate Assets.";
    return data.import_error || `Assets are empty. Import ${data.import_count} IP addresses from project Scope? This adds inventory records without scanning the network.`;
  }

  async function ensureAssetReadiness(data) {
    if (data.next === "ready") return true;
    $("#asset-readiness-description").textContent = readinessMessage(data);
    $("#asset-readiness-error").textContent = "";
    const action = $("#asset-readiness-action");
    const importing = data.next === "import_scope";
    action.textContent = importing ? "Import from Scope" : data.next === "enumerate_subdomains" ? "Configure Subdomain Enumeration" : "Open Scope";
    action.disabled = importing && !!data.import_error;
    action.onclick = async () => {
      const projectId = state.projectId;
      if (importing) {
        action.disabled = true;
        try {
          await api(`/api/projects/${encodeURIComponent(projectId)}/assets/import-scope`, { method: "POST", body: { scope_version: data.scope_version } });
          if (state.projectId !== projectId) return;
          $("#asset-readiness-dialog").close();
          await targetCatalog();
          notice("IP addresses imported into Assets. Select hosts in module settings, then start scanning.", "success");
          if (state.view === "assets") await loadDashboard();
        } catch (error) { if (projectId === state.projectId) $("#asset-readiness-error").textContent = error.message; }
        finally { action.disabled = false; }
      } else {
        $("#asset-readiness-dialog").close();
        if (data.next === "enumerate_subdomains") {
          selectedModules.clear(); selectedModules.add("subdomains"); renderScanModules();
          openScanDialog(scanModules.find((module) => module.id === "subdomains"), "settings");
        } else location.hash = "#scope";
      }
    };
    $("#asset-readiness-dialog").showModal();
    return false;
  }

  function updateTargetSummary() {
    const summary = $("#scan-target-summary");
    if (summary) summary.textContent = `${settingsTargetIds.size} ${settingsTargetIds.size === 1 ? "host" : "hosts"} selected`;
  }

  function targetEligible(row, module) {
    return module.id === "http" ? row.urls.length > 0 : module.id === "ports" ? row.ips.length > 0 : true;
  }

  async function openTargetPicker(module) {
    $("#scan-settings-error").textContent = "";
    try {
      const data = await targetCatalog();
      if (settingsModule?.id !== module.id || !$("#scan-module-dialog").open) return;
      if (data.next !== "ready") {
        $("#scan-settings-error").textContent = readinessMessage(data);
        return;
      }
      targetPickerRows = data.items;
      targetPickerDraft = new Set([...settingsTargetIds].filter((id) => targetPickerRows.some((row) => row.id === id && targetEligible(row, module))));
      targetPickerOffset = 0;
      $("#asset-target-search").value = "";
      $("#asset-target-title").textContent = `Select hosts · ${module.title}`;
      $("#asset-target-hint").textContent = module.id === "http" ? "Select hosts with stored URLs. Hosts without URLs need Web Crawling first." : module.id === "ports" ? "The scan checks IP addresses associated with selected Assets." : "Select Assets for this module.";
      renderTargetPicker();
      $("#asset-target-dialog").showModal();
    } catch (error) { $("#scan-settings-error").textContent = error.message; }
  }

  function filteredTargetRows() {
    const query = $("#asset-target-search").value.trim().toLowerCase();
    return targetPickerRows.filter((row) => [row.host || "", ...row.ips].some((value) => value.toLowerCase().includes(query)));
  }

  function renderTargetPicker() {
    const rows = filteredTargetRows();
    targetPickerOffset = Math.min(targetPickerOffset, Math.floor(Math.max(0, rows.length - 1) / 50) * 50);
    $("#asset-target-rows").replaceChildren(table(["Select", "DNS name / IP", "Confidence / interest", "URLs"], rows.slice(targetPickerOffset, targetPickerOffset + 50), (row, column) => {
      if (column === "DNS name / IP") {
        const cell = el("div", row.host || row.ips.join(", "));
        if (row.host && row.ips.length) cell.appendChild(el("div", row.ips.join(", "), "muted"));
        return cell;
      }
      if (column === "Confidence / interest") return `${row.confidence || "unknown"} / ${row.interest || "unknown"}`;
      if (column === "URLs") return row.urls.length;
      const input = el("input"); input.type = "checkbox"; input.checked = targetPickerDraft.has(row.id);
      input.disabled = !targetEligible(row, settingsModule);
      input.setAttribute("aria-label", `Select ${row.host || row.ips.join(", ")}`);
      input.addEventListener("change", () => {
        if (input.checked) targetPickerDraft.add(row.id); else targetPickerDraft.delete(row.id);
        $("#asset-target-count").textContent = `${targetPickerDraft.size} selected · ${rows.length} matching hosts`;
      });
      return input;
    }));
    $("#asset-target-count").textContent = `${targetPickerDraft.size} selected · ${rows.length} matching hosts`;
    $("#asset-target-page").textContent = rows.length ? `${targetPickerOffset + 1}–${Math.min(targetPickerOffset + 50, rows.length)} of ${rows.length}` : "0 hosts";
    $("#asset-target-previous").disabled = targetPickerOffset === 0;
    $("#asset-target-next").disabled = targetPickerOffset + 50 >= rows.length;
  }

  $("#asset-target-search").addEventListener("input", () => { targetPickerOffset = 0; renderTargetPicker(); });
  $("#asset-target-all").addEventListener("click", () => { for (const row of filteredTargetRows()) if (targetEligible(row, settingsModule)) targetPickerDraft.add(row.id); renderTargetPicker(); });
  $("#asset-target-none").addEventListener("click", () => { targetPickerDraft.clear(); renderTargetPicker(); });
  $("#asset-target-save").addEventListener("click", () => { settingsTargetIds = new Set(targetPickerDraft); updateTargetSummary(); $("#asset-target-dialog").close(); });
  $("#asset-target-cancel").addEventListener("click", () => $("#asset-target-dialog").close());
  $("#asset-target-previous").addEventListener("click", () => { targetPickerOffset -= 50; renderTargetPicker(); });
  $("#asset-target-next").addEventListener("click", () => { targetPickerOffset += 50; renderTargetPicker(); });
  $("#asset-readiness-cancel").addEventListener("click", () => $("#asset-readiness-dialog").close());

  function openScanDialog(module, action) {
    const subdomainSettings = module.id === "subdomains" && action === "settings";
    $("#scan-module-dialog").classList.toggle("scan-subdomain-settings", subdomainSettings);
    settingsModule = action === "settings" ? module : null;
    settingsTargetIds = new Set(savedTargetIds(module));
    $("#scan-dialog-title").textContent = `${module.title} · ${action === "settings" ? "Settings" : "Information"}`;
    $("#scan-settings-error").textContent = "";
    const content = $("#scan-dialog-content");
    content.replaceChildren(el("p", module.description, "muted"));
    $("#apply-scan-settings").hidden = action !== "settings";
    if (action === "info") {
      content.appendChild(el("p", `Planned tools · ${module.planned}`, "scan-planned"));
    } else {
      content.appendChild(el("p", module.id === "subdomains" ? "DNS names are taken from the approved Scope of this project."
        : module.id === "assets" ? "Uses all current Assets and their DNS names and IP addresses. Scope controls permissions."
        : "Choose hosts from project Assets. Scope controls permissions.", "muted"));
      if (!["subdomains", "assets"].includes(module.id)) {
        const targets = el("div", null, "scan-target-controls");
        const choose = el("button", "Select hosts"); choose.type = "button";
        choose.disabled = scanning || state.me?.role === "viewer";
        choose.addEventListener("click", () => openTargetPicker(module));
        const summary = el("span", "", "muted"); summary.id = "scan-target-summary";
        append(targets, choose, summary); content.appendChild(targets); updateTargetSummary();
      }
      if (module.id === "assets") {
        const toggle = el("input"); toggle.type = "checkbox"; toggle.id = "discovery-http-setting";
        toggle.checked = state.discoveryHttpEnrichment; toggle.disabled = scanning || state.me?.role === "viewer";
        const label = el("label", null, "checkbox"); append(label, toggle, el("span", "Active HTTP enrichment"));
        content.appendChild(label);
        content.appendChild(el("p", "Disabled by default. Enable to send HTTP requests in addition to passive enrichment and DNS verification.", "muted field-hint"));
      }
      const tasks = moduleTasks(module);
      if (!tasks.length) content.appendChild(el("p", "No implemented tasks are available for this module yet.", "empty"));
      for (const task of tasks) {
        const section = el("fieldset", null, "scan-task-settings");
        const legend = el("legend");
        const choiceLabel = el("label", null, "checkbox");
        const choice = el("input");
        choice.type = "checkbox";
        choice.dataset.scanTask = task.name;
        choice.checked = scanChoices.get(module.id)?.has(task.name) || false;
        choice.disabled = !task.available || scanning || state.me?.role === "viewer";
        append(choiceLabel, choice, el("span", task.title));
        legend.appendChild(choiceLabel);
        section.appendChild(legend);
        if (task.unavailable_reason) section.appendChild(el("p", task.unavailable_reason, "muted"));
        const fields = el("div", null, "scan-task-fields");
        fields.hidden = !choice.checked || !task.available;
        choice.addEventListener("change", () => { fields.hidden = !choice.checked; });
        const params = defaultScanParams(task);
        if (module.id === "subdomains") {
          const targets = scopeScanDomains();
          fields.appendChild(el("p", targets.length ? `${targets.length} DNS names from project Scope: ${targets.join(", ")}` : "Add allowed DNS names to Scope first.", "muted field-hint"));
        }
        if (task.name === "subdomains.discover") fields.appendChild(el("p", "Source: Cert Spotter (Certificate Transparency). Finds names published in TLS certificates, then verifies A/AAAA before adding them to Assets.", "muted field-hint"));
        if (task.name === "dns.records") fields.appendChild(el("p", "Query DNS records for names in project Scope. This does not discover subdomains by guessing names. Leave record types empty to query A, AAAA, CNAME, MX, NS and TXT.", "muted field-hint"));
        for (const [key, property] of Object.entries(task.params_schema.properties || {})) {
          if (hiddenScanField(task, key)) continue;
          const field = el("div", null, "field");
          if (subdomainSettings) field.classList.add(`subdomain-setting-${key}`);
          const id = `scan-setting-${task.name.replaceAll(".", "-")}-${key}`;
          const label = el("label", scanFieldLabels[key] || key);
          label.htmlFor = id;
          let input;
          if (task.name === "reverse.ip" && key === "sources") {
            const choices = el("fieldset", null, "source-choices");
            choices.appendChild(el("legend", "Sources"));
            for (const value of property.items.enum) {
              const option = el("input");
              option.type = "checkbox"; option.dataset.scanParam = key; option.dataset.task = task.name; option.dataset.scanValue = value;
              option.checked = params.sources?.includes(value) || false;
              option.disabled = scanning || state.me?.role === "viewer" || !state.providers[value]?.available;
              const text = value === "ptr" ? "PTR" : value === "censys" ? "Censys" : "Shodan InternetDB";
              const label = el("label", null, "checkbox");
              append(label, option, el("span", option.disabled && !state.providers[value]?.available ? `${text} (not configured)` : text));
              choices.appendChild(label);
            }
            fields.appendChild(choices);
            continue;
          } else if (property.enum) {
            input = el("select");
            for (const option of property.enum) input.appendChild(new Option(option, option));
            input.value = params[key] ?? property.default ?? property.enum[0];
          } else {
            input = el(property.type === "array" && property.items?.type !== "integer" ? "textarea" : "input");
            if (property.type === "boolean") {
              input.type = "checkbox";
              input.checked = params[key] ?? key === "resolve";
            } else {
              if (property.type === "integer") { input.type = "number"; input.min = property.minimum ?? 0; }
              input.value = Array.isArray(params[key]) ? params[key].join(input.tagName === "TEXTAREA" ? "\n" : ", ") : params[key] ?? "";
              if (input.tagName === "TEXTAREA") input.rows = subdomainSettings ? 1 : 2;
              input.placeholder = task.params_schema.required?.includes(key) ? "Required" : "Use task defaults";
            }
          }
          input.id = id;
          input.dataset.scanParam = key;
          input.dataset.task = task.name;
          input.disabled = scanning || state.me?.role === "viewer";
          if (property.type === "boolean") {
            label.textContent = "";
            label.className = "checkbox";
            append(label, input, el("span", scanFieldLabels[key] || key));
            field.appendChild(label);
          } else {
            if (key === "ports") {
              const preset = el("select"); preset.setAttribute("aria-label", `Port preset for ${task.title}`);
              const presets = { common: "22, 80, 443, 445, 3389, 8080, 8443", web: "80, 443, 8000, 8080, 8443, 8888" };
              preset.append(new Option("Common services", "common"), new Option("Web services", "web"), new Option("Custom ports", "custom"));
              if (!input.value) input.value = presets.common;
              preset.value = Object.keys(presets).find((key) => presets[key].replaceAll(" ", "") === input.value.replaceAll(" ", "")) || "custom";
              preset.addEventListener("change", () => { if (presets[preset.value]) input.value = presets[preset.value]; });
              input.addEventListener("input", () => { preset.value = "custom"; });
              preset.disabled = input.disabled;
              append(field, label, preset, input);
            } else append(field, label, input);
          }
          const help = {
            wordlist: "Full built-in dnsmap wordlist: 989 entries.",
            concurrency: "Choose how many DNS lookups run in parallel. Default: 8. Higher values increase DNS traffic.",
            record_types: "A: IPv4 · AAAA: IPv6 · CNAME: aliases · MX: mail servers · NS: name servers · TXT: text records. Selected types are saved in the records artifact; A/AAAA are always checked for Assets.",
          };
          if (help[key] && !(subdomainSettings && key === "record_types")) {
            const hint = el("p", help[key], "muted field-hint");
            hint.id = `${id}-hint`;
            input.setAttribute("aria-describedby", hint.id);
            field.appendChild(hint);
          }
          if (key === "resolve") field.appendChild(el("p", "Check discovered subdomains for A/AAAA records and add resolving names and their IPs to Assets. Names without addresses are recorded in the job artifact. Scope exclusions apply.", "muted field-hint"));
          if (property.type === "array") {
            field.appendChild(el("p", property.items?.enum ? `Options: ${property.items.enum.join(", ")}. One per line or separated by commas.`
              : "One per line or separated by commas.", "muted field-hint"));
          }
          fields.appendChild(field);
        }
        section.appendChild(fields);
        if (!subdomainSettings && Object.keys(task.limits).length) section.appendChild(el("p", `Limits · ${Object.entries(task.limits).map(([key, value]) => `${key.replaceAll("_", " ")} ${value}`).join(" · ")}`, "muted field-hint"));
        content.appendChild(section);
      }
    }
    $("#apply-scan-settings").disabled = scanning || state.me?.role === "viewer" || !moduleTasks(module).some((task) => task.available);
    $("#scan-module-dialog").showModal();
  }

  function readTaskParams(task) {
    const params = {};
    for (const input of $$("#scan-dialog-content [data-scan-param]").filter((node) => node.dataset.task === task.name)) {
      const key = input.dataset.scanParam;
      const schema = task.params_schema.properties[key];
      if (input.dataset.scanValue) {
        params[key] = $$("#scan-dialog-content [data-scan-value]").filter((node) => node.dataset.task === task.name && node.dataset.scanParam === key && node.checked).map((node) => node.dataset.scanValue);
        if (!params[key].length) throw new Error("Select at least one Discovery source.");
        continue;
      }
      if (schema.type === "boolean") { params[key] = input.checked; continue; }
      if (!input.value.trim()) {
        if (task.params_schema.required?.includes(key)) throw new Error(`${scanFieldLabels[key] || key} is required.`);
        continue;
      }
      if (schema.type === "array") {
        const values = input.value.split(/[,\n]+/).map((value) => value.trim()).filter(Boolean);
        params[key] = schema.items?.type === "integer" ? values.map(Number) : values;
        if (schema.items?.enum && values.some((value) => !schema.items.enum.includes(value))) throw new Error(`Choose valid ${key} from the listed options.`);
        if (schema.items?.type === "integer" && params[key].some((value) => !Number.isInteger(value) || value < 1 || value > 65535)) throw new Error("Enter valid TCP ports from 1 to 65535.");
      } else if (schema.type === "integer") {
        params[key] = Number(input.value);
        if (!Number.isInteger(params[key]) || (schema.enum && !schema.enum.includes(params[key])) || params[key] < (schema.minimum ?? 0) || (schema.maximum && params[key] > schema.maximum)) throw new Error(`Invalid ${scanFieldLabels[key] || key}.`);
      } else params[key] = input.value.trim();
    }
    return params;
  }

  $("#close-scan-dialog").addEventListener("click", () => $("#scan-module-dialog").close());
  $("#cancel-scan-settings").addEventListener("click", () => $("#scan-module-dialog").close());
  $("#scan-settings-form").addEventListener("submit", (event) => {
    event.preventDefault();
    try {
      const choices = new Set();
      const updates = new Map();
      for (const task of moduleTasks(settingsModule).filter((task) => task.available)) {
        const choice = $$("#scan-dialog-content [data-scan-task]").find((node) => node.dataset.scanTask === task.name);
        if (choice.checked) { choices.add(task.name); updates.set(task.name, readTaskParams(task)); }
      }
      if (!choices.size) throw new Error("Select at least one available task.");
      scanChoices.set(settingsModule.id, choices);
      for (const [name, params] of updates) scanParams.set(name, params);
      if (settingsModule.id === "assets") state.discoveryHttpEnrichment = $("#discovery-http-setting").checked;
      if (!["subdomains", "assets"].includes(settingsModule.id)) {
        targetSelections.set(settingsModule.id, new Set(settingsTargetIds));
        try { localStorage.setItem(`lastest.targets.${state.projectId}.${settingsModule.id}`, JSON.stringify([...settingsTargetIds])); } catch (_) {}
      }
      $("#scan-module-dialog").close();
      renderScanModules();
    } catch (error) { $("#scan-settings-error").textContent = error.message; }
  });

  $("#start-scanning-button").addEventListener("click", async () => {
    if (scanning || preparingScans || !requireProject() || state.me?.role === "viewer") return;
    const projectId = state.projectId;
    const tasks = new Map();
    let catalog;
    preparingScans = true;
    updateScanLaunch();
    try {
      catalog = await targetCatalog();
      if (projectId !== state.projectId) return;
      const needsAssets = [...selectedModules].some((id) => id !== "subdomains");
      if (needsAssets && !await ensureAssetReadiness(catalog)) return;
      if (!needsAssets && (state.scope?.status !== "approved" || !scopeScanDomains().length)) {
        $("#scan-error").textContent = "Add and approve DNS names in Scope before Subdomain Enumeration.";
        return;
      }
      for (const module of scanModules.filter((item) => selectedModules.has(item.id))) {
        let assetIds;
        if (module.id !== "subdomains") {
          assetIds = module.id === "assets" ? catalog.items.map((row) => row.id) : [...savedTargetIds(module)];
          const rows = assetIds.map((id) => catalog.items.find((row) => row.id === id));
          if (!assetIds.length || rows.some((row) => !row || !targetEligible(row, module))) {
            openScanDialog(module, "settings");
            $("#scan-settings-error").textContent = module.id === "http" ? "Select hosts with collected URLs. Run Web Crawling first if no URLs are available." : "Select and save hosts from Assets before starting this module.";
            return;
          }
        }
        for (const task of moduleTasks(module).filter((item) => item.available && scanChoices.get(module.id)?.has(item.name))) {
          const params = defaultScanParams(task);
          const runs = task.name === "dns.wordlist" ? scopeScanDomains().map((domain) => ({ ...params, domain })) : [params];
          for (const run of runs) {
            if (module.id === "assets") {
              const chain = { preset: "asset_discovery", asset_ids: assetIds, sources: run.sources, http_enrichment: state.discoveryHttpEnrichment };
              tasks.set(JSON.stringify(chain), { task_type: "asset_discovery", params: chain });
            } else tasks.set(JSON.stringify({ task_type: task.name, params: run, asset_ids: assetIds }), { task_type: task.name, params: run, asset_ids: assetIds });
          }
        }
      }
    } catch (error) { if (projectId === state.projectId) $("#scan-error").textContent = error.message; return; }
    finally { preparingScans = false; updateScanLaunch(); }
    if (!tasks.size) return;
    scanning = true;
    renderScanModules();
    $("#scan-error").textContent = "";
    const submitted = [];
    try {
      for (const { task_type, params, asset_ids } of tasks.values()) {
        const fingerprint = JSON.stringify({ projectId, task_type, params, asset_ids });
        if (!submissionKeys.has(fingerprint)) {
          const bytes = crypto.getRandomValues(new Uint8Array(16));
          submissionKeys.set(fingerprint, Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""));
        }
        const chain = task_type === "asset_discovery";
        await api(`/api/projects/${encodeURIComponent(projectId)}/${chain ? "chains" : "jobs"}`, {
          method: "POST", body: chain ? { ...params, idempotency_key: submissionKeys.get(fingerprint) }
            : { task_type, params, asset_ids, idempotency_key: submissionKeys.get(fingerprint) },
        });
        submitted.push(task_type);
      }
      submissionKeys.clear();
      if (state.projectId === projectId) {
        selectedModules.clear();
        notice(`Submitted ${submitted.length} ${submitted.length === 1 ? "job" : "jobs"} (${[...new Set(submitted)].join(", ")}).`, "success");
      }
    } catch (error) {
      if (state.projectId === projectId) {
        $("#scan-error").textContent = `${submitted.length} jobs submitted. ${error.message} Retry to continue without duplicating submitted jobs.`;
      }
    } finally {
      scanning = false;
      renderScanModules();
      if (state.projectId === projectId) {
        try { await loadJobs(); } catch (error) { notice(error.message, "error"); }
      }
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

  let assetsSearchTimer;
  let candidatesSearchTimer;
  $("#assets-search").addEventListener("input", (event) => {
    state.assetsQuery = event.target.value;
    state.assetsOffset = 0;
    state.assetsRequest++;
    state.assetsLoading = true;
    renderAssets();
    clearTimeout(assetsSearchTimer);
    assetsSearchTimer = setTimeout(loadAssets, 200);
  });
  for (const [id, key] of [["assets-filter-technology", "technology"], ["assets-filter-provider", "provider"], ["assets-filter-category", "category"]]) {
    $(`#${id}`).addEventListener("input", (event) => {
      state.assetFilters[key] = event.target.value.trim();
      state.assetsOffset = 0;
      clearTimeout(assetsSearchTimer);
      assetsSearchTimer = setTimeout(loadAssets, 200);
    });
  }
  $("#candidates-search").addEventListener("input", (event) => {
    state.candidatesQuery = event.target.value;
    state.candidatesOffset = 0;
    state.candidatesRequest++;
    state.candidatesLoading = true;
    renderCandidates();
    clearTimeout(candidatesSearchTimer);
    candidatesSearchTimer = setTimeout(loadCandidates, 200);
  });
  for (const [id, key] of [["candidates-source", "source"], ["candidates-dns", "dns_status"], ["candidates-ip-match", "ip_match"], ["candidates-scope", "scope_status"], ["candidates-confidence", "confidence"], ["candidates-interest", "interest"]]) {
    $(`#${id}`).addEventListener("change", (event) => {
      state.candidateFilters[key] = event.target.value;
      state.candidatesOffset = 0;
      loadCandidates();
    });
  }
  $("#candidates-previous").addEventListener("click", () => { state.candidatesOffset = Math.max(0, state.candidatesOffset - 10); loadCandidates(); });
  $("#candidates-next").addEventListener("click", () => { state.candidatesOffset += 10; loadCandidates(); });
  for (const format of ["json", "csv"]) $("#candidates-export-" + format).addEventListener("click", () => downloadCandidates(format));
  $("#close-candidate-detail").addEventListener("click", () => $("#candidate-detail-dialog").close());
  $("#close-asset-detail").addEventListener("click", () => $("#asset-detail-dialog").close());
  $("#candidate-add-scope").addEventListener("click", addCandidateToScope);
  $("#assets-previous").addEventListener("click", () => { state.assetsOffset = Math.max(0, state.assetsOffset - 10); loadAssets(); });
  $("#assets-next").addEventListener("click", () => { state.assetsOffset += 10; loadAssets(); });
  for (const format of ["txt", "csv"]) $("#assets-export-" + format).addEventListener("click", () => downloadAssets(format));
  $("#cancel-delete-asset").addEventListener("click", () => $("#delete-asset-dialog").close());
  $("#delete-asset-dialog").addEventListener("cancel", (event) => { if (state.assetDeleting) event.preventDefault(); });
  $("#delete-asset-dialog").addEventListener("close", () => { state.deleteAsset = null; });
  $("#delete-asset-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const row = state.deleteAsset;
    if (!row || state.assetDeleting) return;
    state.assetDeleting = true;
    $("#confirm-delete-asset").disabled = true;
    $("#cancel-delete-asset").disabled = true;
    $("#delete-asset-error").textContent = "";
    try {
      await api(`/api/projects/${encodeURIComponent(row.projectId)}/assets/${encodeURIComponent(row.id)}`, { method: "DELETE" });
      $("#delete-asset-dialog").close();
      if (row.projectId === state.projectId) {
        await loadAssets();
        await loadDashboard(false);
      }
      notice(row.kind === "host" ? "Host deleted. IP records are preserved." : "IP address deleted.", "info");
    } catch (error) {
      if ($("#delete-asset-dialog").open) $("#delete-asset-error").textContent = error.message;
      else notice(`Asset deleted, but the view could not be refreshed: ${error.message}`, "error");
    }
    finally {
      state.assetDeleting = false;
      $("#confirm-delete-asset").disabled = false;
      $("#cancel-delete-asset").disabled = false;
      renderAssets();
    }
  });

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
