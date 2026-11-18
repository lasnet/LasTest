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
      renderScanModules();
    } catch (error) { notice(error.message, "error"); }
  }

  async function selectProject(id) {
    state.projectId = id;
    selectedModules.clear();
    scanParams.clear();
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
    if (state.view === "users") renderUsers();
  }

  async function refreshCurrent() {
    if (!state.projectId) return;
    try {
      if (["dashboard", "assets", "findings"].includes(state.view)) await loadDashboard();
      if (state.view === "scans") await Promise.all([loadJobs(), loadScope()]);
      if (state.view === "scope") await loadScope();
      if (state.view === "users") await loadAdmin();
    } catch (error) {
      notice(error.message, "error");
    }
  }

  async function loadDashboard() {
    if (!requireProject()) return;
    const projectId = state.projectId;
    const value = await api(`/api/projects/${encodeURIComponent(projectId)}/dashboard`);
    if (projectId !== state.projectId) return;
    state.dashboard = value;
    renderDashboard();
    renderAssets();
    renderFindings();
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
      description: "Find subdomains through passive sources. With Resolve IP addresses enabled, Subfinder results are checked for A/AAAA records before hosts and IPs are added to Assets. DNS validation includes subdomains of the approved seed and respects exclusions. Connection checks use the approved host and IP scope.",
      planned: "Subfinder, subdomain-only ffuf, and an optimized dnsmap wordlist with eight workers." },
    { id: "assets", title: "Asset Discovery", family: "recon", mode: "Passive Recon", tone: "yellow",
      tasks: ["reverse.ip"],
      description: "Discover IP-related assets using PTR and configured passive reverse-IP providers. Explicit approved IP addresses are required.",
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
      description: "Check explicit approved IP addresses with native TCP connect or the optional fixed unprivileged Nmap service profile. Select the ports in settings. Nmap is available when installed and configured.",
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
      if (available.length && !scanChoices.has(module.id)) scanChoices.set(module.id, new Set([available[0].name]));
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
        const mode = el("span", available ? module.mode : "Not available yet", "scan-module-mode");
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
    $("#start-scanning-button").disabled = scanning || !state.projectId || !ready || !selectedModules.size || state.me?.role === "viewer";
    $("#start-scanning-button").textContent = scanning ? "Submitting…" : "Start scanning";
    $("#scan-selection-status").textContent = !state.projectId ? "Select a project to start scanning."
      : !state.scope ? "Loading project scope…"
      : !ready ? "Approve the project scope before starting."
      : titles.length ? `Selected: ${titles.join(", ")}` : "Select one or more techniques.";
  }

  const scanFieldLabels = {
    domains: "Domains", targets: "Targets", domain: "Domain", ips: "IP addresses",
    sources: "Sources", resolve: "Resolve IP addresses", providers: "Providers",
    record_types: "DNS record types", words: "Wordlist", mode: "Scan mode", seeds: "Starting URLs",
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

  function scopeScanIps() {
    const rules = state.scope?.rules || [];
    return [...new Set(rules.filter((rule) => rule.kind === "ip" && !rule.exclusion
      && !rules.some((excluded) => excluded.kind === "ip" && excluded.exclusion && excluded.value === rule.value))
      .map((rule) => rule.value))];
  }

  function hiddenScanField(task, key) {
    return scanTargetFields.has(key) || (task.name === "subdomains.subfinder" && key === "sources");
  }

  function defaultScanParams(task) {
    const params = Object.fromEntries(Object.entries(scanParams.get(task.name) || {}).filter(([key]) => !hiddenScanField(task, key)));
    const domains = scopeScanDomains();
    for (const key of Object.keys(task.params_schema.properties || {})) {
      if (key === "ips") params.ips = scopeScanIps();
      else if (key === "domain") params.domain = domains[0] || "";
      else if (["domains", "targets"].includes(key)) params[key] = domains;
      else if (["seeds", "base_urls"].includes(key)) params[key] = domains.map((domain) => `https://${domain}/`);
    }
    return params;
  }

  function openScanDialog(module, action) {
    settingsModule = action === "settings" ? module : null;
    $("#scan-dialog-title").textContent = `${module.title} · ${action === "settings" ? "Settings" : "Information"}`;
    $("#scan-settings-error").textContent = "";
    const content = $("#scan-dialog-content");
    content.replaceChildren(el("p", module.description, "muted"));
    $("#apply-scan-settings").hidden = action !== "settings";
    if (action === "info") {
      content.appendChild(el("p", `Planned tools · ${module.planned}`, "scan-planned"));
    } else {
      content.appendChild(el("p", "Targets are taken automatically from the approved Scope of this project. Edit Scope to change them.", "muted"));
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
        const ipTask = Object.hasOwn(task.params_schema.properties || {}, "ips");
        const targets = ipTask ? scopeScanIps() : scopeScanDomains();
        fields.appendChild(el("p", targets.length ? `${targets.length} ${ipTask ? "IP addresses" : "DNS names"} from project Scope: ${targets.join(", ")}`
          : ipTask ? "No IP address records in Scope. Add allowed IP address records in Scope to use this task. DNS names alone do not authorize IP scanning."
          : "No allowed DNS names in Scope. Add DNS Name records in Scope to use this task.", "muted field-hint"));
        for (const [key, property] of Object.entries(task.params_schema.properties || {})) {
          if (hiddenScanField(task, key)) continue;
          const field = el("div", null, "field");
          const id = `scan-setting-${task.name.replaceAll(".", "-")}-${key}`;
          const label = el("label", scanFieldLabels[key] || key);
          label.htmlFor = id;
          let input;
          if (property.enum) {
            input = el("select");
            for (const option of property.enum) input.appendChild(new Option(option, option));
            input.value = params[key] ?? property.enum[0];
          } else {
            input = el(property.type === "array" && property.items?.type !== "integer" ? "textarea" : "input");
            if (property.type === "boolean") {
              input.type = "checkbox";
              input.checked = params[key] ?? key === "resolve";
            } else {
              if (property.type === "integer") { input.type = "number"; input.min = property.minimum ?? 0; }
              input.value = Array.isArray(params[key]) ? params[key].join(input.tagName === "TEXTAREA" ? "\n" : ", ") : params[key] ?? "";
              if (input.tagName === "TEXTAREA") input.rows = 2;
              input.placeholder = task.params_schema.required?.includes(key) ? "Required" : "Use task defaults";
            }
          }
          input.id = id;
          input.dataset.scanParam = key;
          input.dataset.task = task.name;
          input.disabled = scanning || state.me?.role === "viewer";
          append(field, label, input);
          if (key === "resolve") field.appendChild(el("p", "Check discovered subdomains for A/AAAA records and add resolving names and their IPs to Assets. Names without addresses are recorded in the job artifact. Scope exclusions apply.", "muted field-hint"));
          if (property.type === "array") {
            field.appendChild(el("p", property.items?.enum ? `Options: ${property.items.enum.join(", ")}. One per line or separated by commas.`
              : "One per line or separated by commas.", "muted field-hint"));
          }
          fields.appendChild(field);
        }
        append(section, fields, el("p", `Limits · ${Object.entries(task.limits).map(([key, value]) => `${key.replaceAll("_", " ")} ${value}`).join(" · ")}`, "muted field-hint"));
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
        if (!Number.isInteger(params[key]) || params[key] < (schema.minimum ?? 0) || (schema.maximum && params[key] > schema.maximum)) throw new Error(`Invalid ${scanFieldLabels[key] || key}.`);
      } else params[key] = input.value.trim();
    }
    return params;
  }

  $("#close-scan-dialog").addEventListener("click", () => $("#scan-module-dialog").close());
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
      $("#scan-module-dialog").close();
      renderScanModules();
    } catch (error) { $("#scan-settings-error").textContent = error.message; }
  });

  $("#start-scanning-button").addEventListener("click", async () => {
    if (scanning || !requireProject() || state.me?.role === "viewer" || state.scope?.status !== "approved") return;
    const projectId = state.projectId;
    const tasks = new Map();
    for (const module of scanModules.filter((item) => selectedModules.has(item.id))) {
      for (const task of moduleTasks(module).filter((item) => item.available && scanChoices.get(module.id)?.has(item.name))) {
        const params = defaultScanParams(task);
        const ipTask = Object.hasOwn(task.params_schema.properties || {}, "ips");
        if (!(ipTask ? scopeScanIps() : scopeScanDomains()).length) {
          openScanDialog(module, "settings");
          $("#scan-settings-error").textContent = `Add allowed ${ipTask ? "IP address" : "DNS Name"} records in project Scope before starting ${task.title}.`;
          return;
        }
        const missing = (task.params_schema.required || []).find((key) => !params[key] || (Array.isArray(params[key]) && !params[key].length));
        if (missing) {
          openScanDialog(module, "settings");
          $("#scan-settings-error").textContent = `Configure ${scanFieldLabels[missing] || missing} before starting.`;
          return;
        }
        const runs = task.name === "dns.wordlist" ? scopeScanDomains().map((domain) => ({ ...params, domain })) : [params];
        for (const run of runs) tasks.set(JSON.stringify({ task_type: task.name, params: run }), { task_type: task.name, params: run });
      }
    }
    if (!tasks.size) return;
    scanning = true;
    renderScanModules();
    $("#scan-error").textContent = "";
    const submitted = [];
    try {
      for (const { task_type, params } of tasks.values()) {
        const fingerprint = JSON.stringify({ projectId, task_type, params });
        if (!submissionKeys.has(fingerprint)) {
          const bytes = crypto.getRandomValues(new Uint8Array(16));
          submissionKeys.set(fingerprint, Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""));
        }
        await api(`/api/projects/${encodeURIComponent(projectId)}/jobs`, {
          method: "POST", body: { task_type, params, idempotency_key: submissionKeys.get(fingerprint) },
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
