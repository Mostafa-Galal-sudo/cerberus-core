/* CERBERUS SOC dashboard — vanilla JS, polls the Flask REST API. */
"use strict";

const API = {
  alerts: (status) => `/api/alerts${status ? `?status=${status}` : ""}`,
  alert: (id) => `/api/alerts/${id}`,
  alertStatus: (id) => `/api/alerts/${id}/status`,
  devices: "/api/devices",
  deviceStatus: (id) => `/api/devices/${id}/status`,
  incidents: "/api/incidents",
  timeline: (id) => `/api/incidents/${id}/timeline`,
};

const state = {
  alerts: [],
  devices: [],
  incidents: [],
  selectedAlert: null,
  selectedIncident: null,
};

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

async function api(url, options) {
  const resp = await fetch(url, options);
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(`${resp.status} ${body.error || resp.statusText}`);
  }
  return resp.json();
}

function fmtTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/* ---- rendering ---------------------------------------------------------- */

function renderStats() {
  const today = new Date().toDateString();
  const recent = state.alerts.filter((a) => new Date(a.created_at).toDateString() === today);
  $("stat-alerts").textContent = recent.length;
  $("stat-open").textContent = state.alerts.filter((a) => a.status === "open").length;
  $("stat-devices").textContent = state.devices.length;
  $("stat-isolated").textContent = state.devices.filter((d) => d.status === "isolated").length;
  $("stat-incidents").textContent = state.incidents.length;
}

function renderAlerts() {
  const filter = $("alert-filter").value;
  const rows = filter ? state.alerts.filter((a) => a.status === filter) : state.alerts;
  $("alerts-body").innerHTML = rows.map((a) => `
    <tr data-alert="${a.id}">
      <td>#${a.id}</td>
      <td>${esc(fmtTime(a.created_at))}</td>
      <td>${esc(a.device_id ?? "–")}</td>
      <td>${esc(a.attack_class ?? a.source_label ?? "–")}</td>
      <td>${(a.confidence ?? 0).toFixed(2)}</td>
      <td><span class="status-${esc(a.status)}">${esc(a.status)}</span></td>
    </tr>`).join("");
  $("alerts-empty").hidden = rows.length > 0;
  document.querySelectorAll("#alerts-body tr").forEach((tr) => {
    tr.addEventListener("click", () => selectAlert(Number(tr.dataset.alert)));
  });
}

function renderDevices() {
  $("devices-list").innerHTML = state.devices.map((d) => `
    <li>
      <span>${esc(d.device_id)}</span>
      <span>
        <span class="dev-${esc(d.status)}">${esc(d.status)}</span>
        <button class="btn btn-ghost" data-isolate="${esc(d.device_id)}"
                ${d.status === "isolated" ? "disabled" : ""}>Isolate</button>
      </span>
    </li>`).join("");
  $("devices-empty").hidden = state.devices.length > 0;
  document.querySelectorAll("[data-isolate]").forEach((btn) => {
    btn.addEventListener("click", () => isolateDevice(btn.dataset.isolate));
  });
}

function renderIncidents() {
  $("incidents-list").innerHTML = state.incidents.map((i) => `
    <li data-incident="${i.id}">#${i.id} &mdash; ${esc(i.title)}
      <span class="muted">(${(i.alert_ids || []).length} alerts)</span></li>`).join("");
  $("incidents-empty").hidden = state.incidents.length > 0;
  document.querySelectorAll("[data-incident]").forEach((li) => {
    li.addEventListener("click", () => selectIncident(Number(li.dataset.incident)));
  });
}

function scoreBar(label, value) {
  const pct = Math.round((value ?? 0) * 100);
  return `
    <div class="scorebar">
      <div class="bar-label"><span>${esc(label)}</span><span>${pct}%</span></div>
      <div class="bar-track"><div class="bar-fill ${pct >= 80 ? "high" : ""}" style="width:${pct}%"></div></div>
    </div>`;
}

function renderDetail() {
  const panel = $("alert-detail");
  if (!state.selectedAlert) {
    panel.hidden = true;
    return;
  }
  const a = state.selectedAlert;
  panel.hidden = false;
  $("detail-id").textContent = `#${a.id}`;
  $("detail-summary").innerHTML =
    `${esc(a.device_id ?? "unknown device")} &mdash; ${esc(a.attack_class ?? "unknown class")}` +
    ` (${esc(a.source_label ?? "no label")})`;

  $("detail-scores").innerHTML = [
    scoreBar("Confidence", a.confidence),
    scoreBar("ML anomaly", a.anomaly_score),
    scoreBar("Rules", a.rule_score),
    scoreBar("Fingerprint", a.fingerprint_score),
  ].join("");

  const reasons = a.explanation?.length ? a.explanation : (a.reasons || []);
  $("detail-reasons").innerHTML = reasons.length
    ? reasons.map((r) => `<li>${esc(r)}</li>`).join("")
    : "<li class='muted'>No reason strings recorded.</li>";

  const feats = a.ml_top_features || [];
  $("detail-features").innerHTML = feats.length
    ? feats.map(([name, weight]) =>
        `<li class="${weight >= 0 ? "pos" : "neg"}">${esc(name)}: ${weight >= 0 ? "+" : ""}${Number(weight).toFixed(3)}</li>`).join("")
    : "<li class='muted'>No SHAP attribution stored for this alert.</li>";
}

async function renderTimeline() {
  const box = $("timeline");
  if (!state.selectedIncident) {
    box.hidden = true;
    return;
  }
  const events = await api(API.timeline(state.selectedIncident));
  $("timeline-title").textContent = `Incident #${state.selectedIncident}`;
  $("timeline-events").innerHTML = events.map((e) => `
    <li><span class="ev-time">${esc(fmtTime(e.created_at))}</span>
        <span class="ev-type">${esc(e.event_type)}</span>
        ${esc(e.message)}</li>`).join("");
  box.hidden = false;
}

/* ---- actions ------------------------------------------------------------ */

function selectAlert(id) {
  state.selectedAlert = state.alerts.find((a) => a.id === id) || null;
  renderDetail();
}

async function setAlertStatus(status) {
  if (!state.selectedAlert) return;
  await api(API.alertStatus(state.selectedAlert.id), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  await refresh();
  selectAlert(state.selectedAlert.id);
}

async function isolateDevice(deviceId) {
  if (!window.confirm(`Isolate ${deviceId}? This is a policy-bounded response action.`)) return;
  await api(API.deviceStatus(deviceId), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: "isolated" }),
  });
  await refresh();
}

async function selectIncident(id) {
  state.selectedIncident = id;
  await renderTimeline();
}

/* ---- refresh loop -------------------------------------------------------- */

async function refresh() {
  try {
    const status = $("alert-filter").value;
    const [alerts, devices, incidents] = await Promise.all([
      api(API.alerts(status)),
      api(API.devices),
      api(API.incidents),
    ]);
    state.alerts = alerts.alerts;
    state.devices = devices.devices;
    state.incidents = incidents.incidents;
    $("conn-pill").textContent = "connected";
    $("conn-pill").className = "pill pill-up";
    $("last-updated").textContent = `updated ${fmtTime(new Date().toISOString())}`;
    renderStats();
    renderAlerts();
    renderDevices();
    renderIncidents();
    renderDetail();
  } catch (err) {
    $("conn-pill").textContent = "disconnected";
    $("conn-pill").className = "pill pill-down";
    console.error("refresh failed:", err);
  }
}

/* ---- boot ----------------------------------------------------------------- */

$("refresh-btn").addEventListener("click", refresh);
$("alert-filter").addEventListener("change", refresh);
$("close-detail").addEventListener("click", () => {
  state.selectedAlert = null;
  renderDetail();
});
document.querySelectorAll("#alert-detail [data-status]").forEach((btn) => {
  btn.addEventListener("click", () => setAlertStatus(btn.dataset.status));
});
$("isolate-btn").addEventListener("click", () => {
  const deviceId = state.selectedAlert?.device_id;
  if (deviceId) isolateDevice(deviceId);
});

refresh();
setInterval(refresh, 5000);
