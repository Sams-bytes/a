// Aegis dashboard - plain JavaScript, no build step.
const $ = (sel, root = document) => root.querySelector(sel);
const api = async (method, path, body) => {
  const res = await fetch(path, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Error ${res.status}`);
  return data;
};
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const scoreColor = (s) => s >= 80 ? "var(--good)" : s >= 60 ? "var(--med)" : s >= 40 ? "var(--high)" : "var(--crit)";
const scoreLabel = (s) => s >= 80 ? "Good" : s >= 60 ? "Moderate risk" : s >= 40 ? "High risk" : "Critical risk";

let domains = [];
let current = null;

// ---------- theme ----------
try { const t = localStorage.getItem("aegis-theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
$("#theme").onclick = () => {
  const dark = getComputedStyle(document.documentElement).getPropertyValue("--bg").trim() === "#0f1218";
  const next = dark ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("aegis-theme", next); } catch {}
};

// ---------- domain list ----------
async function loadDomains() {
  domains = await api("GET", "/api/domains");
  const ul = $("#domain-list");
  ul.innerHTML = domains.map((d) => `
    <li data-d="${esc(d.domain)}" class="${d.domain === current ? "active" : ""}">
      <span class="name">${esc(d.domain)}</span>
      <span class="meta">${d.verified
        ? (d.last_score != null ? `<b style="color:${scoreColor(d.last_score)}">${d.last_score}</b>/100` : "verified")
        : "unverified"}</span>
    </li>`).join("") || `<li class="hint">No domains yet.</li>`;
  ul.querySelectorAll("li[data-d]").forEach((li) => li.onclick = () => select(li.dataset.d));
}

$("#add-form").onsubmit = async (e) => {
  e.preventDefault();
  const input = $("#add-input");
  try {
    const d = await api("POST", "/api/domains", { domain: input.value });
    input.value = "";
    await loadDomains();
    select(d.domain);
  } catch (err) { alert(err.message); }
};

// ---------- detail view ----------
async function select(name) {
  current = name;
  await loadDomains();
  const d = domains.find((x) => x.domain === name);
  if (!d) return;
  const detail = $("#detail");
  detail.innerHTML = "";
  if (!d.verified) return renderUnverified(detail, d);
  renderVerified(detail, d);
}

function renderUnverified(root, d) {
  root.append($("#tpl-unverified").content.cloneNode(true));
  $(".dname", root).textContent = d.domain;
  $(".rname", root).textContent = d.record_name;
  $(".rvalue", root).textContent = d.record_value;
  $(".copy", root).onclick = () => navigator.clipboard?.writeText(d.record_value);
  $(".remove", root).onclick = () => removeDomain(d.domain);
  $(".check", root).onclick = async (e) => {
    e.target.disabled = true;
    const msg = $(".msg", root);
    try {
      const r = await api("POST", `/api/domains/${encodeURIComponent(d.domain)}/verify`);
      if (r.verified) return select(d.domain);
      msg.textContent = "Not found yet. The TXT record isn't visible in DNS yet - wait a few minutes and try again.";
      msg.style.color = "var(--med)";
    } catch (err) { msg.textContent = err.message; msg.style.color = "var(--crit)"; }
    e.target.disabled = false;
  };
}

async function renderVerified(root, d) {
  root.append($("#tpl-verified").content.cloneNode(true));
  $(".dname", root).textContent = d.domain;
  $(".remove", root).onclick = () => removeDomain(d.domain);
  $(".scan", root).onclick = (e) => runScan(d.domain, e.target);
  renderMonitor(root, d);
  await renderHistory(d.domain, true);
}

// ---------- weekly monitoring ----------
const when = (iso) => {
  const days = (new Date(iso) - Date.now()) / 86400000;
  if (days <= 0) return "due now";
  if (days < 1) return `in ${Math.max(1, Math.round(days * 24))} hours`;
  return `in ${Math.round(days)} days (${new Date(iso).toLocaleDateString()})`;
};

function renderMonitor(root, d) {
  const toggle = $(".mon-toggle", root), info = $(".mon-info", root);
  toggle.checked = d.monitor;
  info.textContent = !d.monitor ? "Off: Aegis only scans when you press Run scan."
    : d.next_scan_due ? `Next automatic scan ${when(d.next_scan_due)}. You get an alert if something new opens up.`
    : "First automatic scan within 15 minutes.";
  toggle.onchange = async () => {
    await api("PATCH", `/api/domains/${encodeURIComponent(d.domain)}`, { monitor: toggle.checked });
    select(d.domain);
  };
  $(".run-now", root).onclick = async (e) => {
    e.target.disabled = true;
    $(".scanning").classList.remove("hidden");
    try {
      await api("POST", "/api/monitor/run-now");
      await loadAlerts();
      await select(d.domain);
    } catch (err) { alert(err.message); }
    $(".scanning")?.classList.add("hidden");
    e.target.disabled = false;
  };
}

// ---------- alerts ----------
async function loadAlerts() {
  const alerts = await api("GET", "/api/alerts");
  const unseen = alerts.filter((a) => !a.seen_at);
  const box = $("#alerts");
  if (!unseen.length) { box.innerHTML = ""; return; }
  box.innerHTML = `<h2>🔔 ${unseen.length} new alert${unseen.length > 1 ? "s" : ""}</h2>
    ${unseen.map((a) => `
      <div class="alert ${a.level}" data-d="${esc(a.domain)}" data-scan="${a.scan_id ?? ""}">
        <b>${esc(a.title)}</b>
        <ul>${a.details.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>
        <span class="hint">${new Date(a.created_at).toLocaleString()} · click to open</span>
      </div>`).join("")}`;
  box.querySelectorAll(".alert").forEach((el) => el.onclick = async () => {
    await api("POST", `/api/alerts/seen?domain=${encodeURIComponent(el.dataset.d)}`);
    await select(el.dataset.d);
    if (el.dataset.scan) renderResult(await api("GET", `/api/scans/${el.dataset.scan}`));
    loadAlerts();
  });
}

function renderCves(cves) {
  const row = (c) => `<li>
      <a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.id)}</a>
      <span class="sev ${c.cvss >= 9 ? "critical" : c.cvss >= 7 ? "high" : c.cvss >= 4 ? "medium" : "low"}">CVSS ${c.cvss ?? "?"}</span>
      ${c.kev ? `<span class="kev" title="On CISA's Known Exploited Vulnerabilities list">actively exploited</span>` : ""}
      <div class="hint">${esc(c.summary)}</div></li>`;
  const first = cves.slice(0, 5), rest = cves.slice(5);
  return `<details class="cves" ${cves.length <= 5 ? "open" : ""}>
      <summary>Known vulnerabilities (${cves.length}). Click an ID for NIST's details</summary>
      <ul>${first.map(row).join("")}</ul>
      ${rest.length ? `<details><summary>Show ${rest.length} more</summary><ul>${rest.map(row).join("")}</ul></details>` : ""}
    </details>`;
}

function renderChanges(ch) {
  if (!ch || ch.first_scan) return "";
  const rows = [
    ...ch.new_ports.map((p) => `<li class="bad">New open port <b>${p.port}</b> (${esc(p.service)})</li>`),
    ...ch.new_findings.map((f) => `<li class="${f.severity === "info" ? "" : "bad"}">New finding: ${esc(f.title)}</li>`),
    ...ch.closed_ports.map((p) => `<li class="good">Closed: port <b>${p.port}</b> (${esc(p.service)})</li>`),
    ...ch.fixed_findings.map((f) => `<li class="good">Fixed: ${esc(f.title)}</li>`),
  ];
  const delta = ch.score_after - ch.score_before;
  return `<div class="card changes"><h3>What changed since the previous scan</h3>
    ${rows.length ? `<ul>${rows.join("")}</ul>` : `<p class="hint">Nothing changed. That's what you want to see.</p>`}
    <p>Score ${ch.score_before} → <b>${ch.score_after}</b>${delta ? ` (<span class="${delta < 0 ? "bad" : "good"}">${delta > 0 ? "+" : ""}${delta}</span>)` : ""}</p></div>`;
}

async function runScan(domain, btn) {
  btn.disabled = true;
  $(".scanning").classList.remove("hidden");
  $(".results").innerHTML = "";
  try {
    const scan = await api("POST", `/api/domains/${encodeURIComponent(domain)}/scan`);
    renderResult(scan);
    await loadDomains();
    await renderHistory(domain, false);
  } catch (err) {
    $(".results").innerHTML = `<div class="card" style="color:var(--crit)">${esc(err.message)}</div>`;
  }
  $(".scanning").classList.add("hidden");
  btn.disabled = false;
}

async function renderHistory(domain, showLatest) {
  const scans = await api("GET", `/api/domains/${encodeURIComponent(domain)}/scans`);
  const box = $(".history");
  if (!box) return;
  if (!scans.length) {
    $(".results").innerHTML = `<div class="card hint">No scans yet. Press <b>Run scan</b> to see what the internet can see.</div>`;
    box.innerHTML = "";
    return;
  }
  box.innerHTML = `<h3>Scan history</h3><ul>${scans.map((s) => `
    <li><a data-id="${s.id}">${new Date(s.finished_at).toLocaleString()}</a>
    ${s.source === "scheduled" ? `<span class="tag">automatic</span>` : ""}
    <b style="color:${scoreColor(s.score)}">${s.score}/100</b></li>`).join("")}</ul>`;
  box.querySelectorAll("a[data-id]").forEach((a) => a.onclick = async () => renderResult(await api("GET", `/api/scans/${a.dataset.id}`)));
  if (showLatest) renderResult(await api("GET", `/api/scans/${scans[0].id}`));
}

function renderResult(scan) {
  const r = scan.result;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  r.findings.forEach((f) => counts[f.severity]++);
  const tls = r.tls;
  const tlsText = !tls ? "No HTTPS port open"
    : tls.valid ? `${esc(tls.version)}, certificate by ${esc(tls.issuer)}, expires ${esc(tls.expires)} (${tls.days_left} days)`
    : `Certificate problem: ${esc(tls.error)}`;

  $(".results").innerHTML = `
    <div class="card summary">
      <div class="score">
        <div class="num" style="color:${scoreColor(r.score)}">${r.score}</div>
        <div class="lbl">/100 · ${scoreLabel(r.score)}</div>
      </div>
      <div>
        <div class="counts">${Object.entries(counts).map(([k, v]) =>
          `<div class="count"><b class="sev ${k}">${v}</b><span>${k}</span></div>`).join("")}</div>
        <div class="facts">
          IP addresses: ${r.ips.map(esc).join(", ") || "none"}<br>
          Scan engine: ${esc(r.engine || "built-in (25 TCP ports)")}${(r.engine || "").startsWith("Nmap")
            ? " · top 1,000 TCP ports + high-risk extras" : " · install Nmap for a professional scan"}<br>
          UDP: ${r.udp === "ok" ? "17 important services checked" : esc(r.udp || "not scanned")}<br>
          Open ports: ${r.open_ports.map((p) => `${p.proto === "udp" ? "UDP " : ""}${p.port}`).join(", ") || "none"}<br>
          Software detected: ${(r.software || []).map((s) =>
            `${esc(s.name)} ${esc(s.version)}${s.ports.length ? ` (port ${s.ports.join(", ")})` : ""}`).join(", ") || "none announced"}<br>
          HTTPS: ${tlsText}<br>
          Scanned ${new Date(scan.finished_at).toLocaleString()}${r.duration_s ? ` in ${r.duration_s}s` : ""}
        </div>
      </div>
    </div>
    ${r.error ? `<div class="card" style="color:var(--crit)">${esc(r.error)}</div>` : ""}
    ${renderChanges(r.changes)}
    ${r.local ? `<div class="card local-note"><b>Local scan: you are looking from the inside.</b>
      This shows which programs are running on this computer, not what the internet can reach.
      Your firewall decides that. Open ports here are shown as <i>info</i>, with how serious
      they would be if they were exposed. To see the attacker's view, scan your public domain.</div>` : ""}
    ${r.vulns && r.vulns.live === false ? `<div class="card local-note">
      <b>Live CVE check skipped</b> (no connection to NIST's database). Showing matches from Aegis's
      built-in list of well-known CVEs only. Run the scan again when online for the full picture.</div>` : ""}
    <h3>Findings, worst first</h3>
    ${r.findings.length ? r.findings.map((f) => `
      <div class="finding ${f.severity}">
        <div class="t"><span>${esc(f.title)}</span>
          <span class="sev ${f.severity}">${f.severity}${f.cvss ? ` · CVSS ${f.cvss.toFixed(1)}` : ""}${f.exposed_severity
            ? ` · if exposed: ${f.exposed_severity}, CVSS ${f.exposed_cvss.toFixed(1)}` : ""}</span></div>
        <p>${esc(f.what)}</p>
        <p class="fix">${esc(f.fix)}</p>
        ${f.cves ? renderCves(f.cves) : ""}
        <p class="law">NIS2 ${esc(f.nis2)}${f.port ? ` · port ${f.port}` : ""}</p>
      </div>`).join("") : `<div class="card">No issues found. Nice work.</div>`}
    <h3>Open ports</h3>
    ${r.open_ports.length ? `<table class="ports"><tr><th>Port</th><th>Proto</th><th>Service</th><th>Software / banner</th></tr>
      ${r.open_ports.map((p) => `<tr><td>${p.port}</td><td>${(p.proto || "tcp").toUpperCase()}</td><td>${esc(p.service)}</td>
        <td class="b">${esc(p.banner) || "-"}</td></tr>`).join("")}
    </table>` : `<p class="hint">No common ports are open.</p>`}
    ${(r.uncertain_udp || []).length ? `<p class="hint"><b>Uncertain UDP</b> (no answer, so open <i>or</i> blocked by a firewall;
      UDP can't tell the difference): ${r.uncertain_udp.map((p) => `${p.port} ${esc(p.service)}`).join(", ")}</p>` : ""}`;
}

async function removeDomain(domain) {
  if (!confirm(`Remove ${domain} and all its scans?`)) return;
  await api("DELETE", `/api/domains/${encodeURIComponent(domain)}`);
  current = null;
  location.reload();
}

loadDomains().then(() => { if (domains[0]) select(domains[0].domain); });
loadAlerts();
setInterval(() => loadAlerts().catch(() => {}), 60000); // pick up alerts from automatic scans
