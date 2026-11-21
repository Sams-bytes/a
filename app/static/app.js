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
  const all = await api("GET", "/api/domains");
  // Roots first, each followed by its monitored subdomains (indented).
  domains = all.filter((d) => !d.parent).flatMap((root) => [root, ...all.filter((c) => c.parent === root.domain)]);
  const ul = $("#domain-list");
  ul.innerHTML = domains.map((d) => `
    <li data-d="${esc(d.domain)}" class="${d.domain === current ? "active" : ""} ${d.parent ? "child" : ""}">
      <span class="name">${esc(d.domain)}</span>
      <span class="meta">${d.verified
        ? (d.last_score != null ? `<b style="color:${scoreColor(d.last_score)}">${d.last_score}</b>/100` : "verified")
        : "unverified"}</span>
    </li>`).join("") || `<li class="hint">No domains yet.</li>`;
  ul.querySelectorAll("li[data-d]").forEach((li) => li.onclick = () => select(li.dataset.d));
  $("#netmap-btn").classList.toggle("active", current === "__network__");
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
  renderHosting(root, d);
  if (!d.parent && d.domain !== "localhost") renderSubdomains(root, d);
  await renderHistory(d.domain, true);
}

// ---------- hosting: who owns the server? ----------
async function renderHosting(root, d) {
  const box = $(".hosting", root);
  if (d.domain === "localhost") {
    box.innerHTML = `<b>Hosting:</b> this computer → <b>full scan</b> (it's yours).`;
    return;
  }
  if (d.scan_mode === "unknown") {
    box.innerHTML = `<b>Hosting:</b> <span class="hint">checking who owns the server…</span>`;
    try { d = await api("POST", `/api/domains/${encodeURIComponent(d.domain)}/hosting-check`); } catch {}
  }
  const who = d.hosting_provider ? esc(d.hosting_provider) : "no hosting company found (probably your own server)";
  if (d.scan_mode === "full") {
    box.innerHTML = `<b>Hosting:</b> ${who} → <b>full scan</b> (all ports + UDP).
      ${d.hosting === "own" ? `<span class="hint">You confirmed on ${new Date(d.hosting_confirmed_at).toLocaleDateString()}
        that this server is yours alone.</span> <button class="ghost small to-light">Switch to light scan</button>` : ""}`;
  } else {
    box.innerHTML = `<b>Hosting:</b> ${who} → <b>light scan</b>: the website, its certificate, headers and software
      versions, like a browser visit. <b>No port scan</b>, because the server isn't only yours: on shared hosting it
      also runs other customers' sites, and scanning it means scanning the provider.
      <button class="ghost small to-own">This is my own server (VPS / dedicated)</button>`;
  }
  $(".to-own", box)?.addEventListener("click", async () => {
    if (!confirm(`Only confirm this if ${d.domain} runs on a server that is yours alone (a VPS or dedicated server you manage).\n\n` +
      `On shared hosting, a port scan would scan the provider's machine and other customers' sites, which you are not allowed to do.\n\nIs this server yours alone?`)) return;
    await api("PATCH", `/api/domains/${encodeURIComponent(d.domain)}`, { hosting: "own", confirm: true });
    select(d.domain);
  });
  $(".to-light", box)?.addEventListener("click", async () => {
    await api("PATCH", `/api/domains/${encodeURIComponent(d.domain)}`, { hosting: "shared" });
    select(d.domain);
  });
}

// ---------- subdomains ----------
const SUB_STATUS = {
  ok: "",
  no_address: `<span class="hint">no address (only in old certificates)</span>`,
  takeover_risk: `<span class="kev">takeover risk</span>`,
};

async function renderSubdomains(root, d) {
  const box = $(".subs", root);
  box.classList.remove("hidden");
  const draw = (subs, note = "") => {
    box.innerHTML = `<div class="row" style="justify-content:space-between;align-items:center">
        <h3 style="margin:0">Subdomains</h3>
        <button class="ghost small discover">${subs.length ? "Discover again" : "Discover subdomains"}</button></div>
      <p class="hint">Found in public certificate logs, DNS records and by trying ~120 common names.
        Forgotten subdomains are where attackers often get in. ${note}</p>
      ${subs.length ? `<table class="ports"><tr><th>Name</th><th>Address</th><th>Hosted by</th><th>Found via</th><th></th></tr>
        ${subs.map((s) => `<tr>
          <td><b>${esc(s.name)}</b> ${SUB_STATUS[s.status] || ""}
            ${s.status === "takeover_risk" ? `<div class="hint">Points to ${esc(s.cname)}, which no longer exists.
              An attacker could claim it and show their page on your subdomain. Remove this DNS record.</div>` : ""}</td>
          <td class="b">${s.cname ? `→ ${esc(s.cname)}<br>` : ""}${s.ips.map(esc).join("<br>") || "-"}</td>
          <td>${esc(s.provider || "your own?")}</td>
          <td class="hint">${s.sources.map(esc).join(", ")}</td>
          <td>${s.monitored ? `<span class="tag">monitored</span>`
            : s.status === "takeover_risk" ? "" : `<button class="ghost small mon" data-s="${esc(s.name)}">Monitor</button>`}</td>
        </tr>`).join("")}</table>` : ""}`;
    $(".discover", box).onclick = async (e) => {
      e.target.disabled = true;
      e.target.textContent = "Searching… (up to a minute)";
      try {
        const r = await api("POST", `/api/domains/${encodeURIComponent(d.domain)}/discover`);
        const off = Object.entries(r.sources).filter(([k, v]) => ["crt.sh", "certspotter"].includes(k) && !v).map(([k]) => k);
        draw(r.subdomains, (r.new.length ? `<b>${r.new.length} new since last time.</b> ` : "") +
          (off.length ? `(${off.join(", ")} didn't answer this time.)` : "") +
          (r.sources.wildcard_dns ? " This domain uses wildcard DNS; guessed names that only hit the wildcard were ignored." : ""));
      } catch (err) { alert(err.message); draw(subs); }
    };
    box.querySelectorAll(".mon").forEach((b) => b.onclick = async () => {
      try {
        await api("POST", `/api/domains/${encodeURIComponent(d.domain)}/subdomains/${encodeURIComponent(b.dataset.s)}/monitor`);
        await loadDomains();
        draw(await api("GET", `/api/domains/${encodeURIComponent(d.domain)}/subdomains`));
      } catch (err) { alert(err.message); }
    });
  };
  draw(await api("GET", `/api/domains/${encodeURIComponent(d.domain)}/subdomains`));
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

// ---------- live jobs (watch a scan work) ----------
function livePanel(j) {
  return `<div class="card live">
    <div class="live-bar"><div class="live-fill" style="width:${j.percent || 0}%"></div></div>
    <div class="live-phase"><b>${esc(j.phase || "Working…")}</b> · ${j.percent || 0}%</div>
    <div class="live-log">${(j.lines || []).slice(-8).map((l) => `<div>› ${esc(l)}</div>`).join("")}</div>
  </div>`;
}

// Start a background scan and show its live progress in `target` until it finishes.
async function runLive(path, body, target) {
  const { job_id } = await api("POST", path, body);
  target.innerHTML = livePanel({ phase: "Starting…", percent: 0 });
  return await new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        const j = await api("GET", `/api/jobs/${job_id}`);
        target.innerHTML = livePanel(j);
        if (j.state === "done") return resolve(j.result);
        if (j.state === "error") return reject(new Error(j.error || "Scan failed"));
        setTimeout(tick, 800);
      } catch (e) { reject(e); }
    };
    tick();
  });
}

async function runScan(domain, btn) {
  btn.disabled = true;
  try {
    const scan = await runLive(`/api/domains/${encodeURIComponent(domain)}/scan?live=true`, null, $(".results"));
    renderResult(scan);
    await loadDomains();
    await renderHistory(domain, false);
  } catch (err) {
    $(".results").innerHTML = `<div class="card" style="color:var(--crit)">${esc(err.message)}</div>`;
  }
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

// ================= My network map =================
const DEVICE = {
  router: { icon: "📶", label: "Router / gateway" }, computer: { icon: "💻", label: "Computer" },
  phone: { icon: "📱", label: "Phone / tablet" }, printer: { icon: "🖨️", label: "Printer" },
  tv: { icon: "📺", label: "TV / media" }, iot: { icon: "💡", label: "Smart device (IoT)" },
  unknown: { icon: "❓", label: "Unknown device" },
};

async function openNetwork() {
  current = "__network__";
  loadDomains();                       // refresh sidebar active state
  const detail = $("#detail");
  detail.innerHTML = `<div class="card"><h1>My network map</h1>
    <p>See every device on your own network — router, computers, phones, printers, smart gadgets —
    and spot anything that shouldn't be there.</p>
    <p class="legal">Only scan a network that is <b>yours</b> (your home or your office). Scanning
    someone else's network — a café, a hotel, a client — without written permission is a crime,
    exactly like scanning a stranger's server.</p>
    <div class="net-setup hint">Looking for your networks…</div></div>
    <div id="net-view"></div>`;
  try {
    const info = await api("GET", "/api/network/interfaces");
    const box = $(".net-setup");
    if (!info.nmap) { box.innerHTML = `Install <a href="https://nmap.org/download.html" target="_blank" rel="noopener">Nmap</a> first — the network map needs it.`; return; }
    if (!info.networks.length) { box.innerHTML = `No private network found. Connect to Wi-Fi and reopen this page.`; return; }
    box.innerHTML = `
      <label>Network:
        <select class="net-cidr">${info.networks.map((n) =>
          `<option value="${esc(n.cidr)}">${esc(n.cidr)}${n.gateway ? ` (router ${esc(n.gateway)})` : ""}</option>`).join("")}</select>
      </label>
      <label class="switch" style="margin:8px 0"><input type="checkbox" class="net-own"> This network is mine and I'm allowed to scan it</label>
      <label class="switch"><input type="checkbox" class="net-deep" ${info.admin ? "" : "disabled"}>
        Deep scan: open ports + operating system ${info.admin ? "" : "(needs admin — relaunch Aegis as administrator)"}</label>
      <div class="row" style="margin-top:10px">
        <button class="net-scan" disabled>Scan my network</button>
        ${info.admin ? "" : `<span class="hint">Running as admin would add device makers and OS detection.</span>`}
      </div>`;
    const own = $(".net-own"), btn = $(".net-scan");
    own.onchange = () => btn.disabled = !own.checked;
    btn.onclick = () => scanNetwork($(".net-cidr").value, $(".net-deep").checked, btn);
    const first = info.networks.find((n) => n.scanned);
    if (first) { try { drawNetwork(await api("GET", `/api/network/last?cidr=${encodeURIComponent(first.cidr)}`)); } catch {} }
  } catch (err) { $(".net-setup").innerHTML = esc(err.message); }
}

async function scanNetwork(cidr, deep, btn) {
  btn.disabled = true;
  try {
    drawNetwork(await runLive("/api/network/scan", { cidr, confirm: true, deep, live: true }, $("#net-view")));
  } catch (err) {
    $("#net-view").innerHTML = `<div class="card" style="color:var(--crit)">${esc(err.message)}</div>`;
  }
  btn.disabled = false;
}

function drawNetwork(r) {
  const devices = r.devices || [];
  const others = devices.filter((d) => !d.is_gateway);
  const W = 720, H = Math.max(420, 240 + others.length * 18), cx = W / 2, cy = H / 2;
  const R = Math.min(cx, cy) - 70;
  const node = (d, x, y) => {
    const m = DEVICE[d.type] || DEVICE.unknown;
    const name = d.hostname || d.ip;
    return `<g class="dev ${d.is_new ? "new" : ""}" data-ip="${esc(d.ip)}" transform="translate(${x},${y})">
      <circle r="26" class="dev-bg ${d.is_self ? "self" : ""}"/>
      <text class="ico" y="9" text-anchor="middle">${m.icon}</text>
      <text class="lbl" y="44" text-anchor="middle">${esc(name.replace(/\.home$/, ""))}</text>
      ${d.is_new ? `<text class="lbl new" y="58" text-anchor="middle">new!</text>` : ""}</g>`;
  };
  const router = devices.find((d) => d.is_gateway);
  const spokes = others.map((d, i) => {
    const a = (i / others.length) * 2 * Math.PI - Math.PI / 2;
    const x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
    return { d, x, y, line: `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" class="wire"/>` };
  });
  const svg = `<svg viewBox="0 0 ${W} ${H}" class="netmap" role="img" aria-label="network map">
    ${spokes.map((s) => s.line).join("")}
    ${router ? node(router, cx, cy) : `<g transform="translate(${cx},${cy})"><circle r="26" class="dev-bg"/><text class="ico" y="9" text-anchor="middle">🌐</text><text class="lbl" y="44" text-anchor="middle">internet</text></g>`}
    ${spokes.map((s) => node(s.d, s.x, s.y)).join("")}
  </svg>`;

  const newOnes = devices.filter((d) => d.is_new);
  $("#net-view").innerHTML = `
    ${newOnes.length ? `<div class="card local-note" style="border-left-color:var(--crit)">
      <b>⚠ ${newOnes.length} device${newOnes.length > 1 ? "s" : ""} not seen before:</b>
      ${newOnes.map((d) => esc(d.hostname || d.ip)).join(", ")}. If you don't recognise ${newOnes.length > 1 ? "them" : "it"},
      someone may be on your network — change your Wi-Fi password.</div>` : ""}
    <div class="card">
      <div class="facts" style="margin:0 0 8px">${r.network} · ${r.count} devices · ${esc(r.engine || "")}
        ${r.admin ? "" : "· basic scan (run as admin for OS detection)"}</div>
      ${svg}
      <div class="net-detail hint">Click a device to see its details.</div>
    </div>
    <table class="ports"><tr><th>Device</th><th>IP</th><th>Maker</th><th>Type</th><th>Ports</th></tr>
      ${devices.map((d) => `<tr data-ip="${esc(d.ip)}">
        <td><b>${esc((d.hostname || "?").replace(/\.home$/, ""))}</b>${d.is_self ? ` <span class="tag">this PC</span>` : ""}${d.is_new ? ` <span class="kev">new</span>` : ""}</td>
        <td class="b">${esc(d.ip)}</td>
        <td>${esc(d.vendor || (d.randomized_mac ? "hidden (random MAC)" : "—"))}</td>
        <td>${(DEVICE[d.type] || DEVICE.unknown).label}</td>
        <td class="b">${(d.open_ports || []).map((p) => p.port).join(", ") || "—"}</td></tr>`).join("")}
    </table>`;

  const show = (ip) => {
    const d = devices.find((x) => x.ip === ip); if (!d) return;
    const m = DEVICE[d.type] || DEVICE.unknown;
    $(".net-detail").innerHTML = `<b>${m.icon} ${esc(d.hostname || d.ip)}</b> — ${m.label}<br>
      IP ${esc(d.ip)}${d.mac ? ` · MAC ${esc(d.mac)}` : ""}${d.vendor ? ` · ${esc(d.vendor)}` : ""}
      ${d.randomized_mac ? `<br><span class="hint">Uses a random MAC address (a privacy feature of phones), so the maker is hidden.</span>` : ""}
      ${d.os ? `<br>OS guess: ${esc(d.os)}` : ""}
      ${(d.open_ports || []).length ? `<br>Open ports: ${d.open_ports.map((p) => `${p.port} ${esc(p.service || "")}`).join(", ")}` : ""}`;
    document.querySelectorAll(".dev").forEach((g) => g.classList.toggle("sel", g.dataset.ip === ip));
  };
  $("#net-view").querySelectorAll("[data-ip]").forEach((el) => el.onclick = () => show(el.dataset.ip));
}

$("#netmap-btn").onclick = openNetwork;

loadDomains().then(() => { if (domains[0]) select(domains[0].domain); });
loadAlerts();
setInterval(() => loadAlerts().catch(() => {}), 60000); // pick up alerts from automatic scans
