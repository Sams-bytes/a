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
  await renderHistory(d.domain, true);
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
          Open ports: ${r.open_ports.map((p) => p.port).join(", ") || "none"}<br>
          HTTPS: ${tlsText}<br>
          Scanned ${new Date(scan.finished_at).toLocaleString()}${r.duration_s ? ` in ${r.duration_s}s` : ""}
        </div>
      </div>
    </div>
    ${r.error ? `<div class="card" style="color:var(--crit)">${esc(r.error)}</div>` : ""}
    <h3>Findings, worst first</h3>
    ${r.findings.length ? r.findings.map((f) => `
      <div class="finding ${f.severity}">
        <div class="t"><span>${esc(f.title)}</span>
          <span class="sev ${f.severity}">${f.severity}${f.cvss ? ` · CVSS ${f.cvss.toFixed(1)}` : ""}</span></div>
        <p>${esc(f.what)}</p>
        <p class="fix">${esc(f.fix)}</p>
        <p class="law">NIS2 ${esc(f.nis2)}${f.port ? ` · port ${f.port}` : ""}</p>
      </div>`).join("") : `<div class="card">No issues found. Nice work.</div>`}
    <h3>Open ports</h3>
    ${r.open_ports.length ? `<table class="ports"><tr><th>Port</th><th>Service</th><th>Banner</th></tr>
      ${r.open_ports.map((p) => `<tr><td>${p.port}</td><td>${esc(p.service)}</td><td class="b">${esc(p.banner) || "-"}</td></tr>`).join("")}
    </table>` : `<p class="hint">No common ports are open.</p>`}`;
}

async function removeDomain(domain) {
  if (!confirm(`Remove ${domain} and all its scans?`)) return;
  await api("DELETE", `/api/domains/${encodeURIComponent(domain)}`);
  current = null;
  location.reload();
}

loadDomains().then(() => { if (domains[0]) select(domains[0].domain); });
