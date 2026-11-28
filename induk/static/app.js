const state = {
  uiToken: sessionStorage.getItem("muse_ui_token") || "",
  username: sessionStorage.getItem("muse_ui_user") || "",
  nodes: [],
  jobs: [],
  summary: {},
  selected: new Set(),
  comboFilename: "",
  ws: null,
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (v, d = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};

// Populate worker options: auto + 1..30
(() => {
  const sel = $("run-workers");
  for (let i = 1; i <= 30; i += 1) {
    const opt = document.createElement("option");
    opt.value = String(i);
    opt.textContent = String(i);
    sel.appendChild(opt);
  }
})();

function headers(extra = {}) {
  return { "X-UI-Token": state.uiToken, ...extra };
}

function setAuthUi(loggedIn) {
  $("auth-user").classList.toggle("hidden", loggedIn);
  $("auth-pass").classList.toggle("hidden", loggedIn);
  $("connect-btn").classList.toggle("hidden", loggedIn);
  $("logout-btn").classList.toggle("hidden", !loggedIn);
  $("logout-btn").textContent = state.username ? `Logout (${state.username})` : "Logout";
}

function clearAuth(label = "Login required") {
  state.uiToken = "";
  sessionStorage.removeItem("muse_ui_token");
  if (state.ws) { state.ws.close(); state.ws = null; }
  $("ws-dot").classList.remove("on");
  $("ws-label").textContent = label;
  setAuthUi(false);
}

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: headers(opts.headers || {}) });
  if (res.status === 401) clearAuth("Session expired");
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`${res.status}: ${txt}`);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

function checkedIds() {
  return [...state.selected].filter((id) => state.nodes.some((n) => n.vps_id === id));
}

const _HIDE_LOG_RE = /\b(?:rotat(?:e|ed|ing|i|asi)|openvpn|ovpn|ganti\s+vpn|vpn\b|api\s*slot|lease\b.*ufasproxy|ufasproxy\s+lease|smart\b|sistem\s+pintar|aimd|bottleneck|node\s*score)\b|\b(?:DROP\s+-?\d+%|Scale\s+[+-]\d+)/i;
const _ANSI_RE = /\x1b\[[0-9;]*m/g;

function renderLiveLogs() {
  const ids = checkedIds();
  const hint = $("live-log-hint");
  const logBox = $("live-logs");
  if (!ids.length) {
    hint.textContent = "Centang VPS untuk lihat log";
    logBox.textContent = "";
    return;
  }
  hint.textContent = `${ids.length} VPS tercentang`;
  const lines = [];
  for (const vid of ids) {
    const node = state.nodes.find((n) => n.vps_id === vid);
    const tail = ((node && node.telemetry && node.telemetry.log_tail) || []);
    for (const raw of tail) {
      const clean = String(raw || "").replace(_ANSI_RE, "").trim();
      if (!clean || _HIDE_LOG_RE.test(clean)) continue;
      lines.push(`[${vid}] ${clean}`);
    }
  }
  const atBottom = (logBox.scrollHeight - logBox.scrollTop - logBox.clientHeight) < 24;
  logBox.textContent = lines.slice(-150).join("\n");
  if (atBottom) logBox.scrollTop = logBox.scrollHeight;
}

function renderAll() {
  const s = state.summary || {};
  $("k-proc").textContent = `${num(s.checked).toLocaleString()} / ${num(s.total).toLocaleString()}`;
  $("k-valid").textContent = num(s.valid).toLocaleString();
  $("k-otp").textContent = num(s.otp).toLocaleString();
  $("k-rate").textContent = `${num(s.rate_per_sec).toFixed(1)}/s`;
  $("k-waf").textContent = `${num(s.waf_solved)}/${num(s.waf)}`;
  $("k-vps").textContent = `${num(s.online_nodes)} / ${num(s.total_nodes)}`;
  $("k-wrk").textContent = `${num(s.workers_live)} / ${num(s.workers_total)}`;

  const tb = $("vps-tbody");
  tb.innerHTML = state.nodes.map((n) => {
    const p = (n.telemetry && n.telemetry.progress) || {};
    const vpn = (n.telemetry && n.telemetry.vpn) || {};
    const host = (n.telemetry && n.telemetry.host) || {};
    const bench = n.benchmark || {};
    const pChecked = num(p.checked);
    const pTotal = num(p.total);
    const pct = pTotal > 0 ? Math.min(100, (pChecked / pTotal) * 100) : 0;
    const chk = state.selected.has(n.vps_id) ? "checked" : "";
    const defW = num(n.default_workers, 4);
    const benchTxt = bench.cpu_cores ? `${num(bench.cpu_cores)}c/${Math.round(num(bench.ram_mb) / 1024)}G` : `w${defW}`;
    let vpnTxt = "-";
    if (vpn.mode === "ufasproxy") {
      vpnTxt = `ufasproxy (${num(vpn.proxy_live)} live)`;
    } else if (vpn.ovpn) {
      vpnTxt = `${esc(vpn.provider)}/${esc(vpn.ovpn)} (${esc(vpn.exit_ip || "-")})`;
    }
    return `<tr>
      <td><input type="checkbox" class="row-chk" data-id="${esc(n.vps_id)}" ${chk} /></td>
      <td><strong>${esc(n.vps_id)}</strong><div class="muted">${esc(n.os_info || "linux")} · ${esc(benchTxt)}</div></td>
      <td><span class="badge ${esc(n.effective_state)}">${esc(n.effective_state)}</span><div class="muted">CPU ${num(host.cpu_pct)}% · RAM ${num(host.ram_pct)}%</div></td>
      <td><div class="pbar"><span style="width:${pct.toFixed(1)}%"></span></div>${pChecked}/${pTotal} (${pct.toFixed(1)}%)</td>
      <td>${num(p.rate_per_sec).toFixed(1)}/s<div class="muted">ETA ${num(p.eta_sec)}s</div></td>
      <td><span class="ok">${num(p.valid)}</span> / <span class="warn">${num(p.otp)}</span></td>
      <td>${num(p.waf_solved)}/${num(p.waf)}</td>
      <td>${num(p.workers_live)}/${num(p.workers_total, defW)}</td>
      <td>${vpnTxt}</td>
      <td><button class="del-vps-btn" data-id="${esc(n.vps_id)}">Hapus</button></td>
    </tr>`;
  }).join("");

  document.querySelectorAll(".row-chk").forEach((el) => {
    el.onchange = () => {
      if (el.checked) state.selected.add(el.dataset.id);
      else state.selected.delete(el.dataset.id);
      renderLiveLogs();
      updateOutNote();
    };
  });
  document.querySelectorAll(".del-vps-btn").forEach((el) => {
    el.onclick = () => window.delVps(el.dataset.id);
  });
  renderLiveLogs();
  updateOutNote();
  const chkAll = $("chk-all");
  if (chkAll) {
    const total = state.nodes.length;
    const sel = state.nodes.filter((n) => state.selected.has(n.vps_id)).length;
    chkAll.checked = total > 0 && sel === total;
    chkAll.indeterminate = sel > 0 && sel < total;
  }
}

function updateOutNote() {
  const ids = checkedIds();
  $("out-scope-note").textContent = ids.length
    ? `Target output.zip: ${ids.length} VPS tercentang (${ids.join(", ")}) — semua folder di output/`
    : "Target output.zip: Semua VPS terdaftar — semua folder di output/";
}

function renderJobs() {
  updateOutNote();
}

window.delVps = async (vid) => {
  if (!confirm(`Hapus ${vid}?`)) return;
  try {
    await api(`/api/v1/vps/${encodeURIComponent(vid)}`, { method: "DELETE" });
    state.selected.delete(vid);
    await loadVps();
  } catch (e) { alert(e.message); }
};

window.bulkCmd = async (type) => {
  const vps_ids = checkedIds();
  if (!vps_ids.length) return alert("Centang minimal 1 VPS.");
  try {
    const res = await api("/api/v1/commands/bulk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vps_ids, type, payload: {} }),
    });
    $("sys-msg").textContent = `Command ${type} dikirim ke ${res.queued.length} VPS.`;
  } catch (e) { alert(e.message); }
};

async function loadJobs() {
  try {
    const data = await api("/api/v1/jobs");
    state.jobs = data.jobs || [];
    renderJobs();
  } catch (_) {}
}

async function loadVps() {
  const data = await api("/api/v1/vps");
  state.nodes = data.nodes || [];
  state.summary = data.summary || {};
  renderAll();
  await loadJobs();
}

async function connectWs() {
  if (state.ws) state.ws.close();
  let ticket = "";
  try {
    const tokRes = await api("/api/v1/ui/ws-ticket", { method: "POST" });
    ticket = tokRes.ticket || "";
  } catch (_) {
    return;
  }
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws/ui?ticket=${encodeURIComponent(ticket)}`);
  state.ws = ws;
  ws.onopen = () => { $("ws-dot").classList.add("on"); $("ws-label").textContent = "Live 2-Way"; };
  ws.onclose = () => {
    $("ws-dot").classList.remove("on");
    $("ws-label").textContent = state.uiToken ? "Reconnecting..." : "Disconnected";
    if (state.uiToken) setTimeout(() => { if (state.ws === ws && state.uiToken) connectWs(); }, 3000);
  };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "snapshot") { state.nodes = msg.nodes || []; state.summary = msg.summary || {}; renderAll(); }
    else if (msg.type === "hits_added") { loadJobs(); }
    else if (msg.type === "job_output_ready") {
      if (msg.job_id === "output.zip" && msg.vps_id) $("sys-msg").textContent = `Archive output/ VPS ${msg.vps_id} tersinkron ✓`;
      loadJobs();
    }
    else if (msg.type === "provision_log") { $("prov-log").textContent += msg.line + "\n"; $("prov-log").scrollTop = $("prov-log").scrollHeight; }
  };
}

$("auth-user").value = state.username;
$("auth-form").onsubmit = async (e) => {
  e.preventDefault();
  try {
    const username = $("auth-user").value.trim();
    const password = $("auth-pass").value;
    const res = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
    const data = await res.json();
    state.uiToken = data.token;
    state.username = data.username || username;
    sessionStorage.setItem("muse_ui_token", state.uiToken);
    sessionStorage.setItem("muse_ui_user", state.username);
    $("auth-pass").value = "";
    $("sys-msg").textContent = "";
    setAuthUi(true);
    await loadVps();
    await connectWs();
  } catch (err) { $("sys-msg").textContent = `Login gagal: ${err.message}`; }
};
$("logout-btn").onclick = async () => {
  await fetch("/api/v1/auth/logout", { method: "POST", headers: headers() }).catch(() => {});
  clearAuth("Disconnected");
};

$("chk-all").onchange = (e) => {
  state.nodes.forEach((n) => (e.target.checked ? state.selected.add(n.vps_id) : state.selected.delete(n.vps_id)));
  renderAll();
};

$("combo-file").onchange = async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  state.comboFilename = f.name || "";
  $("combo-fname").textContent = state.comboFilename;
  $("combo-text").value = await f.text();
};
$("combo-text").oninput = () => {
  state.comboFilename = "";
  $("combo-fname").textContent = "";
};

$("dispatch-btn").onclick = async () => {
  try {
    const vps_ids = checkedIds();
    if (!vps_ids.length) return alert("Centang minimal 1 VPS.");
    const workers = $("run-workers").value || "auto";
    const two_tab = $("run-two-tab").value === "y";
    const res = await api("/api/v1/jobs/dispatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vps_ids,
        mode: "split",
        split_strategy: "weighted",
        combo_text: $("combo-text").value,
        workers,
        two_tab,
        filename: state.comboFilename,
        args: [],
      }),
    });
    $("sys-msg").textContent = `Job ${res.job_id} langsung dijalankan di ${res.queued.length} VPS (${workers}w, 2-tab=${two_tab ? "Y" : "N"}).`;
    await loadJobs();
  } catch (e) { alert(e.message); }
};

$("prov-mode").onchange = (e) => $("ssh-fields").classList.toggle("hidden", e.target.value !== "ssh");
$("prov-btn").onclick = async () => {
  try {
    $("prov-log").textContent = "";
    const res = await api("/api/v1/vps/provision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vps_id: $("prov-id").value.trim(),
        name: $("prov-name").value.trim(),
        mode: $("prov-mode").value,
        host: $("prov-host").value.trim(),
        port: Number($("prov-port").value || 22),
        username: $("prov-user").value.trim(),
        password: $("prov-pass").value,
        private_key: $("prov-key").value,
      }),
    });
    if (res.bootstrap_script) $("prov-log").textContent = res.bootstrap_script;
    else $("prov-log").textContent = `Auto-setup client ${res.vps_id} berjalan...\n`;
  } catch (e) { $("prov-log").textContent = `ERROR: ${e.message}`; }
};

$("sync-out-btn").onclick = async () => {
  const btn = $("sync-out-btn");
  btn.disabled = true;
  try {
    const ids = checkedIds();
    const target = ids.length ? ids : state.nodes.map((n) => n.vps_id);
    if (!target.length) return alert("Belum ada VPS terdaftar.");
    const res = await api("/api/v1/commands/bulk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vps_ids: target, type: "COLLECT_OUTPUTS", payload: {} }),
    });
    $("sys-msg").textContent = `Sync folder output/ diminta ke ${res.queued.length} VPS...`;
  } catch (e) { alert(e.message); }
  finally { btn.disabled = false; }
};

$("download-zip-btn").onclick = async () => {
  const btn = $("download-zip-btn");
  btn.disabled = true;
  try {
    const res = await fetch("/api/v1/results/output.zip", {
      method: "POST",
      headers: headers({ "Content-Type": "application/json" }),
      body: JSON.stringify({ vps_ids: checkedIds() }),
    });
    if (res.status === 401) clearAuth("Session expired");
    if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "output.zip";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) { alert(e.message); }
  finally { btn.disabled = false; }
};

$("send-tg-btn").onclick = async () => {
  const btn = $("send-tg-btn");
  btn.disabled = true;
  try {
    const res = await api("/api/v1/results/output-zip/telegram", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vps_ids: checkedIds() }),
    });
    if (!res.ok) throw new Error("Telegram API gagal");
    $("sys-msg").textContent = `output.zip (${res.counts.folders} folder) terkirim ke Telegram ✓`;
  } catch (e) { alert(e.message); }
  finally { btn.disabled = false; }
};

$("backup-btn").onclick = async () => {
  try {
    const res = await fetch("/api/v1/system/backup", { headers: headers() });
    if (res.status === 401) clearAuth("Session expired");
    if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "induk-backup.tar.gz";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) { alert(e.message); }
};

$("restore-btn").onclick = async () => {
  try {
    const f = $("restore-file").files[0];
    if (!f) return alert("Pilih file backup .tar.gz dulu.");
    const fd = new FormData();
    fd.append("bundle", f);
    const res = await api("/api/v1/system/restore", { method: "POST", body: fd });
    $("sys-msg").textContent = `Restore sukses (${res.restored_nodes} VPS).`;
    await loadVps();
  } catch (e) { alert(e.message); }
};

setAuthUi(Boolean(state.uiToken));
if (state.uiToken) { loadVps().then(connectWs).catch(() => {}); }
