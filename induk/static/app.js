const state = {
  apiKey: sessionStorage.getItem("muse_api_key") || "",
  nodes: [],
  summary: {},
  selected: new Set(),
  inputMode: "split",
  ws: null,
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const num = (v, d = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};

function headers(extra = {}) {
  return { "X-API-Key": state.apiKey, ...extra };
}

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: headers(opts.headers || {}) });
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
    const sm = (n.telemetry && n.telemetry.smart) || {};
    const vpn = (n.telemetry && n.telemetry.vpn) || {};
    const host = (n.telemetry && n.telemetry.host) || {};
    const bench = n.benchmark || {};
    const pChecked = num(p.checked);
    const pTotal = num(p.total);
    const pct = pTotal > 0 ? Math.min(100, (pChecked / pTotal) * 100) : 0;
    const chk = state.selected.has(n.vps_id) ? "checked" : "";
    const isDrop = sm.health === "DROP";
    const smartCls = isDrop ? "DROP" : "HEALTHY";
    const smartTxt = isDrop ? `DROP (${esc(sm.cause_tag)} ${num(sm.cause_pct)}%)` : esc(sm.health || "-");
    const defW = num(n.default_workers, 4);
    const benchTxt = bench.cpu_cores ? `${num(bench.cpu_cores)}c/${Math.round(num(bench.ram_mb) / 1024)}G · rec ${defW}w` : `rec ${defW}w`;
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
      <td><span class="badge ${esc(smartCls)}">${smartTxt}</span></td>
      <td>
        <button onclick="inspectVps('${esc(n.vps_id)}')">Detail</button>
        <button onclick="delVps('${esc(n.vps_id)}')">Hapus</button>
      </td>
    </tr>`;
  }).join("");

  document.querySelectorAll(".row-chk").forEach((el) => {
    el.onchange = () => {
      if (el.checked) state.selected.add(el.dataset.id);
      else state.selected.delete(el.dataset.id);
      renderPerVpsInputs();
    };
  });

  const sel = $("inspect-vps-select");
  const prev = sel.value;
  const optIds = state.nodes.map((n) => n.vps_id);
  if (sel.dataset.ids !== optIds.join(",")) {
    sel.dataset.ids = optIds.join(",");
    sel.innerHTML = optIds.map((id) => `<option value="${esc(id)}">${esc(id)}</option>`).join("");
    if (prev && optIds.includes(prev)) sel.value = prev;
  }
  renderSmartPanel();
  renderPerVpsInputs();
}

function renderSmartPanel() {
  const vid = $("inspect-vps-select").value;
  const node = state.nodes.find((n) => n.vps_id === vid);
  if (!node) {
    $("smart-panel").textContent = "Belum ada VPS terdaftar.";
    $("live-logs").textContent = "";
    return;
  }
  const t = node.telemetry || {};
  const sm = t.smart || {};
  const vpn = t.vpn || {};
  const p = t.progress || {};
  const heal = sm.last_heal ? `${sm.last_heal.action} (${sm.last_heal.cause})` : "Belum ada";
  const vpnLine = vpn.mode === "ufasproxy"
    ? `ufasproxy · ${num(vpn.proxy_live)} proxy live`
    : `Score ${num(vpn.node_score)} · WAF ${num(vpn.consec_waf_rate)}/${num(vpn.waf_threshold)} · Rotasi ${num(vpn.rotations)}x · Cooldown ${num(vpn.ovpn_cooldown_count)}/${num(vpn.ovpn_total)}`;
  $("smart-panel").innerHTML = `
    <div><span class="muted">Speed Cur / Peak</span><div><strong>${num(sm.cur_rate)}/s</strong> vs ${num(sm.peak_rate)}/s (session ${num(sm.session_peak)}/s)</div></div>
    <div><span class="muted">AIMD Workers &amp; Bottleneck</span><div><strong>${esc(sm.smart_note || "-")}</strong> · ${esc(sm.cause_tag || "-")} (${num(sm.cause_pct)}%)</div></div>
    <div><span class="muted">Auto-Heal / Scale Terakhir</span><div>${esc(heal)}</div></div>
    <div><span class="muted">VPN / Proxy Intelligence</span><div>${esc(vpnLine)}</div></div>
    <div><span class="muted">Tiers &amp; Peak</span><div>M:${num(p.rank_mythic)} L:${num(p.rank_legend)} E:${num(p.rank_epic)} · Peak ${num(p.peak_skins)} skins / Lv ${num(p.peak_lvl)}</div></div>
  `;
  const logBox = $("live-logs");
  const atBottom = (logBox.scrollHeight - logBox.scrollTop - logBox.clientHeight) < 24;
  logBox.textContent = (t.log_tail || []).join("\n");
  if (atBottom) logBox.scrollTop = logBox.scrollHeight;
}

function renderPerVpsInputs() {
  const box = $("per-vps-box");
  if (state.inputMode !== "per_vps") return;
  const ids = checkedIds();
  const sig = ids.join(",");
  if (box.dataset.ids === sig) return;
  const saved = {};
  box.querySelectorAll(".per-vps-txt").forEach((el) => { saved[el.dataset.id] = el.value; });
  box.dataset.ids = sig;
  box.innerHTML = ids.length
    ? ids.map((id) => `<div><div class="muted">${esc(id)}</div><textarea class="per-vps-txt" data-id="${esc(id)}" rows="2" placeholder="Combo khusus ${esc(id)}"></textarea></div>`).join("")
    : `<div class="muted">Centang minimal 1 VPS di tabel atas.</div>`;
  box.querySelectorAll(".per-vps-txt").forEach((el) => { if (saved[el.dataset.id]) el.value = saved[el.dataset.id]; });
}

window.inspectVps = (vid) => { $("inspect-vps-select").value = vid; renderSmartPanel(); };
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
    const res = await api("/api/v1/commands/bulk", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ vps_ids, type, payload: {} }) });
    $("sys-msg").textContent = `Command ${type} dikirim ke ${res.queued.length} VPS.`;
  } catch (e) { alert(e.message); }
};

window.distributeVpn = async () => {
  const vps_ids = checkedIds();
  if (!vps_ids.length) return alert("Centang minimal 1 VPS.");
  try {
    const res = await api("/api/v1/vpn/distribute", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ vps_ids, sync_now: true }) });
    $("sys-msg").textContent = `VPN distributed: ${JSON.stringify(res.distributed)}`;
  } catch (e) { alert(e.message); }
};

async function loadVps() {
  const data = await api("/api/v1/vps");
  state.nodes = data.nodes || [];
  state.summary = data.summary || {};
  renderAll();
  try {
    const vp = await api("/api/v1/vpn/pool");
    $("vpn-pool-info").textContent = `Stok VPN Lokal: ${vp.total} .ovpn (${Object.entries(vp.folders || {}).map(([k, v]) => `${k}: ${v.count}`).join(", ") || "kosong - pakai gateway token.env"})`;
  } catch (_) {}
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
    $("ws-label").textContent = "Reconnecting...";
    if (state.apiKey) setTimeout(() => { if (state.ws === ws) connectWs(); }, 3000);
  };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "snapshot") { state.nodes = msg.nodes || []; state.summary = msg.summary || {}; renderAll(); }
    else if (msg.type === "provision_log") { $("prov-log").textContent += msg.line + "\n"; $("prov-log").scrollTop = $("prov-log").scrollHeight; }
  };
}

$("api-key-input").value = state.apiKey;
$("connect-btn").onclick = async () => {
  try {
    state.apiKey = $("api-key-input").value.trim();
    sessionStorage.setItem("muse_api_key", state.apiKey);
    await loadVps();
    await connectWs();
  } catch (e) { $("sys-msg").textContent = `Error: ${e.message}`; }
};
$("chk-all").onchange = (e) => {
  state.nodes.forEach((n) => (e.target.checked ? state.selected.add(n.vps_id) : state.selected.delete(n.vps_id)));
  renderAll();
};
$("inspect-vps-select").onchange = renderSmartPanel;

$("mode-split-btn").onclick = () => { state.inputMode = "split"; $("split-box").classList.remove("hidden"); $("per-vps-box").classList.add("hidden"); $("mode-split-btn").classList.add("active"); $("mode-11-btn").classList.remove("active"); };
$("mode-11-btn").onclick = () => { state.inputMode = "per_vps"; $("split-box").classList.add("hidden"); $("per-vps-box").classList.remove("hidden"); $("mode-11-btn").classList.add("active"); $("mode-split-btn").classList.remove("active"); renderPerVpsInputs(); };
$("combo-file").onchange = async (e) => { if (e.target.files[0]) $("combo-text").value = await e.target.files[0].text(); };

$("dispatch-btn").onclick = async () => {
  try {
    const vps_ids = checkedIds();
    if (!vps_ids.length) return alert("Centang minimal 1 VPS.");
    const args = ["--vpn-waf-threshold", $("run-waf").value, "--waf-cooldown", $("run-cd").value];
    const gwUrl = $("run-vpn-api-url").value.trim();
    if (gwUrl) args.push("--vpn-api-url", gwUrl);
    if ($("run-two-tab").checked) args.push("--two-tab");
    if ($("run-skip-ovpn").checked) args.push("--skip-ovpn-test");
    const per_vps_combos = {};
    document.querySelectorAll(".per-vps-txt").forEach((el) => { per_vps_combos[el.dataset.id] = el.value; });
    const res = await api("/api/v1/jobs/dispatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        vps_ids,
        mode: state.inputMode,
        split_strategy: $("split-strategy").value,
        combo_text: $("combo-text").value,
        per_vps_combos,
        workers: Number($("run-workers").value || 0),
        distribute_vpn: $("run-dist-vpn").checked,
        args,
      }),
    });
    $("sys-msg").textContent = `Job ${res.job_id} dikirim ke ${res.queued.length} VPS.`;
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
        induk_url: $("prov-induk-url").value.trim(),
        pointer_url: $("prov-ptr-url").value.trim(),
      }),
    });
    if (res.bootstrap_script) $("prov-log").textContent = res.bootstrap_script;
    else $("prov-log").textContent = `Provisioning ${res.vps_id}...\n`;
  } catch (e) { $("prov-log").textContent = `ERROR: ${e.message}`; }
};

$("download-hits-btn").onclick = async () => {
  try {
    const jid = $("res-job-id").value.trim() || "all";
    const txt = await api(`/api/v1/results/${encodeURIComponent(jid)}?hit_type=${$("res-type").value}&dedup=${$("res-dedup").value}&format=txt`);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([txt], { type: "text/plain" }));
    a.download = `hits_${jid}_${$("res-type").value.toLowerCase()}.txt`;
    a.click();
  } catch (e) { alert(e.message); }
};

$("backup-btn").onclick = async () => {
  try {
    const res = await fetch("/api/v1/system/backup", { headers: headers() });
    if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "induk-backup.tar.gz";
    a.click();
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

$("migrate-btn").onclick = async () => {
  try {
    const new_induk_url = $("new-induk-url").value.trim();
    const res = await api("/api/v1/system/migrate-induk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ new_induk_url, vps_ids: checkedIds() }),
    });
    $("sys-msg").textContent = `SET_INDUK dikirim ke ${res.queued.length} VPS -> ${res.new_induk_url}`;
  } catch (e) { alert(e.message); }
};

if (state.apiKey) { loadVps().then(connectWs).catch(() => {}); }
