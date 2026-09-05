/* ArkIDS 真实流量监控前端 —— 抓包控制 / 拓扑 / 封包 / 威胁 / AI */
"use strict";

const $ = id => document.getElementById(id);
const els = {
  modeChip: $("modeChip"), threat: $("threat"),
  kPkts: $("kPkts"), kPps: $("kPps"), kFlows: $("kFlows"),
  kDet: $("kDet"), kCrit: $("kCrit"),
  modeLive: $("modeLive"), modePcap: $("modePcap"),
  paneLive: $("paneLive"), panePcap: $("panePcap"),
  iface: $("iface"), btnRefresh: $("btnRefresh"), capFilter: $("capFilter"),
  btnStart: $("btnStart"), btnBrowse: $("btnBrowse"), pcapText: $("pcapText"),
  pcapFile: $("pcapFile"), dispFilter: $("dispFilter"), btnStartPcap: $("btnStartPcap"),
  btnStop: $("btnStop"), autoBlock: $("autoBlock"),
  wsChip: $("wsChip"), btnWsOpen: $("btnWsOpen"), btnSave: $("btnSave"),
  toolsHint: $("toolsHint"),
  net: $("net"), spark: $("spark"), toasts: $("toasts"), netHint: $("netHint"),
  pktSearch: $("pktSearch"), pktBody: $("pktBody"), pktEmpty: $("pktEmpty"),
  pktStat: $("pktStat"), btnPktExport: $("btnPktExport"),
  thLevel: $("thLevel"), thBody: $("thBody"), thEmpty: $("thEmpty"),
  thCnt: $("thCnt"), btnThExport: $("btnThExport"),
  hostsRow: $("hostsRow"), flowBody: $("flowBody"),
  aiList: $("aiList"), llmBadge: $("llmBadge"), aiQ: $("aiQ"),
  btnLLM: $("btnLLM"), aiAns: $("aiAns"),
  fwForm: $("fwForm"), fwSrc: $("fwSrc"), fwAction: $("fwAction"),
  fwProto: $("fwProto"), fwPort: $("fwPort"), fwBody: $("fwBody"),
  btnScript: $("btnScript"), fwScript: $("fwScript"),
};
const zh = { critical: "严重", warning: "警告", info: "提示" };
const kindZh = { tcp_syn_flood: "TCP SYN 洪泛", port_scan: "端口扫描",
  conn_burst: "连接突发", unknown: "其它" };
const fmt = n => Number(n || 0).toLocaleString("zh-CN");
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const timeStr = ts => { const d = new Date(ts * 1000);
  return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"); };

async function api(path, opts) {
  const res = await fetch(path, opts);
  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error(typeof body === "string" ? body : (body.error || res.status));
  return body;
}
const post = (path, obj) => api(path, { method: "POST",
  headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) });

const state = { meta: null, mode: "idle", ifaces: [], lastPktSeq: 0, pktShown: [],
  thSeen: 0, thDismiss: new Set(), netCtx: null, sparkCtx: null, lastSnap: null,
  pcapPath: "", toastStep: 0 };

// ================================================================ 基础工具
function toast(text, cls) {
  const div = document.createElement("div");
  div.className = "toast " + (cls || "");
  div.textContent = text;
  els.toasts.appendChild(div);
  while (els.toasts.childNodes.length > 4) els.toasts.removeChild(els.toasts.firstChild);
  setTimeout(() => div.remove(), 3000);
}
function csvExport(rows, cols, name) {
  const head = cols.map(c => esc(c)).join(",");
  const lines = rows.map(r => cols.map(c => `"${String(r[c] ?? "").replace(/"/g, '""')}"`).join(","));
  const blob = new Blob(["\ufeff" + head + "\n" + lines.join("\n")], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
  URL.revokeObjectURL(a.href);
}

// ================================================================ 数据源
function renderMeta(m) {
  state.meta = m;
  els.modeChip.textContent = m.mode === "live" ? "LIVE 抓包中" :
    m.mode === "pcap" ? "回放: " + (m.source || "").slice(0, 24) :
    m.mode === "error" ? "错误" : "空闲";
  els.modeChip.className = "statechip " + (m.mode || "idle");
  els.btnStop.classList.toggle("hidden", m.mode !== "live" && m.mode !== "pcap");
  els.btnSave.classList.toggle("hidden", !m.saved_path);
  els.btnSave.title = m.saved_path || "";
  els.autoBlock.checked = !!m.auto_block;
  // Wireshark 工具
  const hasT = !!m.tools.tshark, hasW = !!m.tools.wireshark;
  els.wsChip.textContent = hasT ? "✓ tshark " + (m.tools.tshark_version || "").replace(/^.*\s(\d[\w.]*).*$/, "$1")
    : (m.mode === "pcap" ? "tshark ✗ (内置解析器)" : "tshark ✗ 未安装");
  els.wsChip.className = "ws-chip" + (hasT || m.mode === "pcap" ? " ok" : "");
  els.btnWsOpen.disabled = !hasW;
  if (!hasT && !m.saved_path) {
    els.toolsHint.classList.remove("hidden");
    els.toolsHint.className = "hintbox error";
    els.toolsHint.innerHTML = "⚠ 未检测到 <b>Wireshark/tshark</b>：实时抓包需要安装 "
      + "<a href='https://www.wireshark.org/download.html' target='_blank' style='color:#35d0ff'>Wireshark</a>"
      + "(含 tshark 与 Npcap, 并以管理员运行)。你仍可切换到“回放抓包文件”加载真实的 .pcap 文件。";
  } else {
    els.toolsHint.classList.add("hidden");
  }
  if (m.last_error) toast("采集异常: " + m.last_error, "warn");
  state.mode = m.mode;
}

function fillInterfaces(ifaces) {
  els.iface.innerHTML = "";
  if (!ifaces || !ifaces.length) {
    els.iface.innerHTML = "<option value=''>无可用网卡(需 Npcap/管理员)</option>";
    return;
  }
  const pref = ifaces.find(i => !/loopback|virtual|蓝牙/i.test(i.description || "")) || ifaces[0];
  ifaces.forEach(i => {
    const o = document.createElement("option");
    o.value = i.name;
    o.textContent = `${i.name}  (${i.description || "未知接口"})`;
    if (i.name === pref.name) o.selected = true;
    els.iface.appendChild(o);
  });
}

async function refreshMeta() {
  try {
    const m = await api("/api/meta");
    renderMeta(m);
    if (JSON.stringify(m.interfaces) !== JSON.stringify(state.ifaces)) {
      state.ifaces = m.interfaces; fillInterfaces(m.interfaces);
    }
    return m;
  } catch (err) { console.warn(err); return state.meta; }
}

async function doStart() {
  const body = { action: "start-live", interface: els.iface.value,
    filter: els.capFilter.value.trim() };
  if (!body.interface) { toast("请先选择网卡", "warn"); return; }
  els.btnStart.disabled = true; els.btnStart.textContent = "启动中…";
  try {
    const r = await post("/api/capture", body);
    if (!r.ok) { toast(r.error || "启动失败", "warn"); return; }
    toast("已开始实时抓包, 数据来自真实网络", "");
    els.btnStart.textContent = "▶ 开始抓包";
  } catch (err) { toast("启动失败: " + err.message, "warn"); }
  finally { els.btnStart.disabled = false; els.btnStart.textContent = "▶ 开始抓包"; }
}
async function doStartPcap(filePath) {
  const r = await post("/api/capture", { action: "start-pcap", file: filePath,
    display_filter: els.dispFilter.value.trim() });
  if (!r.ok) { toast(r.error || "回放失败", "warn"); throw new Error(r.error); }
  state.pcapPath = filePath;
  toast("正在回放真实抓包: " + filePath.split(/[\\/]/).pop(), "");
}
async function stop() {
  await post("/api/capture", { action: "stop" });
  toast("已停止采集", "");
}

// 文件选择 -> 上传到服务端 -> 自动回放
async function uploadAndPlay(file) {
  if (!file) return;
  const btn = els.btnStartPcap;
  btn.disabled = true; btn.textContent = "上传中…";
  try {
    const name = encodeURIComponent(file.name);
    const res = await fetch(`/api/upload-capture?name=${name}`, { method: "POST",
      body: file });
    const data = await res.json();
    if (!res.ok || !data.ok) { toast("上传失败: " + (data.error || res.status), "warn"); return; }
    els.pcapText.value = data.path;
    await doStartPcap(data.path);
  } catch (err) { toast("上传失败: " + err.message, "warn"); }
  finally { btn.disabled = false; btn.textContent = "▶ 回放"; }
}

// ================================================================ 模式切换
function setMode(m) {
  const live = m === "live";
  els.paneLive.classList.toggle("hidden", !live);
  els.panePcap.classList.toggle("hidden", live);
  els.modeLive.classList.toggle("active", live);
  els.modePcap.classList.toggle("active", !live);
  if (live) refreshMeta();
}

// ================================================================ 封包表
function renderPackets(snap, force) {
  const list = (snap.packets || []).slice().reverse();   // 新->旧
  const q = els.pktSearch.value.trim().toLowerCase();
  const newOnes = list.filter(p => p.seq > state.lastPktSeq);
  state.lastPktSeq = list.length ? list[0].seq : state.lastPktSeq;
  els.pktStat.textContent = snap.meta.capturing
    ? `实时抓包中 · 累计 ${fmt(snap.stats.packets)} 包`
    : (snap.meta.mode === "pcap" ? `文件回放 · 累计 ${fmt(snap.stats.packets)} 包`
      : "未在采集");
  if (force) els.pktBody.innerHTML = "";
  (force ? list : newOnes).forEach(p => {
    if (p.seq <= state.lastPktSeq - 400 && !force) return;
    if (!matchPkt(p, q)) return;
    const tr = document.createElement("tr");
    const flag = p.flags || "-";
    const cls = p.flags && p.flags.includes("S") && !p.flags.includes("A") ? " warn" : "";
    tr.innerHTML =
      `<td>${p.num || p.seq}</td><td>${timeStr(p.ts)}</td><td>${esc(p.src)}</td>` +
      `<td>${esc(p.dst)}</td><td>${esc(p.proto)}</td>` +
      `<td>${esc(p.sport || "-")}</td><td>${esc(p.dport || "-")}</td>` +
      `<td class="${cls}">${flag}</td><td>${p.length}</td>`;
    els.pktBody.prepend(tr);
  });
  els.pktEmpty.classList.toggle("hidden", els.pktBody.childNodes.length > 0 ||
    (snap.stats && snap.stats.packets > 0));
  while (els.pktBody.childNodes.length > 320) els.pktBody.removeChild(els.pktBody.lastChild);
  state.pktShown = list.slice(0, 300);
}
function matchPkt(p, q) {
  if (!q) return true;
  return [p.src, p.dst, p.proto, p.sport, p.dport, p.flags].join(" ").toLowerCase().includes(q);
}

// ================================================================ 威胁处置
function blockIp(ip, note) {
  return post("/api/firewall", { src_ip: ip, action: "deny", protocol: "any",
    note: note || "威胁联动处置" });
}
function renderThreats(snap) {
  const list = (snap.detections || []).filter(d => !state.thDismiss.has(d.ts + d.title));
  els.thCnt.textContent = list.length ? String(list.length) : "";
  els.thEmpty.classList.toggle("hidden", list.length > 0);
  els.thBody.innerHTML = "";
  const lv = els.thLevel.value;
  list.slice(0, 120).forEach(d => {
    if (lv && d.level !== lv) return;
    const tr = document.createElement("tr");
    const kind = kindZh[d.kind] || d.kind || "未知";
    const conf = Math.round((d.confidence || 0) * 100) + "%";
    const blockable = d.src;
    tr.innerHTML =
      `<td>${esc(d.time || timeStr(d.ts))}</td>` +
      `<td class="${d.level === "critical" ? "attack" : "warn"}">${zh[d.level] || d.level}</td>` +
      `<td>${esc(kind)}</td>` +
      `<td><b>${esc(d.title)}</b><br><span class="hint">${esc(d.detail || "")}</span></td>` +
      `<td>${conf}</td>` +
      `<td>${blockable
        ? `<button class="btn mini" data-ip="${esc(d.src)}" data-note="${esc(d.kind)}">阻断源 ${esc(d.src)}</button> `
        : (d.dst ? `<span class="hint">目标 ${esc(d.dst)}:${esc(d.dport || "")}, 建议边界限速</span>` : "-")}
         <span class="del" data-dim="1" title="忽略">忽略</span></td>`;
    const blockBtn = tr.querySelector("[data-ip]");
    if (blockBtn) blockBtn.addEventListener("click", async () => {
      try {
        await blockIp(blockBtn.dataset.ip, blockBtn.dataset.note);
        toast("已添加 deny 规则: " + blockBtn.dataset.ip, "");
        loadFirewall();
      } catch (err) { toast("操作失败: " + err.message, "warn"); }
    });
    tr.querySelector(".del").addEventListener("click", () => {
      state.thDismiss.add(d.ts + d.title);
      d._hide = true;
      renderThreats(snap);
    });
    els.thBody.appendChild(tr);
  });
  els.thCnt.textContent = els.thBody.childNodes.length ? String(els.thBody.childNodes.length) : "";
}

// ================================================================ 连接明细
function renderFlows(snap) {
  const links = snap.links || [];
  els.flowBody.innerHTML = "";
  links.slice(0, 200).forEach(l => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(l.src)}</td><td>${esc(l.dst)}</td><td>${esc(l.proto)}</td>` +
      `<td>${esc(l.dport || "-")}</td><td>${l.pkts}</td><td>${fmt(l.bytes)}</td>` +
      `<td>${l.proto === "tcp" ? l.syn || 0 : "-"}</td>`;
    els.flowBody.appendChild(tr);
  });
  els.hostsRow.innerHTML = "";
  (snap.top_hosts || []).forEach(h => {
    const span = document.createElement("span");
    span.className = "hostchip" + (h.internal ? "" : " ext");
    span.innerHTML = `<span class="ip">${esc(h.id)}</span>  ↓${fmt(h.in)} ↑${fmt(h.out)} · ${fmt(h.bytes)}B`;
    els.hostsRow.appendChild(span);
  });
}

// ================================================================ 网络图
const LOGICAL_W = 960, LOGICAL_H = 440;
function setupCanvas(canvas, key) {
  const wrap = canvas.parentElement;
  const w = wrap.clientWidth || 700;
  canvas.width = Math.max(320, Math.floor(w * (window.devicePixelRatio || 1)));
  canvas.height = Math.max(240, Math.floor(canvas.width * LOGICAL_H / LOGICAL_W));
  canvas.style.height = "auto";
  return { ctx: canvas.getContext("2d"), sx: canvas.width / LOGICAL_W,
    sy: canvas.height / LOGICAL_H };
}
function nodePosition(nodes, nd, i) {
  // 内部主机放右侧(可信区), 外部放左侧(不可信区)
  const side = nd.role === "internal" ? 1 : 0;
  const same = nodes.filter(x => x.role === nd.role);
  const idx = same.indexOf(nd);
  const total = Math.max(1, same.length);
  const col = side * (LOGICAL_W - 160) + 90;              // x 中心
  const spread = 30 + (LOGICAL_H - 120) / Math.max(1, Math.ceil(total / 6)) * (idx % Math.ceil(total / 6));
  const y = 70 + ((idx * 97) % (LOGICAL_H - 140));
  const x = col + (side ? -60 + (idx % 6) * 22 : 60 - (idx % 6) * 22);
  return { x, y: y, r: 7 + Math.min(14, Math.log2(nd.pkts + 1) * 2.6) };
}
function drawNet(snap) {
  if (!state.netCtx) state.netCtx = setupCanvas(els.net, "net");
  const { ctx, sx, sy } = state.netCtx;
  const W = els.net.width, H = els.net.height;
  ctx.clearRect(0, 0, W, H); ctx.save(); ctx.scale(sx, sy);
  const nodes = (snap.nodes || []);
  const byId = {}; nodes.forEach(n => byId[n.id] = n);
  const detIps = new Set();
  (snap.detections || []).forEach(d => { if (d.src) detIps.add(d.src); if (d.dst) detIps.add(d.dst); });
  // 边
  (snap.links || []).slice(0, 180).forEach(lk => {
    const a = byId[lk.src], b = byId[lk.dst];
    if (!a || !b) return;
    const posA = nodePosition(nodes, a, 0), posB = nodePosition(nodes, b, 0);
    const threat = detIps.has(lk.src) || detIps.has(lk.dst);
    ctx.beginPath(); ctx.moveTo(posA.x, posA.y); ctx.lineTo(posB.x, posB.y);
    ctx.strokeStyle = threat ? "rgba(255,85,96,.85)" : "rgba(70,180,240,.4)";
    ctx.lineWidth = threat ? 2 : Math.min(4, 0.6 + Math.log2(lk.pkts + 1));
    if (threat) ctx.setLineDash([5, 4]);
    ctx.stroke(); ctx.setLineDash([]);
    if (threat) { // 方向指示包
      const t = (performance.now() / 900) % 1;
      const px = posA.x + (posB.x - posA.x) * t, py = posA.y + (posB.y - posA.y) * t;
      ctx.fillStyle = "#ff9aa2";
      ctx.beginPath(); ctx.arc(px, py, 2.4, 0, Math.PI * 2); ctx.fill();
    }
  });
  // 节点
  nodes.forEach((nd, i) => {
    const p = nodePosition(nodes, nd, i);
    const threat = detIps.has(nd.id);
    ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    ctx.fillStyle = threat ? "#331320" : (nd.role === "internal" ? "#0c2b22" : "#1a1230");
    ctx.fill();
    ctx.lineWidth = threat ? 2.4 : 1.4;
    ctx.strokeStyle = threat ? "#ff5560" : (nd.role === "internal" ? "#2ee6a8" : "#b06bff");
    ctx.stroke();
    ctx.font = "9px Consolas,monospace"; ctx.textAlign = "center"; ctx.fillStyle = "#c9d7ee";
    ctx.fillText(nd.id, p.x, p.y - p.r - 4);
    ctx.fillStyle = "#8ba3c7";
    ctx.fillText(fmt(nd.pkts) + " pkt", p.x, p.y + p.r + 9);
  });
  ctx.font = "10px sans-serif"; ctx.textAlign = "left"; ctx.fillStyle = "#8ba3c7";
  ctx.fillText("◀ 外部/公网        [连线=真实流量, 宽度按包数, 红=命中威胁]        内部/私网 ▶",
    30, LOGICAL_H - 10);
  if (!nodes.length) {
    ctx.textAlign = "center"; ctx.font = "14px sans-serif"; ctx.fillStyle = "#5b7194";
    ctx.fillText("等待真实流量…(开始抓包或回放文件后展示实际主机)", LOGICAL_W / 2, LOGICAL_H / 2);
  }
  ctx.restore();
}
function drawSpark(snap) {
  if (!state.sparkCtx) state.sparkCtx = setupCanvas(els.spark, "spark");
  const { ctx, sx, sy } = state.sparkCtx;
  const W = els.spark.width, H = els.spark.height;
  ctx.clearRect(0, 0, W, H); ctx.save(); ctx.scale(sx, sy);
  const sp = snap.spark || [];
  const maxP = Math.max(10, ...sp.map(x => x.pps));
  ctx.strokeStyle = "#35d0ff"; ctx.lineWidth = 1.6; ctx.beginPath();
  sp.forEach((x, i) => {
    const px = 10 + i / Math.max(1, sp.length - 1) * (900 - 20);
    const py = 50 - (x.pps / maxP) * 42;
    i === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
  });
  ctx.stroke();
  ctx.fillStyle = "#ffc24b";
  sp.forEach((x, i) => { if (x.dps > 0) {
    const px = 10 + i / Math.max(1, sp.length - 1) * (900 - 20);
    ctx.fillRect(px, 54, 2, -Math.min(26, x.dps * 14)); } });
  ctx.font = "9px sans-serif"; ctx.fillStyle = "#8ba3c7";
  ctx.fillText("包速率(蓝 pps) / 新告警速率(黄)", 8, 8);
  ctx.restore();
}

// ================================================================ 顶栏
function renderTop(snap) {
  const s = snap.stats || {};
  els.kPkts.textContent = fmt(s.packets);
  els.kPps.textContent = s.pps !== undefined ? Math.round(s.pps) : 0;
  els.kFlows.textContent = fmt(s.flows_now);
  els.kDet.textContent = fmt(s.detections);
  els.kCrit.textContent = fmt(s.critical_now);
  els.kCrit.className = s.critical_now > 0 ? "danger" : "";
  const lv = snap.threat_level || "safe";
  els.threat.className = "threat " + lv;
  els.threat.textContent = lv === "safe" ? "安全" : lv === "warning" ? "有威胁" : "严重威胁";
  els.netHint.textContent = snap.meta.capturing ? `采样中 · ${snap.meta.source}` : "未在采集";
  if (snap.meta && snap.meta.saved_path && els.btnSave.title !== snap.meta.saved_path) {
    els.btnSave.title = snap.meta.saved_path;
  }
}

// ================================================================ 防火墙
async function loadFirewall() {
  try {
    const rules = await api("/api/firewall");
    els.fwBody.innerHTML = "";
    rules.forEach(r => {
      const tr = document.createElement("tr");
      const proto = r.protocol === "any" ? "any" : r.protocol + (r.dport ? "/" + r.dport : "");
      tr.innerHTML =
        `<td class="${r.action === "deny" ? "attack" : "ok"}">${r.action}</td>` +
        `<td>${esc(r.src_ip)}</td><td>${esc(proto)}</td><td>${esc(r.source)}</td>` +
        `<td><span class="switch" data-id="${esc(r.id)}">${r.enabled ? "✔ 启用" : "✘ 停用"}</span></td>` +
        `<td><span class="del" data-id="${esc(r.id)}">✕</span></td>`;
      tr.querySelector(".switch").addEventListener("click", async ev => {
        const cur = rules.find(x => x.id === ev.target.dataset.id);
        await post("/api/firewall/toggle", { id: cur.id, enabled: !cur.enabled });
        loadFirewall();
      });
      tr.querySelector(".del").addEventListener("click", async ev => {
        await post("/api/firewall/delete", { id: ev.target.dataset.id });
        loadFirewall();
      });
      els.fwBody.appendChild(tr);
    });
  } catch (e) { /* ignore */ }
}

// ================================================================ AI
function renderAdvice(items) {
  els.aiList.innerHTML = "";
  if (!items || !items.length) {
    els.aiList.innerHTML = `<div class="advice info"><div class="t">正常</div>
      <div class="d">当前无建议, AI 将持续监控真实流量。</div></div>`;
    return;
  }
  items.forEach(a => {
    const d = document.createElement("div");
    d.className = "advice " + a.level;
    d.innerHTML =
      `<span class="lv">${zh[a.level] || a.level} · ${Math.round((a.confidence || 0) * 100)}%</span>` +
      `<div class="t">${esc(a.title)}</div><div class="d">${esc(a.detail || "")}</div>` +
      `<div class="a">→ ${esc(a.recommended_action || "")}</div>`;
    els.aiList.appendChild(d);
  });
}
async function refreshAdvice() {
  try {
    const data = await api("/api/advisor");
    renderAdvice(data.rules);
    els.llmBadge.textContent = data.llm_available ? "规则引擎 + LLM 在线" : "规则引擎(离线)";
    els.llmBadge.className = "badge" + (data.llm_available ? " on" : "");
  } catch (e) { /* ignore */ }
}

// ================================================================ 主轮询
let lastThreatsJson = "";
async function poll() {
  try {
    const snap = await api("/api/snapshot");
    state.lastSnap = snap;
    renderTop(snap);
    renderPackets(snap, false);
    const tabs = document.querySelector(".tab.active");
    if (tabs && tabs.dataset.tab === "threats") {
      const key = JSON.stringify((snap.detections || []).map(d => d.ts + d.title).slice(0, 8));
      if (key !== lastThreatsJson) { renderThreats(snap); lastThreatsJson = key; }
    }
    if (tabs && tabs.dataset.tab === "flows") renderFlows(snap);
    drawNet(snap);
    drawSpark(snap);
    if (snap.meta.mode !== state.mode) { refreshMeta(); return; }
  } catch (err) { console.warn("poll", err); }
}

// 交互事件绑定
els.modeLive.addEventListener("click", () => setMode("live"));
els.modePcap.addEventListener("click", () => setMode("pcap"));
els.btnRefresh.addEventListener("click", async () => {
  const r = await post("/api/capture", { action: "refresh" });
  state.ifaces = r.interfaces || []; fillInterfaces(state.ifaces);
  toast("网卡列表已刷新", "");
});
els.btnStart.addEventListener("click", doStart);
els.btnStop.addEventListener("click", async () => { await stop(); refreshMeta(); });
els.btnBrowse.addEventListener("click", () => els.pcapFile.click());
els.pcapFile.addEventListener("change", () => {
  if (els.pcapFile.files.length) uploadAndPlay(els.pcapFile.files[0]);
});
els.btnStartPcap.addEventListener("click", async () => {
  const path = els.pcapText.value.trim();
  if (!path) { toast("请先选择 pcap 文件", "warn"); return; }
  try { await doStartPcap(path); } catch (e) { /* toast in fn */ }
});
els.autoBlock.addEventListener("change", async () => {
  await post("/api/capture", { action: "auto-block", enabled: els.autoBlock.checked });
  toast(els.autoBlock.checked ? "已开启自动联动 deny(有误伤风险)" : "自动联动已关闭", "warn");
});
els.btnWsOpen.addEventListener("click", async () => {
  const file = state.meta && state.meta.saved_path;
  try {
    const r = file
      ? await post("/api/tools/open", { file })
      : await post("/api/tools/open", { interface: els.iface.value });
    if (!r.ok) toast(r.error, "warn");
  } catch (e) { toast("打开失败: " + e.message, "warn"); }
});
els.btnSave.addEventListener("click", () => {
  const p = state.meta && state.meta.saved_path;
  if (p) { navigator.clipboard && navigator.clipboard.writeText(p).catch(() => {});
    toast("真实抓包文件已保存: " + p, ""); }
});
// tabs
document.querySelectorAll(".tab").forEach(t => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x === t));
  document.querySelectorAll(".tab-body").forEach(b => b.classList.toggle("hidden",
    b.id !== "tab-" + t.dataset.tab));
  if (t.dataset.tab === "packets") renderPackets(state.lastSnap || { packets: [] }, true);
  if (t.dataset.tab === "threats") renderThreats(state.lastSnap || {});
  if (t.dataset.tab === "flows") renderFlows(state.lastSnap || {});
}));
// 封包过滤 / 导出
let filterTimer;
els.pktSearch.addEventListener("input", () => {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => {
    els.pktBody.innerHTML = "";
    (state.pktShown || []).forEach(p => {
      if (!matchPkt(p, els.pktSearch.value.trim().toLowerCase())) return;
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${p.num || p.seq}</td><td>${timeStr(p.ts)}</td>` +
        `<td>${esc(p.src)}</td><td>${esc(p.dst)}</td><td>${esc(p.proto)}</td>` +
        `<td>${esc(p.sport || "-")}</td><td>${esc(p.dport || "-")}</td>` +
        `<td>${p.flags || "-"}</td><td>${p.length}</td>`;
      els.pktBody.appendChild(tr);
    });
  }, 250);
});
els.btnPktExport.addEventListener("click", () => csvExport(
  state.pktShown || [], ["num", "ts", "src", "dst", "proto", "sport", "dport",
    "flags", "length"], "arkids_packets.csv"));
els.btnThExport.addEventListener("click", () => csvExport(
  (state.lastSnap?.detections || []).map(d => ({
    time: d.time, level: d.level, kind: d.kind, title: d.title, detail: d.detail,
    src: d.src || "", dst: d.dst || "", dport: d.dport || "", confidence: d.confidence })),
  ["time", "level", "kind", "title", "detail", "src", "dst", "dport", "confidence"],
  "arkids_threats.csv"));
els.thLevel.addEventListener("change", () => renderThreats(state.lastSnap || {}));
// AI
els.btnLLM.addEventListener("click", async () => {
  els.btnLLM.disabled = true; els.aiAns.classList.remove("hidden");
  els.aiAns.textContent = "AI 研判中(将真实统计与告警摘要发送给大模型)…";
  try {
    const r = await post("/api/advisor/llm", { question: els.aiQ.value.trim() });
    els.aiAns.textContent = r.ok ? r.text
      : "⚠ " + r.error + "\n(规则引擎建议在上方实时给出)";
  } catch (e) { els.aiAns.textContent = "请求失败: " + e.message; }
  finally { els.btnLLM.disabled = false; }
});
// 防火墙表单
els.fwForm.addEventListener("submit", async ev => {
  ev.preventDefault();
  const src = els.fwSrc.value.trim();
  if (!src) return;
  await post("/api/firewall", { src_ip: src, action: els.fwAction.value,
    protocol: els.fwProto.value, dport: els.fwPort.value.trim(), note: "手工规则" });
  els.fwSrc.value = els.fwPort.value = "";
  toast("规则已添加: " + src, "");
  loadFirewall();
});
els.btnScript.addEventListener("click", async () => {
  if (!els.fwScript.classList.contains("hidden")) { els.fwScript.classList.add("hidden"); return; }
  const { script } = await api("/api/firewall/script");
  els.fwScript.textContent = script || "# 暂无启用的 deny 规则";
  els.fwScript.classList.remove("hidden");
});
window.addEventListener("resize", () => { state.netCtx = null; state.sparkCtx = null; });
window.addEventListener("beforeunload", () => { try { navigator.sendBeacon("/api/capture", new Blob(
  [JSON.stringify({ action: "stop" })], { type: "application/json" })); } catch (e) {} });

// boot
(async function boot() {
  await refreshMeta();
  await loadFirewall();
  await refreshAdvice();
  setInterval(poll, 1000);
  setInterval(() => { if (!state.meta || !state.meta.capturing) refreshMeta(); }, 5000);
  setInterval(loadFirewall, 4000);
  setInterval(refreshAdvice, 4000);
  setMode("live");
})();
