/* ArkIDS 工具台前端 —— 应用壳导航 / 真实监控 / 封包 / 威胁 / 规则 / 自检 / 设置 */
"use strict";

const $ = (id) => document.getElementById(id);
const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
const els = {
  topSource: $("topSource"), topStatus: $("topStatus"), threatBadge: $("threatBadge"),
  verPill: $("verPill"), navThCnt: $("navThCnt"),
  modeLive: $("modeLive"), modePcap: $("modePcap"),
  paneLive: $("paneLive"), panePcap: $("panePcap"),
  iface: $("iface"), btnRefreshIface: $("btnRefreshIface"), capFilter: $("capFilter"),
  btnStartLive: $("btnStartLive"), btnBrowseFile: $("btnBrowseFile"), pcapFile: $("pcapFile"),
  pcapPath: $("pcapPath"), dispFilter: $("dispFilter"), btnStartPcap: $("btnStartPcap"),
  btnStop: $("btnStop"), autoBlock: $("autoBlock"), autoBlock2: $("autoBlock2"),
  wsChip: $("wsChip"), btnWsOpen: $("btnWsOpen"),
  kPkts: $("kPkts"), kPps: $("kPps"), kFlows: $("kFlows"), kBytes: $("kBytes"),
  kDet: $("kDet"), kCrit: $("kCrit"),
  net: $("net"), spark: $("spark"), toasts: $("toasts"), netHint: $("netHint"),
  recentTh: $("recentTh"), btnGoThreats: $("btnGoThreats"), miniPktBody: $("miniPktBody"),
  pktSearch: $("pktSearch"), pktProto: $("pktProto"), btnPktExport: $("btnPktExport"),
  pktStat: $("pktStat"), pktBody: $("pktBody"), pktEmpty: $("pktEmpty"),
  thLevel: $("thLevel"), btnThExport: $("btnThExport"), btnSampleGo: $("btnSampleGo"),
  thBody: $("thBody"), thEmpty: $("thEmpty"),
  fwForm: $("fwForm"), fwSrc: $("fwSrc"), fwAction: $("fwAction"), fwProto: $("fwProto"),
  fwPort: $("fwPort"), fwBody: $("fwBody"), fwEmpty: $("fwEmpty"),
  btnScript: $("btnScript"), fwScript: $("fwScript"),
  btnSelfcheck: $("btnSelfcheck"), chkHead: $("chkHead"), chkList: $("chkList"),
  btnCopyDiag: $("btnCopyDiag"), sampleBtns: $("sampleBtns"), sampleNote: $("sampleNote"),
  btnExpPkt: $("btnExpPkt"), btnExpTh: $("btnExpTh"),
  aboutVer: $("aboutVer"), aboutTools: $("aboutTools"), llmBadge: $("llmBadge"),
  btnResetSession: $("btnResetSession"), logoMark: $("logoMark"),
};

/* ---------- 工具函数 ---------- */
const fmt = (n) => Number(n || 0).toLocaleString("zh-CN");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const timeStr = (ts) => { const d = new Date((ts || 0) * 1000);
  return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0"); };
const kindZh = { tcp_syn_flood: "TCP SYN 洪泛", port_scan: "端口扫描",
  conn_burst: "连接突发", unknown: "其它" };
const lvlZh = { critical: "严重", warning: "警告", info: "提示" };
const STATUS_TEXT = { idle: "空闲", live: "实时抓包中", replay: "文件回放中",
  replay_done: "回放完成", error: "异常" };

async function api(path, opts) {
  const res = await fetch(path, opts);
  const ct = res.headers.get("content-type") || "";
  const body = ct.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error((body && body.error) || res.statusText || String(res.status));
  return body;
}
const postJson = (path, obj) => api(path, { method: "POST",
  headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj || {}) });

function toast(msg, cls) {
  const d = document.createElement("div");
  d.className = "toast " + (cls || "");
  d.textContent = msg;
  els.toasts.appendChild(d);
  while (els.toasts.childNodes.length > 5) els.toasts.removeChild(els.toasts.firstChild);
  setTimeout(() => d.remove(), 3200);
}
function downloadCSV(rows, cols, name) {
  const head = cols.map((c) => esc(c)).join(",");
  const lines = rows.map((r) => cols.map((c) =>
    `"${String((r && r[c]) ?? "").replace(/"/g, '""')}"`).join(","));
  const blob = new Blob(["\ufeff" + head + "\n" + lines.join("\n")],
    { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

/* ---------- 全局状态 ---------- */
const state = {
  view: "overview", meta: null, snap: null,
  ifaceVersion: "", lastPktSeq: 0, pktCache: [], pktShown: [],
  thDismiss: new Set(), chkDone: false, lastThKey: "",
  netCtx: null, sparkCtx: null, prevStatus: "",
};
const active = () => state.view;

/* ===================================================== 顶部/数据源状态 */
function applyMeta(m) {
  state.meta = m;
  if (m.version && els.verPill.textContent !== "v" + m.version)
    els.verPill.textContent = "v" + m.version;
  const st = m.status || "idle";
  els.topStatus.dataset.status = st;
  els.topStatus.textContent = STATUS_TEXT[st] || st;
  els.topStatus.classList.remove("live", "replay", "replay_done", "error", "idle");
  els.topStatus.classList.add(st);
  els.topSource.textContent = m.source
    ? (st === "replay_done" ? m.source + " · 已完成" : m.source) : "等待真实流量…";
  els.btnStop.classList.toggle("hidden", !m.capturing);
  els.autoBlock.checked = !!m.auto_block;
  els.autoBlock2.checked = !!m.auto_block;
  // Wireshark 工具与提示
  const hasT = !!m.tools.tshark, hasW = !!m.tools.wireshark;
  els.wsChip.textContent = hasT ? "tshark " + ((m.tools.tshark_version || "")
    .replace(/^.*?(\d+\.\d+\.\d+).*$/, "$1")) : (st === "replay" || st === "replay_done"
      ? "内置解析器(无需 tshark)" : "未装 tshark");
  els.btnWsOpen.disabled = !hasW;
  els.btnWsOpen.title = hasW ? "用 Wireshark 打开当前文件/接口" : "未检测到 Wireshark GUI";
  if (!hasT && st === "idle" && !els.btnWsOpen.classList.contains("hint-shown")) {
    // 首次提示一次, 引导到工具箱自检
    toast("未检测到 tshark：可回放真实文件；实时抓包请到工具箱自检安装", "ok");
    els.btnWsOpen.classList.add("hint-shown");
  }
}
function renderTop(snap) {
  const s = snap.stats || {};
  els.kPkts.textContent = fmt(s.packets);
  els.kPps.textContent = s.pps !== undefined ? Math.round(s.pps) : 0;
  els.kFlows.textContent = fmt(s.flows_now);
  els.kBytes.textContent = fmt(s.bytes);
  els.kDet.textContent = fmt(s.detections);
  els.kCrit.textContent = fmt(s.critical_now);
  els.kDet.dataset.hot = s.critical_now > 0 ? "2" : (s.detections > 0 ? "1" : "0");
  els.kCrit.dataset.hot = s.critical_now > 0 ? "2" : "0";
  const lv = snap.threat_level || "safe";
  els.threatBadge.dataset.level = lv;
  els.threatBadge.textContent = lv === "safe" ? "安全" : lv === "warning" ? "有威胁" : "严重威胁";
  if (active() === "overview") {
    els.netHint.textContent = snap.meta.capturing ? "采集进行中" :
      (snap.meta.status === "replay_done" ? "回放完成 · 可再次回放或开始抓包" : "未在采集");
  }
  if (els.pktStat) els.pktStat.textContent =
    `累计 ${fmt(s.packets)} 包 · 当前 ${fmt(s.flows_now)} 连接`;
}
function fillInterfaces(list) {
  els.iface.innerHTML = "";
  if (!list || !list.length) {
    const o = document.createElement("option");
    o.value = ""; o.textContent = "无可用网卡(请以管理员运行)";
    els.iface.appendChild(o);
    return;
  }
  const pref = list.find((i) => !/loopback|virtual|蓝牙|bluetooth/i.test(i.description || ""))
    || list[0];
  list.forEach((i) => {
    const o = document.createElement("option");
    o.value = i.name; o.textContent = `${i.name} — ${(i.description || "未知接口").slice(0, 40)}`;
    if (i.name === pref.name) o.selected = true;
    els.iface.appendChild(o);
  });
}
async function refreshMeta({ silent } = {}) {
  try {
    const m = await api("/api/meta");
    if (JSON.stringify(m.interfaces) !== JSON.stringify(state.ifacesCache)) {
      state.ifacesCache = m.interfaces;
      fillInterfaces(m.interfaces);
    }
    applyMeta(m);
    return m;
  } catch (e) { console.warn("meta", e); return state.meta; }
}

/* ===================================================== 数据源动作 */
function setMode(mode) {
  const live = mode === "live";
  els.paneLive.classList.toggle("hidden", !live);
  els.panePcap.classList.toggle("hidden", live);
  els.modeLive.classList.toggle("active", live);
  els.modePcap.classList.toggle("active", !live);
}
async function startLive() {
  const iface = els.iface.value;
  if (!iface) { toast("请先选择网卡(工具箱可自检)", ""); return; }
  els.btnStartLive.disabled = true;
  try {
    const r = await postJson("/api/capture", { action: "start-live", interface: iface,
      filter: els.capFilter.value.trim() });
    if (!r.ok) { toast(r.error || "启动失败", ""); return; }
    toast("已开始实时抓包(真实数据, 落盘 run/captures)", "ok");
  } catch (e) { toast("启动失败: " + e.message, ""); }
  finally { els.btnStartLive.disabled = false; }
}
async function startPcapPath(path) {
  const r = await postJson("/api/capture", { action: "start-pcap", file: path,
    display_filter: els.dispFilter.value.trim() });
  if (!r.ok) { toast(r.error || "回放失败", ""); throw new Error(r.error || "回放失败"); }
  toast("开始回放真实文件: " + String(path).split(/[\\/]/).pop(), "ok");
}
async function uploadAndPlay(file) {
  if (!file) return;
  const btn = els.btnStartPcap; btn.disabled = true;
  try {
    const res = await fetch("/api/upload-capture?name=" + encodeURIComponent(file.name),
      { method: "POST", body: file });
    const data = await res.json();
    if (!res.ok || !data.ok) { toast("上传失败: " + (data.error || res.status), ""); return; }
    els.pcapPath.value = data.path;
    await startPcapPath(data.path);
  } catch (e) { toast("上传失败: " + e.message, ""); }
  finally { btn.disabled = false; }
}
async function stopAll() {
  await postJson("/api/capture", { action: "stop" });
  toast("已停止", "ok");
}

/* ===================================================== 网络图(真实主机) */
const LW = 960, LH = 420;
function canvasCtx(canvas, tag) {
  const wrap = canvas.parentElement;
  const w = Math.max(320, wrap.clientWidth || 700);
  canvas.width = Math.floor(w * (window.devicePixelRatio || 1));
  canvas.height = Math.max(220, Math.floor(canvas.width * LH / LW));
  const c = canvas.getContext("2d");
  tag.sx = canvas.width / LW; tag.sy = canvas.height / LH;
  tag.ctx = c;
}
function nodePos(nodes, id) {
  const nd = nodes.find((x) => x.id === id) || { id, role: "external" };
  const side = nd.role === "internal" ? 1 : 0;
  const same = nodes.filter((x) => x.role === nd.role);
  const idx = Math.max(0, same.findIndex((x) => x.id === id));
  const total = Math.max(1, same.length);
  const col = side ? LW - 190 : 160;
  const row = Math.floor(idx / 8), band = Math.floor((LH - 90) / Math.max(1, Math.ceil(total / 8)));
  return { x: col + (side ? -50 : 50) + (idx % 8) * 16,
    y: 60 + row * 78 + ((idx * 37) % 48), r: 6 + Math.min(13, Math.log2((nd.pkts || 0) + 1) * 2.4) };
}
function drawNet(snap) {
  if (active() !== "overview" || !els.net.isConnected) return;
  if (!state.netCtx) { state.netCtx = {}; canvasCtx(els.net, state.netCtx); }
  const { ctx, sx, sy } = state.netCtx;
  ctx.save(); ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.clearRect(0, 0, els.net.width, els.net.height);
  ctx.scale(sx, sy);
  const nodes = snap.nodes || [];
  const byId = {}; nodes.forEach((n) => byId[n.id] = n);
  const detIps = new Set();
  (snap.detections || []).forEach((d) => { if (d.src) detIps.add(d.src); if (d.dst) detIps.add(d.dst); });
  const pa = {}, pb = {};
  nodes.forEach((n) => { const p = nodePos(nodes, n.id); pa[n.id] = p; pb[n.id] = p; });
  (snap.links || []).slice(0, 160).forEach((lk) => {
    if (!pa[lk.src] || !pb[lk.dst]) return;
    const A = pa[lk.src], B = pb[lk.dst];
    const threat = detIps.has(lk.src) || detIps.has(lk.dst);
    ctx.beginPath(); ctx.moveTo(A.x, A.y); ctx.lineTo(B.x, B.y);
    ctx.strokeStyle = threat ? "rgba(255,90,102,.9)" : "rgba(70,180,240,.45)";
    ctx.lineWidth = threat ? 2.2 : Math.min(4.5, 0.6 + Math.log2((lk.pkts || 0) + 1));
    if (threat) ctx.setLineDash([6, 5]);
    ctx.stroke(); ctx.setLineDash([]);
    if (threat) {
      const t = (performance.now() / 850) % 1;
      ctx.fillStyle = "#ffb9c0";
      ctx.beginPath(); ctx.arc(A.x + (B.x - A.x) * t, A.y + (B.y - A.y) * t, 2.3, 0, 7); ctx.fill();
    }
  });
  nodes.forEach((n) => {
    const p = nodePos(nodes, n.id);
    const threat = detIps.has(n.id);
    ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 7);
    ctx.fillStyle = threat ? "#3a1420" : (n.role === "internal" ? "#0c2d23" : "#1c1236");
    ctx.fill();
    ctx.lineWidth = threat ? 2.4 : 1.3;
    ctx.strokeStyle = threat ? "#ff5a66" : (n.role === "internal" ? "#2ee6a8" : "#b47cff");
    ctx.stroke();
    ctx.font = "9px Consolas,monospace"; ctx.textAlign = "center";
    ctx.fillStyle = "#d6e2f5";
    ctx.fillText(n.id, p.x, p.y - p.r - 4);
    ctx.fillStyle = "#93a7c6";
    ctx.fillText(fmt(n.pkts) + " pkt", p.x, p.y + p.r + 9);
  });
  ctx.font = "11px sans-serif"; ctx.fillStyle = "#93a7c6";
  ctx.textAlign = "left";
  ctx.fillText("◀ 外部/公网        [线宽=真实流量 · 红=命中威胁]        内部/私网 ▶", 16, LH - 8);
  if (!nodes.length) {
    ctx.textAlign = "center"; ctx.fillStyle = "#5f7496"; ctx.font = "14px sans-serif";
    ctx.fillText("等待真实流量…(开始抓包或回放真实文件后展示实际主机)", LW / 2, LH / 2 - 8);
  }
  ctx.restore();
}
function drawSpark(snap) {
  if (active() !== "overview") return;
  if (!state.sparkCtx) { state.sparkCtx = {}; canvasCtx(els.spark, state.sparkCtx); }
  const { ctx, sx, sy } = state.sparkCtx;
  ctx.save(); ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.clearRect(0, 0, els.spark.width, els.spark.height);
  ctx.scale(sx, sy);
  const sp = snap.spark || [];
  const W = 960, H = 52;
  const maxP = Math.max(10, ...sp.map((x) => x.pps));
  ctx.strokeStyle = "#3fd4ff"; ctx.lineWidth = 1.6; ctx.beginPath();
  sp.forEach((x, i) => {
    const px = 8 + (i / Math.max(1, sp.length - 1)) * (W - 16);
    const py = H - 8 - (x.pps / maxP) * (H - 18);
    i === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
  });
  ctx.stroke();
  ctx.fillStyle = "#ffc24b";
  sp.forEach((x, i) => {
    if (x.dps > 0) { const px = 8 + (i / Math.max(1, sp.length - 1)) * (W - 16);
      ctx.fillRect(px, H - 6, 2, -Math.min(22, x.dps * 12)); }
  });
  ctx.restore();
}

/* ===================================================== 表格渲染(健壮) */
function clearTable(body) { body.innerHTML = ""; }
function addEmptyRow(body, text) {
  const tr = document.createElement("tr");
  tr.className = "emptyrow";
  const td = document.createElement("td");
  td.colSpan = 30; td.textContent = text;
  tr.appendChild(td); body.appendChild(tr);
}
function protoOf(p) { return p.proto || "ip"; }

function renderMini(snap) {
  const list = (snap.packets || []).slice(-10).reverse();
  els.miniPktBody.innerHTML = "";
  if (!list.length) addEmptyRow(els.miniPktBody, "等待真实流量…");
  list.forEach((p) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${p.num || p.seq || "-"}</td><td>${esc(p.src)}</td>` +
      `<td>${esc(p.dst)}</td><td>${esc(protoOf(p))}</td>` +
      `<td>${esc(p.dport || "-")}</td>`;
    els.miniPktBody.appendChild(tr);
  });
}
function renderPacketsFull() {
  const q = els.pktSearch.value.trim().toLowerCase();
  const proto = els.pktProto.value;
  let list = (state.snap && state.snap.packets) || [];
  list = list.slice().reverse().filter((p) => {
    if (proto === "其他") { return !["tcp", "udp", "icmp", "icmpv6"].includes(protoOf(p)); }
    if (proto && protoOf(p) !== proto) return false;
    if (q) { return [p.src, p.dst, protoOf(p), p.sport, p.dport, p.flags]
      .join(" ").toLowerCase().includes(q); }
    return true;
  });
  state.pktShown = list;
  clearTable(els.pktBody);
  if (!list.length) { addEmptyRow(els.pktBody, "没有匹配的数据包(先开始抓包/回放)"); return; }
  list.slice(0, 500).forEach((p) => {
    const tr = document.createElement("tr");
    const synOnly = p.flags && p.flags.includes("S") && !p.flags.includes("A");
    tr.innerHTML =
      `<td>${p.num || p.seq || "-"}</td><td>${timeStr(p.ts)}</td>` +
      `<td>${esc(p.src)}</td><td>${esc(p.dst)}</td><td>${esc(protoOf(p))}</td>` +
      `<td>${esc(p.sport || "-")}</td><td>${esc(p.dport || "-")}</td>` +
      `<td class="${synOnly ? "warn" : ""}">${esc(p.flags || "-")}</td><td>${p.length ?? "-"}</td>`;
    els.pktBody.appendChild(tr);
  });
}
function incPackets() {
  const snap = state.snap;
  if (!snap || !snap.packets || !snap.packets.length) return;
  const newest = snap.packets[snap.packets.length - 1];
  if (state.lastPktSeq >= newest.seq) return;
  state.lastPktSeq = newest.seq;
  if (active() === "packets") renderPacketsFull();
}
function blockIp(ip, note) {
  return postJson("/api/firewall", { src_ip: ip, action: "deny", protocol: "any",
    note: note || "威胁联动处置" });
}
function renderThreats(snap) {
  const src = (snap && snap.detections) || [];
  const list = src.filter((d) => !state.thDismiss.has(d.ts + d.title));
  const lv = els.thLevel.value;
  clearTable(els.thBody);
  els.navThCnt.textContent = list.length ? String(list.length) : "";
  if (!list.length) { addEmptyRow(els.thBody, "当前未检测到异常流量"); return; }
  list.slice(0, 150).forEach((d) => {
    if (lv && d.level !== lv) return;
    const tr = document.createElement("tr");
    const conf = Math.round((d.confidence || 0) * 100) + "%";
    const blockable = d.src;
    tr.innerHTML =
      `<td>${esc(d.time || timeStr(d.ts))}</td>` +
      `<td class="${d.level === "critical" ? "attack" : "warn"}">${lvlZh[d.level] || d.level}</td>` +
      `<td>${esc(kindZh[d.kind] || d.kind || "其它")}</td>` +
      `<td><b>${esc(d.title)}</b><div class="hint">${esc(d.detail || "")}</div></td>` +
      `<td>${conf}</td>` +
      `<td>${blockable
        ? `<button class="btn small" data-act="block" data-ip="${esc(d.src)}" data-kind="${esc(d.kind)}">阻断 ${esc(d.src)}</button>`
        : (d.dst ? `<span class="hint">目标 ${esc(d.dst)}${d.dport ? ":" + esc(d.dport) : ""} 建议边界限速</span>` : "-")}
       <button class="tog" data-act="dim" title="忽略此条">忽略</button></td>`;
    const b = tr.querySelector('[data-act="block"]');
    if (b) b.addEventListener("click", async () => {
      try { await blockIp(b.dataset.ip, b.dataset.kind); toast("已添加 deny 规则", "ok"); loadFirewall(); }
      catch (e) { toast("操作失败: " + e.message, ""); }
    });
    tr.querySelector('[data-act="dim"]').addEventListener("click", () => {
      state.thDismiss.add(d.ts + d.title); renderThreats(state.snap); });
    els.thBody.appendChild(tr);
  });
}
function renderRecent(snap) {
  const list = (snap.detections || []).slice(0, 6);
  els.recentTh.innerHTML = "";
  if (!list.length) { const li = document.createElement("li"); li.className = "empty";
    li.textContent = "暂无威胁"; els.recentTh.appendChild(li); return; }
  list.forEach((d) => {
    const li = document.createElement("li");
    li.className = d.level || "info";
    li.innerHTML = `<div class="t">[${lvlZh[d.level] || d.level}] ${esc(kindZh[d.kind] || d.kind || "其它")} · ${esc(d.time || timeStr(d.ts))}</div>` +
      `<div class="d">${esc(d.title)}</div>`;
    els.recentTh.appendChild(li);
  });
}

/* ===================================================== 防火墙 */
async function loadFirewall() {
  try {
    const rules = await api("/api/firewall");
    clearTable(els.fwBody);
    if (!rules.length) { addEmptyRow(els.fwBody, "暂无规则(可从威胁页一键添加)"); return; }
    rules.forEach((r) => {
      const tr = document.createElement("tr");
      const proto = r.protocol === "any" ? "any" : r.protocol + (r.dport ? "/" + r.dport : "");
      tr.innerHTML =
        `<td class="${r.action === "deny" ? "attack" : "ok"}">${esc(r.action)}</td>` +
        `<td>${esc(r.src_ip)}</td><td>${esc(proto)}</td><td>${esc(r.source)}</td>` +
        `<td><button class="tog" data-act="toggle" data-id="${esc(r.id)}" data-on="${r.enabled ? 1 : 0}">${r.enabled ? "启用中" : "已停用"}</button></td>` +
        `<td><button class="del tog" data-act="del" data-id="${esc(r.id)}">删除</button></td>`;
      tr.querySelector('[data-act="toggle"]').addEventListener("click", async (ev) => {
        const cur = rules.find((x) => x.id === ev.currentTarget.dataset.id);
        await postJson("/api/firewall/toggle", { id: cur.id, enabled: !cur.enabled });
        loadFirewall();
      });
      tr.querySelector('[data-act="del"]').addEventListener("click", async (ev) => {
        await postJson("/api/firewall/delete", { id: ev.currentTarget.dataset.id });
        loadFirewall();
      });
      els.fwBody.appendChild(tr);
    });
  } catch (e) { console.warn(e); }
}

/* ===================================================== 工具箱 */
async function runSelfcheck() {
  els.btnSelfcheck.disabled = true;
  els.chkList.innerHTML = "<li class='empty'>检测中…</li>";
  try {
    const r = await api("/api/selfcheck");
    state.diag = r.diagnostic;
    els.chkHead.className = "chkhead " + (r.all_ok ? "ok" : "warn");
    els.chkHead.textContent = r.all_ok ? "全部就绪 —— 可实时抓包" :
      `就绪 ${r.ok_count}/${r.total} · ${r.live_ready ? "实时抓包可用" : "已可用: 回放真实文件; 实时抓包需补装驱动/引擎"}`;
    clearTable ? null : null;
    els.chkList.innerHTML = "";
    r.items.forEach((it) => {
      const li = document.createElement("li");
      li.className = it.ok ? "ok" : "warn";
      const link = it.url ? ` · <a href="${esc(it.url)}" target="_blank" rel="noopener">官方下载</a>` : "";
      li.innerHTML = `<div class="row"><span class="mark">${it.ok ? "✓" : "!"}</span>` +
        `<div><b>${esc(it.name)}</b><span class="det">${esc(it.detail)}${link}</span></div></div>`;
      els.chkList.appendChild(li);
    });
  } catch (e) { els.chkList.innerHTML = "<li class='warn'>检测失败: " + esc(e.message) + "</li>"; }
  finally { els.btnSelfcheck.disabled = false; }
}

/* ===================================================== 事件绑定 */
function bindEvents() {
  els.modeLive.addEventListener("click", () => setMode("live"));
  els.modePcap.addEventListener("click", () => setMode("pcap"));
  els.btnStartLive.addEventListener("click", startLive);
  els.btnStartPcap.addEventListener("click", async () => {
    const p = els.pcapPath.value.trim();
    if (!p) { toast("请先选择 pcap 文件", ""); return; }
    try { await startPcapPath(p); } catch (e) { /* toast in fn */ }
  });
  els.btnStop.addEventListener("click", async () => { await stopAll(); refreshMeta(); });
  els.btnBrowseFile.addEventListener("click", () => els.pcapFile.click());
  els.pcapFile.addEventListener("change", () => {
    if (els.pcapFile.files.length) uploadAndPlay(els.pcapFile.files[0]);
  });
  els.btnRefreshIface.addEventListener("click", async () => {
    const r = await postJson("/api/capture", { action: "refresh" });
    fillInterfaces(r.interfaces || []); toast("网卡已刷新", "ok");
  });
  els.autoBlock.addEventListener("change", () =>
    postJson("/api/capture", { action: "auto-block", enabled: els.autoBlock.checked }));
  els.autoBlock2.addEventListener("change", () => {
    els.autoBlock.checked = els.autoBlock2.checked;
    postJson("/api/capture", { action: "auto-block", enabled: els.autoBlock2.checked });
    toast(els.autoBlock2.checked ? "已开启自动联动(注意误伤风险)" : "自动联动已关闭", "ok");
  });
  els.btnWsOpen.addEventListener("click", async () => {
    const file = state.meta && state.meta.saved_path;
    try {
      const r = file ? await postJson("/api/tools/open", { file })
        : await postJson("/api/tools/open", { interface: els.iface.value });
      if (!r.ok) toast(r.error, "");
    } catch (e) { toast("打开失败: " + e.message, ""); }
  });
  els.btnGoThreats.addEventListener("click", () => showView("threats"));
  els.btnSampleGo.addEventListener("click", () => showView("toolbox"));
  els.btnScript.addEventListener("click", async () => {
    if (!els.fwScript.hidden) { els.fwScript.hidden = true; return; }
    const { script } = await api("/api/firewall/script");
    els.fwScript.textContent = script || "# 暂无启用的 deny 规则";
    els.fwScript.hidden = false;
  });
  els.fwForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const src = els.fwSrc.value.trim();
    if (!src) return;
    await postJson("/api/firewall", { src_ip: src, action: els.fwAction.value,
      protocol: els.fwProto.value, dport: els.fwPort.value.trim(), note: "手工规则" });
    els.fwSrc.value = els.fwPort.value = "";
    toast("已添加规则: " + src, "ok"); loadFirewall();
  });
  // 工具箱
  els.btnSelfcheck.addEventListener("click", runSelfcheck);
  els.btnCopyDiag.addEventListener("click", async () => {
    const txt = state.diag || "未检测";
    try { await navigator.clipboard.writeText(txt); toast("诊断已复制", "ok"); }
    catch (e) { toast("无法复制: " + e.message, ""); }
  });
  els.sampleBtns.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button[data-name]");
    if (!btn) return;
    const name = btn.dataset.name;
    els.sampleNote.textContent = "下载中: " + name + " …";
    try {
      const r = await postJson("/api/sample", { name });
      if (!r.ok) { els.sampleNote.textContent = "失败: " + (r.error || "网络不可达"); return; }
      els.sampleNote.textContent = `已获取官方样例 ${r.bytes} 字节 -> ${r.path}; ` +
        ((r.replay && r.replay.ok) ? "已自动开始回放。" : "回放未启动。");
      toast("官方真实样例已加载并回放", "ok");
      showView("overview");
    } catch (e) { els.sampleNote.textContent = "失败: " + e.message; }
  });
  els.btnExpPkt.addEventListener("click", async () => {
    const { rows } = await api("/api/logs?kind=packets&n=6000");
    downloadCSV(rows, ["num", "ts", "src", "dst", "proto", "sport", "dport",
      "flags", "length"], "arkids_packets.csv");
  });
  els.btnExpTh.addEventListener("click", async () => {
    const { rows } = await api("/api/logs?kind=detections&n=6000");
    downloadCSV(rows.map((d) => ({ time: d.time, level: d.level, kind: d.kind,
      title: d.title, detail: d.detail, src: d.src || "", dst: d.dst || "",
      dport: d.dport || "", confidence: d.confidence })),
    ["time", "level", "kind", "title", "detail", "src", "dst", "dport", "confidence"],
    "arkids_threats.csv");
  });
  els.btnResetSession.addEventListener("click", async () => {
    await postJson("/api/capture", { action: "reset" });
    toast("会话已清空(规则保留)", "ok"); refreshMeta();
  });
  // 过滤器
  els.pktSearch.addEventListener("input", () => { if (active() === "packets") renderPacketsFull(); });
  els.pktProto.addEventListener("change", () => { if (active() === "packets") renderPacketsFull(); });
  els.pktSearch.addEventListener("keydown", () => {}); // 预留
  els.btnPktExport.addEventListener("click", async () => {
    const { rows } = await api("/api/logs?kind=packets&n=6000");
    downloadCSV(rows, ["num", "ts", "src", "dst", "proto", "sport", "dport",
      "flags", "length"], "arkids_packets.csv");
  });
  els.btnThExport.addEventListener("click", async () => {
    const { rows } = await api("/api/logs?kind=detections&n=6000");
    downloadCSV(rows.map((d) => ({ time: d.time, level: d.level, kind: d.kind,
      title: d.title, src: d.src || "", dst: d.dst || "", confidence: d.confidence })),
    ["time", "level", "kind", "title", "src", "dst", "confidence"], "arkids_threats.csv");
  });
  els.thLevel.addEventListener("change", () => renderThreats(state.snap));
  // 导航
  $$(".navitem").forEach((it) => it.addEventListener("click", () => showView(it.dataset.view)));
}

/* ===================================================== 视图路由 */
function showView(name) {
  state.view = name;
  $$(".navitem").forEach((x) => x.classList.toggle("active", x.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + name));
  if (name === "packets") renderPacketsFull();
  if (name === "threats") renderThreats(state.snap);
  if (name === "firewall") loadFirewall();
  if (name === "toolbox" && !state.chkDone) { state.chkDone = true; runSelfcheck(); }
  if (name === "settings") refreshMeta();
}

/* ===================================================== 轮询 */
let thKey = "";
async function poll() {
  try {
    const snap = await api("/api/snapshot");
    state.snap = snap;
    if (state.meta && (snap.meta.status !== state.meta.status ||
        snap.meta.capturing !== state.meta.capturing)) {
      refreshMeta({ silent: true });
    }
    renderTop(snap);
    if (active() === "overview") {
      drawNet(snap); drawSpark(snap); renderRecent(snap); renderMini(snap);
      // 每 2s 刷新威胁表数据键
      const key = JSON.stringify((snap.detections || []).map((d) => d.ts + d.title).slice(0, 6));
      if (key !== thKey) { renderRecent(snap); thKey = key; }
    } else {
      incPackets();
      if (active() === "threats") {
        const k2 = JSON.stringify((snap.detections || []).map((d) => d.ts + d.title).slice(0, 10));
        if (k2 !== thKey) { renderThreats(snap); thKey = k2; }
      }
      if (active() === "packets") incPackets();
    }
  } catch (e) { console.warn("poll", e); }
}

async function refreshAdviceBadge() {
  try {
    const d = await api("/api/advisor");
    els.llmBadge.textContent = d.llm_available ? "规则引擎 + LLM 在线" : "规则引擎(离线)";
    els.llmBadge.classList.toggle("on", !!d.llm_available);
  } catch (e) { /* ignore */ }
}

/* ===================================================== 启动 */
window.addEventListener("resize", () => { state.netCtx = null; state.sparkCtx = null; });
window.addEventListener("beforeunload", () => { try {
  navigator.sendBeacon("/api/capture", new Blob([JSON.stringify({ action: "stop" })],
    { type: "application/json" })); } catch (e) {} });

(async function boot() {
  bindEvents();
  setMode("live");
  await refreshMeta();
  await loadFirewall();
  refreshAdviceBadge();
  // 关于
  els.aboutVer.textContent = state.meta ? "v" + state.meta.version : "—";
  els.aboutTools.textContent = state.meta ? (state.meta.tools.tshark
    ? state.meta.tools.tshark : "未安装(文件回放可用内置解析器)") : "—";
  setInterval(poll, 1000);
  setInterval(() => refreshMeta({ silent: true }), 5000);
  setInterval(loadFirewall, 4000);
  setInterval(refreshAdviceBadge, 8000);
})();
