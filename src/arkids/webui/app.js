/* ArkIDS Dashboard 前端 —— 实时攻防网络 / 日志 / 防火墙 / AI 建议 */
"use strict";

// ------------------------------------------------------------- DOM 快捷引用
const $ = (id) => document.getElementById(id);
const els = {
  threatBox: $("threatBox"), threatLabel: $("threatLabel"),
  net: $("net"), spark: $("spark"), toasts: $("toasts"),
  kFlows: $("kFlows"), kAlerts: $("kAlerts"), kBlocks: $("kBlocks"),
  kRate: $("kRate"), kRecall: $("kRecall"),
  logBody: document.querySelector("#logTable tbody"), logFilter: $("logFilter"),
  btnPause: $("btnPause"), btnSpeed: $("btnSpeed"),
  adviceList: $("adviceList"), llmBadge: $("llmBadge"),
  aiQuestion: $("aiQuestion"), btnAskAi: $("btnAskAi"), aiAnswer: $("aiAnswer"),
  fwBody: document.querySelector("#fwTable tbody"), fwForm: $("fwForm"),
  fwSrc: $("fwSrc"), fwAction: $("fwAction"), fwProto: $("fwProto"),
  fwPort: $("fwPort"), fwNote: $("fwNote"), btnScript: $("btnScript"),
  fwScript: $("fwScript"),
};
const fmt = (n) => Number(n).toLocaleString("zh-CN");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const LEVEL_ZH = { critical: "严重", warn: "警告", info: "提示" };
const VERDICT_ZH = { normal: "正常", dos: "DoS", probe: "探测", r2l: "R2L", u2r: "U2R", other: "其他" };
const ATTACKER_PREFIX = "203.0.113.";
const USER_PREFIX = "10.10.";

// ------------------------------------------------------------- 状态
const state = {
  paused: false, speed: 40,
  logCount: 0, seenSeq: 0, adviceSeen: new Set(),
  net: null, spark: null, dpr: 1,
};

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

// ========================================================= 网络图绘制
const LOGICAL_W = 900, LOGICAL_H = 460;

function nodePos(role, id, idx, total) {
  if (role === "server") return { x: 740, y: 235, r: 30 };
  if (role === "attacker") {
    const cols = 3, c = idx % cols, r = Math.floor(idx / cols);
    return { x: 110 + c * 120, y: 120 + r * 120 + ((idx * 53) % 40), r: 20 };
  }
  // 内网用户
  const span = Math.max(1, total - 1);
  const t = idx / (span || 1);
  return { x: 400 + Math.cos(t * Math.PI * 1.7) * 130, y: 235 + Math.sin(t * Math.PI) * 150, r: 16 };
}

function setupCanvas(canvas, wrap) {
  const w = wrap.clientWidth || 600;
  canvas.width = Math.max(300, Math.floor(w * (window.devicePixelRatio || 1)));
  canvas.height = Math.max(240, Math.floor(canvas.width * (LOGICAL_H / LOGICAL_W)));
  canvas.style.height = "auto";
  return { sx: canvas.width / LOGICAL_W, sy: canvas.height / LOGICAL_H };
}

function roleOf(ip) {
  if (ip === "192.168.1.10") return "server";
  if (ip.startsWith(ATTACKER_PREFIX)) return "attacker";
  return "user";
}

function drawNet(snap) {
  const wrap = els.net.parentElement;
  if (!state.net) {
    const sc = setupCanvas(els.net, wrap);
    state.net = { ctx: els.net.getContext("2d"), ...sc };
  }
  const { ctx, sx, sy } = state.net;
  const W = els.net.width, H = els.net.height;
  ctx.clearRect(0, 0, W, H);
  ctx.save(); ctx.scale(sx, sy);

  const nodes = (snap.nodes || []).map((n, i) => {
    const role = roleOf(n.id);
    const pos = nodePos(role, n.id, i, (snap.nodes || []).length);
    const ip = n.id;
    const st = (snap.ips && snap.ips[ip]) || {};
    return { ...pos, id: ip, role, blocked: st.blocked, attacks: st.attacks || 0 };
  });
  const byId = {};
  nodes.forEach((nd) => { byId[nd.id] = nd; });

  // ---- 边
  (snap.links || []).forEach((lk) => {
    const a = byId[lk.src], b = byId[lk.dst];
    if (!a || !b) return;
    const attack = lk.attacks > 0;
    ctx.beginPath();
    ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
    const pulse = attack ? 0.55 + 0.35 * Math.sin(performance.now() / 260) : 1;
    ctx.strokeStyle = attack
      ? (lk.blocked ? "rgba(255,194,75,.95)" : `rgba(255,85,96,${pulse})`)
      : "rgba(46,230,168,.35)";
    ctx.lineWidth = attack ? 1.6 + Math.min(3, lk.attacks / 4) : 1;
    if (attack) ctx.setLineDash([6, 5]);
    ctx.lineDashOffset = -((performance.now() / 40) % 12);
    ctx.stroke();
    ctx.setLineDash([]);
    // 移动的数据包
    if (attack) {
      const speed = performance.now() / (attack ? 700 : 1200);
      const t01 = (speed % 1 + 1) % 1;
      const px = a.x + (b.x - a.x) * t01, py = a.y + (b.y - a.y) * t01;
      ctx.fillStyle = lk.blocked ? "#ffc24b" : "#ff5560";
      ctx.beginPath(); ctx.arc(px, py, 2.6, 0, Math.PI * 2); ctx.fill();
    }
  });

  // ---- 节点
  nodes.forEach((nd) => {
    const base = nd.role === "server" ? "#35d0ff" : nd.role === "attacker" ? "#ff5560" : "#2ee6a8";
    ctx.beginPath();
    ctx.arc(nd.x, nd.y, nd.r, 0, Math.PI * 2);
    ctx.fillStyle = nd.role === "server" ? "#0c3b5e" : "#101c33";
    ctx.fill();
    if (nd.blocked) {
      ctx.setLineDash([4, 3]);
      ctx.lineWidth = 2.5;
      ctx.strokeStyle = "#ffc24b";
    } else {
      ctx.lineWidth = nd.role === "server" ? 3 : 1.8;
      ctx.strokeStyle = base;
    }
    ctx.stroke();
    ctx.setLineDash([]);
    if (nd.blocked) { // 封禁闪烁叉号
      const gl = 0.5 + 0.5 * Math.sin(performance.now() / 240);
      ctx.strokeStyle = `rgba(255,194,75,${0.5 + 0.5 * gl})`;
      ctx.lineWidth = 2;
      const k = nd.r * 0.45;
      ctx.beginPath();
      ctx.moveTo(nd.x - k, nd.y - k); ctx.lineTo(nd.x + k, nd.y + k);
      ctx.moveTo(nd.x + k, nd.y - k); ctx.lineTo(nd.x - k, nd.y + k);
      ctx.stroke();
    }
    // 标签
    ctx.font = nd.role === "server" ? "bold 11px monospace" : "10px monospace";
    ctx.textAlign = "center";
    ctx.fillStyle = nd.role === "server" ? "#35d0ff" : "#c6d6ef";
    const label = nd.role === "server" ? "业务服务器\n192.168.1.10"
      : (nd.role === "attacker" ? "攻击源 " + nd.id : "用户 " + nd.id);
    label.split("\n").forEach((line, li) => {
      ctx.fillText(line, nd.x, nd.y + nd.r + 12 + li * 12);
    });
    if (nd.role === "attacker" && nd.attacks > 0) {
      ctx.font = "9px monospace";
      ctx.fillStyle = "#ff9aa2";
      ctx.fillText("告警×" + nd.attacks, nd.x, nd.y - nd.r - 6);
    }
  });

  // ---- 图例与等待提示
  ctx.font = "10px sans-serif"; ctx.textAlign = "left"; ctx.fillStyle = "#8ba3c7";
  ctx.fillText("■ 攻击源(203.0.113.x)  ■ 内网用户(10.10.0.x)  ■ 业务服务器 192.168.1.10", 20, LOGICAL_H - 12);
  if (!snap.links || !snap.links.length) {
    ctx.font = "14px sans-serif"; ctx.textAlign = "center"; ctx.fillStyle = "#5b7194";
    ctx.fillText("等待实时流量…", LOGICAL_W / 2, LOGICAL_H / 2);
  }
  ctx.restore();
}

// ------------------------------------------------------------- 趋势小图
function drawSpark(snap) {
  const sp = (snap.spark || []);
  if (!state.spark) {
    const sc = setupCanvas(els.spark, els.spark.parentElement);
    state.spark = { ctx: els.spark.getContext("2d"), ...sc };
  }
  const { ctx, sx, sy } = state.spark;
  const W = els.spark.width, H = els.spark.height;
  ctx.clearRect(0, 0, W, H); ctx.save(); ctx.scale(sx, sy);
  const lw = 900, lh = 64;
  // 相邻采样差 => 每秒事件数/封禁数
  const flows = [], blocks = [];
  for (let i = 1; i < sp.length; i++) {
    flows.push(Math.max(0, sp[i].flows - sp[i - 1].flows));
    blocks.push(Math.max(0, sp[i].blocks - sp[i - 1].blocks));
  }
  const maxV = Math.max(10, ...flows);
  ctx.strokeStyle = "#35d0ff"; ctx.lineWidth = 2;
  ctx.beginPath();
  flows.forEach((v, i) => {
    const x = (i / Math.max(1, flows.length - 1)) * (lw - 20) + 10;
    const y = lh - 6 - (v / maxV) * (lh - 16);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = "#ffc24b";
  blocks.forEach((v, i) => {
    if (v <= 0) return;
    const x = (i / Math.max(1, blocks.length - 1)) * (lw - 20) + 10;
    ctx.fillRect(x, lh - 6, 2.4, -Math.min(26, v * 10));
  });
  ctx.font = "9px sans-serif"; ctx.fillStyle = "#8ba3c7"; ctx.textAlign = "left";
  ctx.fillText("每秒流量(蓝) / 每秒封禁(黄点柱)", 8, 10);
  ctx.restore();
}

// ========================================================= 顶栏与告警 toast
function renderTop(snap) {
  const s = snap.stats || {};
  const th = snap.threat_level || "safe";
  els.threatBox.className = "threat " + th;
  els.threatLabel.textContent = th === "safe" ? "安全" : th === "warning" ? "威胁" : "严重攻击";
  els.kFlows.textContent = fmt(s.flows);
  els.kAlerts.textContent = fmt(s.alerts);
  els.kBlocks.textContent = fmt(s.blocks);
  els.kRate.textContent = Math.round((s.attack_rate || 0) * 100) + "%";
  els.kRecall.textContent = s.recall !== undefined ? Math.round(s.recall * 100) + "%" : "—";
  els.kRecall.className = (s.recall || 0) >= 0.8 ? "ok" : "warn";
  // 新封禁/告警 toast
  (snap.events || []).forEach((e) => {
    if (e.seq > state.seenSeq) {
      state.seenSeq = e.seq;
      if (e.action === "block") toast("⛔ 已自动封禁 " + e.src, "block");
      else if (e.attack) {
        const step = Math.floor(e.seq / 25);
        if (step !== state._lastToastStep) {
          state._lastToastStep = step;
          toast(`⚠ 攻击: ${VERDICT_ZH[e.verdict] || e.verdict} @ ${e.src} (${Math.round(e.score * 100)}%)`);
        }
      }
    }
  });
}

function toast(text, cls) {
  const div = document.createElement("div");
  div.className = "toast " + (cls || "");
  div.textContent = text;
  els.toasts.appendChild(div);
  while (els.toasts.childNodes.length > 6) els.toasts.removeChild(els.toasts.firstChild);
  setTimeout(() => div.remove(), 2700);
}

// ========================================================= 攻击日志
function appendLog(snap) {
  (snap.events || []).slice().reverse().forEach((e) => {
    if (e.seq <= state.logSeq) return;
    state.logSeq = e.seq;
    const f = els.logFilter.value;
    if (f === "attack" && !e.attack) return;
    if (f === "block" && e.action !== "block") return;
    if (["dos", "probe", "r2l", "u2r"].includes(f) && e.verdict !== f) return;
    const tr = document.createElement("tr");
    const d = new Date(e.ts * 1000);
    const time = d.toTimeString().slice(0, 8);
    const act = e.action === "block" ? "⛔ 自动封禁" : (e.attack ? "⚠ 告警" : "放行");
    tr.innerHTML =
      `<td>${e.seq}</td><td>${time}</td><td>${esc(e.src)}</td><td>${esc(e.dst)}</td>` +
      `<td class="${e.attack ? "attack" : "ok"}">${VERDICT_ZH[e.verdict] || esc(e.verdict)}</td>` +
      `<td>${(e.score * 100).toFixed(1)}%</td>` +
      `<td class="${e.action === "block" ? "cell-block" : e.attack ? "warn" : "ok"}">${act}</td>`;
    els.logBody.prepend(tr);
    while (els.logBody.childNodes.length > 300) els.logBody.removeChild(els.logBody.lastChild);
  });
}

$("btnClearLog").addEventListener("click", () => { els.logBody.innerHTML = ""; });
els.logFilter.addEventListener("change", () => { els.logBody.innerHTML = ""; state.logSeq = 0; });

// ========================================================= 防火墙
async function loadFirewall() {
  const rules = await api("/api/firewall");
  els.fwBody.innerHTML = "";
  rules.forEach((r) => {
    const tr = document.createElement("tr");
    const proto = r.protocol === "any" ? "any" : r.protocol + (r.dport ? "/" + r.dport : "");
    tr.innerHTML =
      `<td class="${r.action === "deny" ? "attack" : "ok"}">${r.action}</td>` +
      `<td>${esc(r.src_ip)}</td><td>${esc(proto)}</td>` +
      `<td>${esc(r.source)}</td>` +
      `<td><span class="switch" data-id="${esc(r.id)}">${r.enabled ? "✔ 启用" : "✘ 停用"}</span></td>` +
      `<td><span class="del" data-id="${esc(r.id)}" title="删除">✕</span></td>`;
    tr.querySelector(".switch").addEventListener("click", async (ev) => {
      const id = ev.target.dataset.id;
      const cur = rules.find((x) => x.id === id);
      await api("/api/firewall/toggle", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, enabled: !cur.enabled }),
      });
      loadFirewall();
    });
    tr.querySelector(".del").addEventListener("click", async (ev) => {
      await api("/api/firewall/delete", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: ev.target.dataset.id }),
      });
      loadFirewall();
    });
    els.fwBody.appendChild(tr);
  });
}

els.fwForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const rule = {
    src_ip: els.fwSrc.value.trim(), action: els.fwAction.value,
    protocol: els.fwProto.value, dport: els.fwPort.value.trim(),
    note: els.fwNote.value.trim(),
  };
  if (!rule.src_ip) return;
  await api("/api/firewall", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(rule),
  });
  els.fwSrc.value = els.fwPort.value = els.fwNote.value = "";
  await loadFirewall();
});

$("btnScript").addEventListener("click", async () => {
  if (!els.fwScript.classList.contains("hidden")) { els.fwScript.classList.add("hidden"); return; }
  const { script } = await api("/api/firewall/script");
  els.fwScript.textContent = script || "# 暂无启用中的 deny 规则";
  els.fwScript.classList.remove("hidden");
});

// ========================================================= AI 建议
function renderAdvice(items) {
  const list = items || [];
  els.adviceList.innerHTML = "";
  if (!list.length) {
    els.adviceList.innerHTML = '<div class="advice info"><div class="t">态势正常</div>' +
      '<div class="d">暂无告警压力, AI 将持续监控。</div></div>';
  }
  list.forEach((a) => {
    const key = a.title + a.ts;
    const card = document.createElement("div");
    card.className = "advice " + a.level;
    card.innerHTML =
      `<span class="lv">${LEVEL_ZH[a.level] || a.level} · 置信 ${Math.round((a.confidence || 0) * 100)}%</span>` +
      `<div class="t">${esc(a.title)}</div><div class="d">${esc(a.detail)}</div>` +
      `<div class="a">→ ${esc(a.recommended_action)}</div>` +
      `<div class="src">依据: ${esc(a.source)}</div>`;
    els.adviceList.appendChild(card);
  });
}

async function loadAdvice() {
  const data = await api("/api/advisor");
  renderAdvice(data.rules);
  els.llmBadge.textContent = data.llm_available ? "规则引擎 + LLM 在线" : "规则引擎(离线)";
  els.llmBadge.className = "badge" + (data.llm_available ? " on" : "");
}

$("btnAskAi").addEventListener("click", async () => {
  els.btnAskAi.disabled = true;
  els.aiAnswer.classList.remove("hidden");
  els.aiAnswer.textContent = "AI 分析中, 请稍候…(规则引擎建议会即时给出)";
  try {
    const res = await api("/api/advisor/llm", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: els.aiQuestion.value.trim() }),
    });
    els.aiAnswer.textContent = res.ok
      ? res.text
      : "⚠ " + res.error + "。若配置了 DEEPSEEK_API_KEY 后将自动启用在线 AI。";
  } catch (err) {
    els.aiAnswer.textContent = "请求失败: " + err.message;
  } finally {
    els.btnAskAi.disabled = false;
  }
});

// ========================================================= 控制
$("btnPause").addEventListener("click", async () => {
  state.paused = !state.paused;
  els.btnPause.textContent = state.paused ? "▶ 继续" : "⏸ 暂停";
  await api("/api/control", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ paused: state.paused }),
  });
});
$("btnSpeed").addEventListener("click", async () => {
  const next = state.speed >= 150 ? 20 : state.speed * 2;
  state.speed = next;
  els.btnSpeed.textContent = "速率 " + next + "/s";
  await api("/api/control", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ speed: next }),
  });
});

// ========================================================= 主循环
async function refresh() {
  try {
    const snap = await api("/api/snapshot");
    state.speed = snap.speed; state.paused = snap.paused;
    els.btnPause.textContent = snap.paused ? "▶ 继续" : "⏸ 暂停";
    els.btnSpeed.textContent = "速率 " + Math.round(snap.speed) + "/s";
    renderTop(snap);
    appendLog(snap);
    drawNet(snap);
    drawSpark(snap);
  } catch (err) {
    console.warn("refresh failed", err);
  }
}

function animate() {
  if (state.net) requestAnimationFrame(() => { drawNet(window.__snap || {}); });
  requestAnimationFrame(animate);
}

async function boot() {
  setInterval(refresh, 1000);
  setInterval(loadFirewall, 4000);
  setInterval(loadAdvice, 4000);
  await loadFirewall();
  await loadAdvice();
  // 动画: 周期取最新快照重绘(带脉冲)
  setInterval(async () => {
    try { window.__snap = await api("/api/snapshot"); }
    catch (e) { /* 忽略瞬时错误 */ }
  }, 1500);
  animate();
}

window.addEventListener("resize", () => { state.net = null; state.spark = null; });
document.addEventListener("DOMContentLoaded", boot);
