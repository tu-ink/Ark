"""可视化 Dashboard: 实时攻防网络仿真 + Web 界面 + REST API。

功能:
    - 实时攻防网络图: 攻击源(203.0.113.x)/内网用户(10.10.0.x) -> 业务服务器
      (192.168.1.10) 的流量关系, 由前端的 canvas 动画绘制;
    - 防火墙在线编辑: 增删/启停 deny 规则并同步导出防火墙脚本;
    - 攻击日志: 检测事件/告警/自动封禁流水;
    - AI 智能建议: 规则引擎(离线可用) + 可选 LLM(DeepSeek)增强。

运行: python -m arkids dashboard --model models/arkids_rf.joblib --port 8642
"""
from __future__ import annotations

import json
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pandas as pd

from .advisor import AIAdvisor
from .config import DATA_DIR, KDD_FEATURES, LABEL_COL, is_attack
from .dataset import generate_demo_flows
from .defense import DefenseEngine, DefenseEvent
from .detector import FlowDetector
from .firewall import FirewallRule, FirewallStore

WEBUI_DIR = Path(__file__).resolve().parent / "webui"
DEFAULT_DATA = DATA_DIR / "demo_eval.csv"
SERVER_IP = "192.168.1.10"
USER_POOL = 6
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
        ".ico": "image/x-icon"}


def _mk_event(seq: int, src: str, verdict: str, score: float,
              attack: bool, truth: bool | None, ts: float) -> dict:
    return {"seq": seq, "ts": ts, "src": src, "dst": SERVER_IP,
            "verdict": verdict, "score": round(float(score), 4),
            "attack": bool(attack), "truth": truth, "action": None}


class LiveEngine:
    """后台仿真线程: 持续回放流量, 驱动检测与防御, 维护可查询的态势状态。"""

    def __init__(self, model_path: str, data_path: str | None = None,
                 threshold: float = 0.5, attacker_pool: int = 5,
                 block_hits: int = 3, window_sec: float = 60.0,
                 state_dir: str = "run", seed: int = 7, speed: float = 40.0) -> None:
        self.detector = FlowDetector.load(model_path, threshold=threshold)
        self.engine = DefenseEngine(state_dir=state_dir, block_hits=block_hits,
                                    window_sec=window_sec)
        self.fw = FirewallStore(state_dir=state_dir)
        self.advisor = AIAdvisor(threshold=threshold)
        self.attacker_pool = attacker_pool
        self.speed = float(speed)
        self.paused = False
        self.seq = 0
        self.flows: pd.DataFrame | None = None
        self._load_data(data_path)
        # 状态容器
        self._lock = threading.Lock()
        self.events: deque[dict] = deque(maxlen=600)
        self.ip_state: dict[str, dict] = {}
        self.spark: deque[dict] = deque(maxlen=120)
        self.counters = {"flows": 0, "alerts": 0, "blocks": 0,
                         "tp": 0, "fp": 0, "tn": 0, "fn": 0}
        self._last_spark_ts = time.time()
        self._thread: threading.Thread | None = None

    def _load_data(self, data_path: str | None) -> None:
        if data_path and Path(data_path).exists():
            df = pd.read_csv(data_path)
        else:
            df = generate_demo_flows(n=1200, seed=1234)  # 内存兜底
        if LABEL_COL in df.columns:
            self.truth: list[bool | None] = [bool(is_attack(v)) for v in df[LABEL_COL]]
        else:
            self.truth = [None] * len(df)
        self.flows = df.reset_index(drop=True)
        self._flow_index = 0
        self._row_index = 0  # 用于轮换正常用户与攻击源

    # ------------------------------------------------------------- 仿真推进
    def _next_row(self):
        """返回 (row, truth, idx); 数据为空时返回 (None, None, -1)。"""
        df = self.flows
        if df is None or len(df) == 0:
            return None, None, -1
        if self._flow_index >= len(df):
            self._flow_index = 0
            self._row_index += 100000  # 每轮更换端点分配, 产生“新会话”
        row = df.iloc[self._flow_index]
        idx = self._flow_index + self._row_index
        truth = self.truth[self._flow_index] if self.truth else None
        self._flow_index += 1
        return row, truth, idx

    def _endpoints(self, attack: bool, idx: int) -> str:
        if attack:
            return f"203.0.113.{10 + idx % self.attacker_pool}"
        return f"10.10.0.{1 + idx % USER_POOL}"

    def tick(self) -> dict | None:
        """产生并处理 1 条流, 返回事件字典(无数据返回 None)。"""
        row, truth, idx = self._next_row()
        if row is None:
            return None
        flow = {c: row[c] for c in KDD_FEATURES}
        det = self.detector.detect_one(flow)
        src = self._endpoints(det.attack, idx)
        ev = self.events
        with self._lock:
            self.seq += 1
            self.counters["flows"] += 1
            if truth is True:
                self.counters["tp" if det.attack else "fn"] += 1
            elif truth is False:
                self.counters["tn" if not det.attack else "fp"] += 1
            stamp = time.time()
            record = _mk_event(self.seq, src, det.verdict, det.score,
                               det.attack, truth, stamp)
            defense_ev = DefenseEvent(src_ip=src, dst_ip=SERVER_IP,
                                      verdict=det.verdict, score=det.score,
                                      attack=det.attack, ts=stamp)
            engine_out = self.engine.handle(defense_ev)
            if engine_out and engine_out.get("action") == "block":
                record["action"] = "block"
                self.counters["blocks"] += 1
                # 自动封禁 -> 同步到防火墙规则库
                self.fw.add(FirewallRule(src_ip=src, action="deny", protocol="any",
                                         note="AI防御自动封禁", source="auto"))
                self._bump_ip(src, det, attack=True, blocked=True, stamp=stamp)
            else:
                if det.attack:
                    self.counters["alerts"] += 1
                self._bump_ip(src, det, attack=det.attack, blocked=False, stamp=stamp)
            self.events.append(record)
            # 每秒追加一个态势采样点
            now = time.time()
            if now - self._last_spark_ts >= 1.0:
                self.spark.append({"t": now, "flows": self.counters["flows"],
                                   "attacks": self.counters["tp"] + self.counters["fn"] + self.counters["fp"],
                                   "alerts": self.counters["alerts"],
                                   "blocks": self.counters["blocks"]})
                self._last_spark_ts = now
            return dict(record)

    def _bump_ip(self, src: str, det, attack: bool, blocked: bool, stamp: float) -> None:
        st = self.ip_state.setdefault(src, {"src": src, "flows": 0, "attacks": 0,
                                            "alerts": 0, "blocked": False,
                                            "verdicts": Counter(), "last": stamp})
        st["flows"] += 1
        st["last"] = stamp
        if attack:
            st["attacks"] += 1
            st["verdicts"][det.verdict] += 1
            st["alerts"] += 1
        if blocked:
            st["blocked"] = True

    def run_forever(self) -> None:
        """后台线程主循环。"""
        while True:
            if self.paused:
                time.sleep(0.1)
                continue
            self.tick()
            time.sleep(max(0.001, 1.0 / max(self.speed, 1.0)))

    def start(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self.run_forever, daemon=True,
                                            name="arkids-live")
            self._thread.start()

    # ------------------------------------------------------------- 快照构建
    def snapshot(self, max_events: int = 120) -> dict:
        with self._lock:
            events = list(self.events)[-max_events:]
            ip_state = {k: {**v, "verdicts": dict(v["verdicts"])}
                        for k, v in self.ip_state.items()}
            counters = dict(self.counters)
            spark = list(self.spark)
            seq = self.seq
        flows_w = len(events)
        attacks_w = sum(1 for e in events if e["attack"])
        attack_rate = attacks_w / max(flows_w, 1)
        thr = "safe"
        if attack_rate > 0.5 or counters["blocks"] > 0:
            thr = "critical"
        elif attack_rate > 0.2:
            thr = "warning"
        tp, fp, tn, fn = (counters[k] for k in ("tp", "fp", "tn", "fn"))
        hits = tp + fp + tn + fn
        acc = (tp + tn) / max(hits, 1)
        recall = tp / max(tp + fn, 1)
        # 图节点与边(由近期事件聚合)
        nodes, links = self._graph(events)
        return {
            "ts": time.time(), "seq": seq, "paused": self.paused,
            "speed": self.speed, "threshold": self.detector.threshold,
            "threat_level": thr, "server": SERVER_IP,
            "stats": {
                "flows": counters["flows"], "alerts": counters["alerts"],
                "blocks": counters["blocks"], "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "accuracy": round(acc, 4), "recall": round(recall, 4),
                "flows_window": flows_w, "attacks_window": attacks_w,
                "attack_rate": round(attack_rate, 4),
                "active_srcs": len(ip_state),
                "blocked_ips": [s for s, st in ip_state.items() if st["blocked"]],
            },
            "spark": spark[-90:],
            "nodes": nodes, "links": links,
            "events": events, "ips": ip_state,
        }

    def _graph(self, events: list) -> tuple[list, list]:
        edges: dict[tuple[str, str], dict] = {}
        for e in events:
            key = (e["src"], e["dst"])
            ed = edges.setdefault(key, {"src": e["src"], "dst": e["dst"],
                                        "count": 0, "attacks": 0,
                                        "last_verdict": "normal", "last_score": 0.0,
                                        "blocked": False})
            ed["count"] += 1
            if e["attack"]:
                ed["attacks"] += 1
                ed["last_verdict"] = e["verdict"]
                ed["last_score"] = e["score"]
            if e["action"] == "block":
                ed["blocked"] = True
        nodes: dict[str, dict] = {}
        for (src, dst) in edges:
            nodes.setdefault(src, {"id": src, "role": "attacker" if src.startswith("203.0.113.")
                                   else "user"})
            nodes.setdefault(dst, {"id": dst, "role": "server"})
        links = [{"src": v["src"], "dst": v["dst"], "count": v["count"],
                  "attacks": v["attacks"], "verdict": v["last_verdict"],
                  "score": v["last_score"], "blocked": v["blocked"]}
                 for v in edges.values()]
        return list(nodes.values()), links

    def advisor_context(self) -> dict:
        snap = self.snapshot(max_events=200)
        return {
            "stats": snap["stats"], "events": snap["events"],
            "blocklist": snap["stats"]["blocked_ips"],
            "fw_rules": self.fw.rules(), "server": SERVER_IP,
            "threshold": self.threshold_for_advisor(),
        }

    def threshold_for_advisor(self) -> float:
        return float(self.detector.threshold)

    def control(self, paused: bool | None = None, speed: float | None = None) -> dict:
        if paused is not None:
            self.paused = bool(paused)
        if speed and speed > 0:
            self.speed = float(speed)
        return {"paused": self.paused, "speed": self.speed}


class _Handler(BaseHTTPRequestHandler):
    server_version = "ArkIDS-Dashboard/0.1"

    # ------------------------------------------------------------- 路由
    def do_GET(self):  # noqa: N802
        svc = self.server.service  # type: ignore[attr-defined]
        path = self.path.split("?")[0]
        if path == "/health":
            self._json({"status": "ok", "service": "arkids-dashboard"})
        elif path in ("/", "/index.html", "/app.js", "/style.css", "/favicon.ico"):
            self._static(path)
        elif path == "/api/snapshot":
            self._json(svc.live.snapshot())
        elif path == "/api/events":
            n = int(self._query().get("n", ["150"])[0])
            with svc.live._lock:
                evs = list(svc.live.events)[-n:]
            self._json(evs)
        elif path == "/api/firewall":
            self._json(svc.live.fw.rules())
        elif path == "/api/firewall/script":
            self._json({"script": svc.live.fw.script_text()})
        elif path == "/api/advisor":
            ctx = svc.live.advisor_context()
            self._json({"rules": svc.live.advisor.rules(ctx),
                        "llm_available": svc.live.advisor.llm_available})
        else:
            self._json({"error": "not found"}, code=404)

    def do_POST(self):  # noqa: N802
        svc = self.server.service  # type: ignore[attr-defined]
        body = self._read_json()
        if body is None:
            return
        path = self.path.split("?")[0]
        if path == "/api/control":
            self._json(svc.live.control(
                paused=body.get("paused"), speed=body.get("speed")))
        elif path == "/api/firewall":
            rule = FirewallRule(
                src_ip=str(body.get("src_ip", "")).strip(),
                action=str(body.get("action", "deny")),
                protocol=str(body.get("protocol", "any")),
                dport=body.get("dport", ""), note=str(body.get("note", "")),
                source="manual")
            if not rule.src_ip:
                self._json({"error": "src_ip required"}, code=400)
                return
            saved = svc.live.fw.add(rule)
            self._json(saved.to_dict())
        elif path == "/api/firewall/toggle":
            rule = svc.live.fw.update(str(body.get("id", "")),
                                      enabled=bool(body.get("enabled", True)))
            self._json(rule.to_dict() if rule else {"error": "rule not found"}, code=200 if rule else 404)
        elif path == "/api/firewall/delete":
            ok = svc.live.fw.delete(str(body.get("id", "")))
            self._json({"ok": ok}, code=200 if ok else 404)
        elif path == "/api/advisor/llm":
            ctx = svc.live.advisor_context()
            res = svc.live.advisor.llm_advice(ctx, str(body.get("question", "")))
            self._json(res)
        else:
            self._json({"error": "not found"}, code=404)

    # ------------------------------------------------------------- 工具
    def _query(self) -> dict:
        from urllib.parse import parse_qs
        q = self.path.split("?", 1)
        return parse_qs(q[1]) if len(q) > 1 else {}

    def _static(self, path: str) -> None:
        name = "index.html" if path == "/" else path.lstrip("/")
        file = (WEBUI_DIR / name)
        if not file.exists():
            self._json({"error": "not found"}, code=404)
            return
        mime = MIME.get(file.suffix, "text/plain")
        payload = file.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) or b"{}"
            return json.loads(raw.decode("utf-8"))
        except Exception:
            self._json({"error": "invalid json"}, code=400)
            return None

    def _json(self, obj, code: int = 200) -> None:
        payload = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args) -> None:
        pass  # 控制台静默, 由 UI 呈现态势


class DashboardService:
    def __init__(self, model_path: str, data_path: str | None = None,
                 threshold: float = 0.5, attacker_pool: int = 5,
                 block_hits: int = 3, window_sec: float = 60.0,
                 state_dir: str = "run", seed: int = 7,
                 speed: float = 40.0) -> None:
        self.live = LiveEngine(model_path=model_path, data_path=data_path,
                               threshold=threshold, attacker_pool=attacker_pool,
                               block_hits=block_hits, window_sec=window_sec,
                               state_dir=state_dir, seed=seed, speed=speed)

    def serve(self, host: str = "127.0.0.1", port: int = 8642,
              open_browser: bool = False) -> None:
        self.live.start()
        httpd = ThreadingHTTPServer((host, port), _Handler)
        httpd.service = self  # type: ignore[attr-defined]
        url = f"http://{host}:{port}"
        print(f"ArkIDS 可视化控制台: {url}  (Ctrl+C 退出)")
        if open_browser:
            import threading as _t
            import webbrowser as _wb
            _t.Timer(1.2, lambda: _wb.open(url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n服务已停止")
