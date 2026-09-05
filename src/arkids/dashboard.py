"""可视化监控服务: 真实流量采集 → 实时分析 → Web 控制台。

数据来源(真实, 不构造):
    1) 本机网卡实时抓包: tshark(内嵌 Wireshark 命令行引擎) `-F pcap -w -`
       → 内建 RawPcapReader 解析, 同步落盘真实 .pcap;
    2) 用户提供的真实抓包文件(.pcap/.pcapng): tshark 转码回放, 或纯内建解析。
无 tshark / 未选源时界面显示“等待真实流量”, 不播放任何仿真数据。

运行: python -m arkids dashboard [--interface eth0 | --pcap file.pcap]
"""
from __future__ import annotations

import json
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .advisor import AIAdvisor
from .capture import (CaptureSource, PacketRecord, find_tshark, find_wireshark,
                      list_interfaces, open_capture_file, tshark_version)
from .config import PROJECT_ROOT
from .firewall import FirewallRule, FirewallStore

WEBUI_DIR = Path(__file__).resolve().parent / "webui"
DEFAULT_SAVE_DIR = PROJECT_ROOT / "run" / "captures"
MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".ico": "image/x-icon"}

INTERNAL_PREFIX = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.2", "127.", "169.254.", "::1", "fe80:", "fd", "fc")


def _is_internal(ip: str) -> bool:
    if not ip:
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (IndexError, ValueError):
            return True
    return ip.startswith(INTERNAL_PREFIX) or ip == "::"


def _fmt_ts(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int((t % 1) * 1000):03d}"


class LiveMonitor:
    """真实流量监控核心: 抓包线程 + 流分析 + 包/告警缓冲 + 采样。"""

    def __init__(self, state_dir: str = "run") -> None:
        self.tshark = find_tshark()
        self.wireshark = find_wireshark()
        self.ifaces = list_interfaces(self.tshark)
        self.fw = FirewallStore(state_dir=state_dir)
        self.advisor = AIAdvisor()
        self.source: CaptureSource | None = None
        self.mode = "idle"            # idle | live | pcap | error
        self.last_error = ""
        self.cap_filter = ""
        self.display_filter = ""
        self.auto_block = False
        self.saved_path = ""
        self.source_label = ""
        self.started_at: float | None = None
        self._lock = threading.Lock()
        self.packets: deque[dict] = deque(maxlen=600)
        self.detections: deque[dict] = deque(maxlen=250)
        self.samples: deque[dict] = deque(maxlen=240)
        self.seq = 0
        self._watchdog_stop = threading.Event()
        self._watcher: threading.Thread | None = None
        from .capture import FlowAnalyzer  # noqa: PLC0415
        self.analyzer = FlowAnalyzer(window_sec=60.0)
        self._last_sample_ts = time.time()
        self._last_packets = 0
        self._last_dets = 0
        self._packets_buf: deque[float] = deque(maxlen=240)
        self._dets_buf: deque[float] = deque(maxlen=240)

    # ------------------------------------------------------------- 生命周期
    def start_live(self, interface: str | None = None) -> dict:
        if self.source and self.source.is_alive():
            return {"ok": False, "error": "已在抓包中, 请先停止"}
        if self.tshark is None:
            return {"ok": False,
                    "error": "未找到 Wireshark/tshark。请安装 Wireshark(含 tshark 与 "
                             "Npcap), 或改用“回放抓包文件”加载真实 pcap。"}
        if not interface:
            cands = [i["name"] for i in self.ifaces
                     if "loopback" not in i["description"].lower()
                     and "virtual" not in i["description"].lower()]
            interface = cands[0] if cands else (self.ifaces[0]["name"] if self.ifaces else None)
        if not interface:
            return {"ok": False, "error": "未检测到可用网卡(可能需要管理员权限)。"}
        self._reset_analysis()
        self.mode = "live"
        self.source_label = f"实时抓包: {interface}"
        self.cap_filter = self.cap_filter
        self.source = CaptureSource(
            mode="live", target=interface, cap_filter=self.cap_filter,
            tshark=self.tshark, save_dir=str(DEFAULT_SAVE_DIR),
            on_record=self._on_record, on_error=self._on_error)
        self.source.start()
        self._start_watcher()
        self.saved_path = ""
        return {"ok": True, "mode": "live", "interface": interface}

    def start_pcap(self, path: str, display_filter: str = "") -> dict:
        if self.source and self.source.is_alive():
            return {"ok": False, "error": "正在抓包/回放, 请先停止"}
        p = Path(path)
        if not p.exists():
            return {"ok": False, "error": f"文件不存在: {path}"}
        if not p.suffix.lower() in (".pcap", ".pcapng", ".cap"):
            return {"ok": False, "error": "请选择 .pcap/.pcapng 抓包文件"}
        self._reset_analysis()
        self.mode = "pcap"
        self.source_label = f"回放文件: {p.name}"
        self.display_filter = display_filter
        self.source = CaptureSource(
            mode="pcap", target=str(p), display_filter=display_filter,
            tshark=self.tshark, save_dir=None,
            on_record=self._on_record, on_error=self._on_error)
        self.source.start()
        self._start_watcher()
        self.saved_path = str(p)
        return {"ok": True, "mode": "pcap", "file": str(p)}

    def stop(self) -> dict:
        if self.source:
            self.source.stop()
            self.source = None
        self._watchdog_stop.set()
        self.mode = "idle"
        return {"ok": True}

    def _reset_analysis(self) -> None:
        with self._lock:
            self.packets.clear()
            self.detections.clear()
            self.samples.clear()
        from .capture import FlowAnalyzer  # noqa: PLC0415
        self.analyzer = FlowAnalyzer(window_sec=60.0)
        self._last_sample_ts = time.time()
        self._last_packets = 0
        self._last_dets = 0
        self._packets_buf.clear()
        self._dets_buf.clear()
        self.started_at = time.time()
        self.last_error = ""

    def _on_error(self, msg: str) -> None:
        self.last_error = msg
        self.mode = "error" if self.source and self.source.mode == "live" else self.mode
        if self.source and not self.source.is_alive():
            self.source = None

    # ------------------------------------------------------------- 数据回调
    def _on_record(self, rec: PacketRecord) -> None:
        try:
            brief = self.analyzer.ingest(rec)
            pkt = rec.to_dict()
            pkt["f"] = brief
            with self._lock:
                self.seq += 1
                pkt["seq"] = self.seq
                self.packets.append(pkt)
        except Exception:
            pass

    def _start_watcher(self) -> None:
        self._watchdog_stop.clear()
        if self._watcher and self._watcher.is_alive():
            return
        self._watcher = threading.Thread(target=self._watch_loop, daemon=True,
                                         name="arkids-watch")
        self._watcher.start()

    def _watch_loop(self) -> None:
        while not self._watchdog_stop.is_set():
            time.sleep(1.0)
            if self.source is None or not self.source.is_alive():
                if self.source is not None:
                    self._on_error(self.source.last_error or "采集已结束")
                    self.source = None
                    self.mode = "idle"
                continue
            now = time.time()
            # 速率采样
            pcount = self.analyzer.counter["packets"]
            dt = max(now - self._last_sample_ts, 1e-3)
            self._packets_buf.append((now, (pcount - self._last_packets) / dt))
            self._last_packets = pcount
            det_count = len(self.detections)
            self._dets_buf.append((now, max(0, det_count - self._last_dets) / dt))
            self._last_dets = det_count
            self._last_sample_ts = now
            self.samples.append({"t": now, "pps": self._packets_buf[-1][1],
                                 "dps": self._dets_buf[-1][1]})
            # 周期性启发式检测
            for d in self.analyzer.detections(now):
                d["ts"] = now
                d["time"] = _fmt_ts(now)
                with self._lock:
                    self.detections.appendleft(d)
                if self.auto_block:
                    ip = d.get("src") or d.get("dst")
                    if ip and not self.fw.is_src_blocked(ip):
                        self.fw.add(FirewallRule(src_ip=ip, action="deny",
                                                 protocol="any",
                                                 note="自动联动: " + d["kind"],
                                                 source="auto"))
            if self.saved_path and self.source.mode == "live" and self.source.saved_path:
                self.saved_path = self.source.saved_path

    # ------------------------------------------------------------- 快照
    def meta(self) -> dict:
        src = self.source
        return {
            "mode": self.mode,
            "source": self.source_label,
            "last_error": self.last_error,
            "capturing": bool(src and src.is_alive()),
            "started_at": self.started_at,
            "packets_captured": self.analyzer.counter["packets"],
            "saved_path": self.saved_path,
            "auto_block": self.auto_block,
            "cap_filter": self.cap_filter,
            "display_filter": self.display_filter,
            "tools": {"tshark": str(self.tshark) if self.tshark else None,
                      "wireshark": str(self.wireshark) if self.wireshark else None,
                      "tshark_version": tshark_version(self.tshark)},
            "interfaces": self.ifaces,
            "save_dir": str(DEFAULT_SAVE_DIR),
        }

    def snapshot(self) -> dict:
        c = self.analyzer.counter
        now = time.time()
        recent_crit = [d for d in self.detections
                       if d["level"] == "critical" and now - d.get("ts", 0) < 60]
        recent_det = [d for d in self.detections if now - d.get("ts", 0) < 120]
        level = "critical" if recent_crit else ("warning" if recent_det else "safe")
        with self._lock:
            packets = list(self.packets)[-220:]
            detections = list(self.detections)[:120]
        nodes, links = self._graph()
        flows = self.analyzer.flows
        return {
            "ts": now,
            "meta": self.meta(),
            "threat_level": level,
            "stats": {
                "packets": c["packets"], "bytes": c["bytes_"],
                "flows_now": len(flows),
                "flows_total": self.analyzer.total_flows_seen,
                "tcp": c["tcp"], "udp": c["udp"], "icmp": c["icmp"],
                "detections": len(detections),
                "critical_now": len(recent_crit),
                "pps": round(self._packets_buf[-1][1], 1) if self._packets_buf else 0.0,
                "dps": round(self._dets_buf[-1][1], 2) if self._dets_buf else 0.0,
            },
            "nodes": nodes,
            "links": links,
            "packets": packets,
            "detections": detections,
            "spark": list(self.samples)[-150:],
            "top_hosts": self._top_hosts(12),
        }

    def _graph(self) -> tuple[list, list]:
        flows = self.analyzer.flows
        nodes: dict[str, dict] = {}
        links: list[dict] = []
        for f in flows.values():
            n = nodes.setdefault(f["src"], {"id": f["src"], "role": "internal"
                                            if _is_internal(f["src"]) else "external",
                                            "pkts": 0, "bytes": 0, "flows": 0})
            m = nodes.setdefault(f["dst"], {"id": f["dst"], "role": "internal"
                                            if _is_internal(f["dst"]) else "external",
                                            "pkts": 0, "bytes": 0, "flows": 0})
            n["pkts"] += f["pkts"]; n["bytes"] += f["bytes"]; n["flows"] += 1
            m["pkts"] += f["pkts"]; m["bytes"] += f["bytes"]; m["flows"] += 1
            links.append({"src": f["src"], "dst": f["dst"], "pkts": f["pkts"],
                          "bytes": f["bytes"], "proto": f["proto"],
                          "dport": f["dport"]})
        links.sort(key=lambda x: -x["pkts"])
        top = sorted(nodes.values(), key=lambda x: -x["pkts"])[:80]
        ids = {x["id"] for x in top}
        kept = [l for l in links if l["src"] in ids and l["dst"] in ids][:220]
        return top, kept

    def _top_hosts(self, k: int) -> list[dict]:
        hosts: dict[str, Counter] = {}
        for f in self.analyzer.flows.values():
            for ip, side in ((f["src"], "out"), (f["dst"], "in")):
                h = hosts.setdefault(ip, Counter())
                h["pkts"] += f["pkts"]
                h["bytes"] += f["bytes"]
                h[side] += f["pkts"]
        out = []
        for ip, h in hosts.items():
            out.append({"id": ip, "pkts": h["pkts"], "bytes": h["bytes"],
                        "in": h["in"], "out": h["out"],
                        "internal": _is_internal(ip)})
        out.sort(key=lambda x: -x["pkts"])
        return out[:k]

    # ------------------------------------------------------------- 建议
    def advice(self) -> list[dict]:
        meta = self.meta()
        out: list[dict] = []
        if not meta["tools"]["tshark"]:
            out.append({"level": "warn", "title": "未检测到 Wireshark/tshark",
                        "detail": "实时抓包需要 Wireshark(含 tshark 与 Npcap)。也可"
                                  "选择“.pcap 文件回放”加载真实抓包。",
                        "recommended_action": "安装 Wireshark 后刷新页面再启用实时抓包。",
                        "confidence": 1.0, "source": "system"})
        elif not self.source and not self.saved_path:
            out.append({"level": "info", "title": "等待真实流量",
                        "detail": "选择一个网卡开始抓包, 或加载真实 pcap 文件回放。",
                        "recommended_action": "在左上角数据源中选择接口或文件。",
                        "confidence": 1.0, "source": "system"})
        pending = [d for d in list(self.detections)[:8]]
        if pending:
            unblocked = [d for d in pending
                         if not self.fw.is_src_blocked(d.get("src") or d.get("dst") or "")]
            if unblocked and not self.auto_block:
                out.append({"level": "warn", "title": f"有 {len(unblocked)} 条威胁待处置",
                            "detail": "最新: " + " / ".join(d["title"] for d in unblocked[:3]),
                            "recommended_action": "在“威胁与处置”中对目标 IP 添加 deny 规则"
                                                  "(或开启自动联动保护)。",
                            "confidence": 0.9, "source": "detector"})
        if self.saved_path:
            out.append({"level": "info", "title": "可复核原始抓包",
                        "detail": f"真实数据包已保存/加载: {self.saved_path}",
                        "recommended_action": "用 Wireshark 打开该文件做人工复核。",
                        "confidence": 1.0, "source": "wireshark"})
        return out

    def advisor_context(self) -> dict:
        snap = self.snapshot()
        return {"stats": snap["stats"], "events": snap["detections"][:30],
                "top_hosts": snap["top_hosts"],
                "fw_rules": self.fw.rules(),
                "mode": self.mode, "source": self.source_label}


class _Handler(BaseHTTPRequestHandler):
    server_version = "ArkIDS-Dashboard/0.1"

    def do_GET(self):  # noqa: N802
        svc: DashboardService = self.server.service  # type: ignore[attr-defined]
        path = self.path.split("?")[0]
        if path == "/health":
            self._json({"status": "ok", "service": "arkids-dashboard",
                        "mode": svc.monitor.mode})
        elif path in ("/", "/index.html", "/app.js", "/style.css", "/favicon.ico"):
            self._static(path)
        elif path == "/api/meta":
            self._json(svc.monitor.meta())
        elif path == "/api/snapshot":
            self._json(svc.monitor.snapshot())
        elif path == "/api/packets":
            n = int(self._query().get("n", ["300"])[0])
            self._json({"packets": list(svc.monitor.packets)[-n:]})
        elif path == "/api/firewall":
            self._json(svc.monitor.fw.rules())
        elif path == "/api/firewall/script":
            self._json({"script": svc.monitor.fw.script_text()})
        elif path == "/api/advisor":
            rules = svc.monitor.advice()
            self._json({"rules": rules,
                        "llm_available": svc.monitor.advisor.llm_available})
        else:
            self._json({"error": "not found"}, code=404)

    def do_POST(self):  # noqa: N802
        svc: DashboardService = self.server.service  # type: ignore[attr-defined]
        path = self.path.split("?")[0]
        if path == "/api/upload-capture":   # 二进制上传, 不能走 JSON 解析
            name = Path(self._query().get("name", ["capture.pcap"])[0]).name
            if not name.lower().endswith((".pcap", ".pcapng", ".cap")):
                self._json({"ok": False, "error": "仅支持 .pcap/.pcapng/.cap"}, code=400)
                return
            up_dir = DEFAULT_SAVE_DIR / "uploads"
            up_dir.mkdir(parents=True, exist_ok=True)
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = self.rfile.read(length) if length else b""
            except Exception:
                self._json({"ok": False, "error": "读取上传内容失败"}, code=400)
                return
            if not data:
                self._json({"ok": False, "error": "上传内容为空"}, code=400)
                return
            target = up_dir / name
            target.write_bytes(data)
            self._json({"ok": True, "path": str(target), "bytes": len(data)})
            return
        body = self._read_json()
        if body is None:
            return
        m = svc.monitor
        if path == "/api/capture":
            action = body.get("action")
            if action == "start-live":
                if body.get("filter") is not None:
                    m.cap_filter = str(body["filter"])
                self._json(m.start_live(body.get("interface")))
            elif action == "start-pcap":
                m.display_filter = str(body.get("display_filter", ""))
                self._json(m.start_pcap(str(body.get("file", "")),
                                        m.display_filter))
            elif action == "stop":
                self._json(m.stop())
            elif action == "auto-block":
                m.auto_block = bool(body.get("enabled", False))
                self._json({"ok": True, "auto_block": m.auto_block})
            elif action == "refresh":
                m.ifaces = list_interfaces(m.tshark)
                self._json({"ok": True, "interfaces": m.ifaces})
            else:
                self._json({"error": "unknown action"}, code=400)
        elif path == "/api/tools/open":
            res = open_capture_file(
                m.wireshark,
                path=str(body.get("file") or "") if body.get("file") else "",
                interface=str(body.get("interface") or ""))
            self._json(res)
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
            self._json(m.fw.add(rule).to_dict())
        elif path == "/api/firewall/toggle":
            rule = m.fw.update(str(body.get("id", "")),
                               enabled=bool(body.get("enabled", True)))
            self._json(rule.to_dict() if rule else {"error": "not found"},
                       code=200 if rule else 404)
        elif path == "/api/firewall/delete":
            ok = m.fw.delete(str(body.get("id", "")))
            self._json({"ok": ok}, code=200 if ok else 404)
        elif path == "/api/advisor/llm":
            res = m.advisor.llm_advice(m.advisor_context(),
                                       str(body.get("question", "")))
            self._json(res)
        else:
            self._json({"error": "not found"}, code=404)

    # ------------------------------------------------------------- 工具方法
    def _query(self) -> dict:
        from urllib.parse import parse_qs
        q = self.path.split("?", 1)
        return parse_qs(q[1]) if len(q) > 1 else {}

    def _static(self, path: str) -> None:
        name = "index.html" if path == "/" else path.lstrip("/")
        file = WEBUI_DIR / name
        if not file.exists():
            self._json({"error": "not found"}, code=404)
            return
        payload = file.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(file.suffix, "text/plain"))
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
        pass


class DashboardService:
    """启动参数仅为 UI 层引导; 真正数据由 LiveMonitor 从真实来源采集。"""

    def __init__(self, state_dir: str = "run") -> None:
        self.monitor = LiveMonitor(state_dir=state_dir)

    def serve(self, host: str = "127.0.0.1", port: int = 8642,
              open_browser: bool = False) -> None:
        httpd = ThreadingHTTPServer((host, port), _Handler)
        httpd.service = self  # type: ignore[attr-defined]
        url = f"http://{host}:{port}"
        print(f"ArkIDS 真实流量监控控制台: {url}  (Ctrl+C 退出)")
        t = self.monitor.tshark
        print("抓包引擎:", (str(t) + " " + tshark_version(t)) if t
              else "未检测到 tshark —— 实时抓包需安装 Wireshark/Npcap, 或回放真实 pcap")
        if open_browser:
            import webbrowser as _wb
            threading.Timer(1.2, lambda: _wb.open(url)).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n服务已停止")
        finally:
            self.monitor.stop()
