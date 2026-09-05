"""极简 REST 检测服务(仅标准库): 把训练好的模型以 HTTP 接口对外提供。

端点:
    GET  /health         存活检查
    GET  /defense/status 防御引擎状态(告警数/封禁列表)
    POST /detect         请求体: {"features": {41 个特征字段}} 或 {"flow": {...}}
                         响应: {"verdict","score","attack","probs"}
    POST /defense/block  手动封禁: {"src_ip": "..."}

说明: 生产环境建议以 gunicorn/uvicorn + 成熟框架部署, 此处仅为最小可运行演示。
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import KDD_FEATURES
from .defense import DefenseEngine, DefenseEvent
from .detector import FlowDetector


class _Handler(BaseHTTPRequestHandler):
    server_version = "ArkIDS/0.1"

    # noinspection PyPep8Naming
    def do_GET(self):  # noqa: N802
        svc = self.server.service  # type: ignore[attr-defined]
        if self.path == "/health":
            self._json({"status": "ok", "service": "arkids"})
        elif self.path == "/defense/status":
            self._json(svc.engine.stats())
        else:
            self._json({"error": "not found"}, code=404)

    # noinspection PyPep8Naming
    def do_POST(self):  # noqa: N802
        svc = self.server.service  # type: ignore[attr-defined]
        body = self._read_json()
        if body is None:
            return
        if self.path == "/detect":
            payload = body.get("features") or body.get("flow") or body
            try:
                det = svc.detector.detect_one(payload)
                out = det.as_dict()
                out["src_ip"] = body.get("src_ip", "unknown")
                svc.engine.handle(DefenseEvent(
                    src_ip=out["src_ip"], dst_ip=body.get("dst_ip", "0.0.0.0"),
                    verdict=det.verdict, score=det.score, attack=det.attack,
                ))
                self._json(out)
            except (KeyError, ValueError) as exc:
                self._json({"error": str(exc)}, code=400)
        elif self.path == "/defense/block":
            ip = body.get("src_ip")
            if not ip:
                self._json({"error": "src_ip required"}, code=400)
                return
            rec = svc.engine.admin_block(ip)
            self._json(rec)
        else:
            self._json({"error": "not found"}, code=404)

    # ------------------------------------------------------------- 工具方法
    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._json({"error": "invalid json"}, code=400)
            return None

    def _json(self, obj, code: int = 200) -> None:
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args) -> None:  # 精简控制台日志
        print(f"[http] {self.address_string()} {fmt % args}")


class DetectionService:
    def __init__(self, model_path: str, threshold: float = 0.5,
                 state_dir: str = "run") -> None:
        self.detector = FlowDetector.load(model_path, threshold=threshold)
        self.engine = DefenseEngine(state_dir=state_dir)

    def serve(self, host: str = "127.0.0.1", port: int = 8735) -> None:
        httpd = ThreadingHTTPServer((host, port), _Handler)
        httpd.service = self  # type: ignore[attr-defined]
        print(f"ArkIDS 检测服务已启动: http://{host}:{port}  (Ctrl+C 退出)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n服务已停止")
