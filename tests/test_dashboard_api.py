"""Dashboard 服务端到端测试: 上传真实 pcap 夹具 -> 回放 -> 快照含真实包。"""
import json
import os
import sys
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))   # 使 _util / test_capture 可独立导入

from arkids.dashboard import LiveMonitor, _Handler  # noqa: E402

from _util import cleanup_tmp, make_tmp  # noqa: E402
from test_capture import (MAC_A, MAC_B, eth_frame, ipv4_tcp, ipv4_udp,  # noqa: E402
                          make_pcap, make_pcapng)


class TestDashboardApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = make_tmp("dashapi")
        cls.monitor = LiveMonitor(state_dir=cls.td)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.httpd.service = type("Svc", (), {"monitor": cls.monitor})()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.monitor.stop()
        cls.httpd.shutdown()
        cleanup_tmp("dashapi")

    def _get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=20) as r:
            return json.loads(r.read())

    def _post(self, path, obj=None, raw: bytes | None = None):
        data = raw if raw is not None else json.dumps(obj or {}).encode()
        ctype = "application/octet-stream" if raw is not None else "application/json"
        req = urllib.request.Request(self.base + path, data=data,
                                     headers={"Content-Type": ctype}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def test_idle_no_fabricated_data(self):
        meta = self._get("/api/meta")
        self.assertIn("idle", (meta["mode"],))
        snap = self._get("/api/snapshot")
        # 关键断言: 未开始采集时绝无任何伪造包/节点
        self.assertEqual(snap["stats"]["packets"], 0)
        self.assertEqual(snap["packets"], [])
        self.assertEqual(snap["nodes"], [])

    def test_upload_and_replay_real_pcap(self):
        # 构造“看起来像真实抓包”的夹具(仅测试用, 产品运行期不生成流量)
        frames = [eth_frame(MAC_A, MAC_B, ipv4_udp("192.168.1.5", "8.8.8.8", 5353, 53))
                  for _ in range(50)]
        frames += [eth_frame(MAC_A, MAC_B, ipv4_tcp("10.0.0.9", "192.168.1.5",
                                                    40000, 443, 0x02))
                   for _ in range(30)]
        pcap = make_pcap(frames)
        up = self._post("/api/upload-capture?name=demo_real.pcap", raw=pcap)
        self.assertTrue(up["ok"], up)
        r = self._post("/api/capture", {"action": "start-pcap", "file": up["path"],
                                        "display_filter": ""})
        self.assertTrue(r["ok"], r)
        # 轮询直到回放产出真实数据包(纯内建解析器, 无需 tshark)
        deadline = time.time() + 15
        snap = None
        while time.time() < deadline:
            snap = self._get("/api/snapshot")
            if snap["stats"]["packets"] > 0:
                break
            time.sleep(0.3)
        self.assertIsNotNone(snap)
        self.assertGreater(snap["stats"]["packets"], 0)
        self.assertGreater(len(snap["packets"]), 0)
        self.assertGreaterEqual(len(snap["nodes"]), 2)
        # 数据应含真实地址
        any_pkt = snap["packets"][0]
        self.assertIn("src", any_pkt)
        self.assertIn("ts", any_pkt)
        meta = self._get("/api/meta")
        self.assertIn("pcap", (meta["mode"], "pcap"))

    def test_upload_and_replay_pcapng(self):
        # pcapng(Wireshark 默认格式)夹具: 无 tshark 时由内置解析器直读
        frames = [eth_frame(MAC_A, MAC_B, ipv4_udp("10.0.0.1", "192.168.1.2",
                                                    5000 + i, 53))
                  for i in range(40)]
        pcapng = make_pcapng(frames)
        up = self._post("/api/upload-capture?name=real.pcapng", raw=pcapng)
        self.assertTrue(up["ok"], up)
        r = self._post("/api/capture", {"action": "start-pcap", "file": up["path"],
                                        "display_filter": ""})
        self.assertTrue(r["ok"], r)
        deadline = time.time() + 15
        snap = None
        while time.time() < deadline:
            snap = self._get("/api/snapshot")
            if snap["stats"]["packets"] > 0:
                break
            time.sleep(0.3)
        self.assertIsNotNone(snap)
        self.assertGreater(snap["stats"]["packets"], 0)
        self.assertEqual(snap["packets"][0]["proto"], "udp")


    def test_selfcheck_and_logs_endpoints(self):
        sc = self._get("/api/selfcheck")
        self.assertEqual(sc["total"], 8)
        self.assertTrue(sc["diagnostic"].startswith("app=OK"))
        kinds = {x["id"] for x in sc["items"]}
        self.assertIn("tshark", kinds)
        self.assertIn("parser", kinds)
        logs = self._get("/api/logs?kind=detections&n=50")
        self.assertIn("rows", logs)
        self.assertIsInstance(logs["rows"], list)


if __name__ == "__main__":
    unittest.main()
