"""打包产物内置自检: 核心功能测试(可在冻结 exe 内运行)。

用法:
    arkids selftest            # 返回码 0=全部通过, 1=有失败
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

RESULTS: list[tuple[str, bool, str]] = []


def _step(name: str, fn) -> None:
    try:
        detail = fn() or "ok"
        RESULTS.append((name, True, str(detail)))
    except Exception as exc:  # noqa: BLE001
        RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))


def _t_version() -> str:
    from .version import __version__
    return f"arkids {__version__} · Python {sys.version.split()[0]} · frozen={getattr(sys, 'frozen', False)}"


def _t_scapy() -> str:
    from . import scapylib
    if not scapylib.available():
        raise RuntimeError("scapy 不可用(需要 Npcap 与内嵌/已安装 scapy)")
    return f"scapy {scapylib.version()} · 网卡 {len(scapylib.list_interfaces())} 个"


def _t_pcap_parse() -> str:
    """用内置解析器解析临时夹具 pcap(链路以太网)。"""
    import struct
    from .capture import RawPcapReader
    eth = (b"\x66\x77\x88\x99\xaa\xbb" + b"\x00\x11\x22\x33\x44\x55" +
           b"\x08\x00" +
           struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
                       bytes([192, 168, 1, 5]), bytes([8, 8, 8, 8])) +
           struct.pack(">HHIIBBHHH", 5000, 443, 0, 0, 5 << 4, 0x02, 65535, 0, 0))
    pcap = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    pcap += struct.pack("<IIII", 1_700_000_000, 0, len(eth), len(eth)) + eth
    pcap += b"\x00" * ((4 - len(eth) % 4) % 4)   # 记录需 4 字节对齐补齐
    td = Path("run") / "selftest_fixtures"
    td.mkdir(parents=True, exist_ok=True)
    f = td / "t.pcap"
    f.write_bytes(bytes(pcap))
    recs = RawPcapReader().feed_file(str(f))
    if len(recs) != 1 or recs[0].dport != "443":
        raise RuntimeError(f"pcap 解析结果异常: {len(recs)} 条")
    return f"pcap OK({recs[0].src}->{recs[0].dst}:{recs[0].dport})"


def _t_pcapng_parse() -> str:
    import struct
    from .capture import RawPcapngReader
    eth = (b"\x66\x77\x88\x99\xaa\xbb" + b"\x00\x11\x22\x33\x44\x55" +
           b"\x08\x00" +
           struct.pack(">BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 17, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) +
           struct.pack(">HHHH", 5300, 53, 8, 0))

    def blk(t: int, content: bytes) -> bytes:
        content += b"\x00" * ((4 - len(content) % 4) % 4)
        total = 12 + len(content)
        return struct.pack("<II", t, total) + content + struct.pack("<I", total)

    shb = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + b"\x00" * 4)
    idb = blk(1, struct.pack("<HHI", 1, 0, 65535) + b"\x00" * 4)
    ts = 1_700_000_000_000_000
    epb = blk(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(eth), len(eth)) + eth)
    td = Path("run") / "selftest_fixtures"
    td.mkdir(parents=True, exist_ok=True)
    f = td / "t.pcapng"
    f.write_bytes(shb + idb + epb)
    recs = RawPcapngReader().feed_file(str(f))
    if len(recs) != 1 or recs[0].proto != "udp":
        raise RuntimeError(f"pcapng 解析结果异常: {len(recs)} 条")
    return "pcapng OK"


def _t_firewall() -> str:
    from .firewall import FirewallRule, FirewallStore
    td = Path("run") / "selftest_fw"
    td.mkdir(parents=True, exist_ok=True)
    st = FirewallStore(state_dir=str(td))
    r = st.add(FirewallRule(src_ip="203.0.113.9", action="deny", note="selftest"))
    assert st.is_src_blocked("203.0.113.9")
    st.update(r.id, enabled=False)
    assert not st.is_src_blocked("203.0.113.9")
    assert st.delete(r.id)
    return "规则增删改/脚本导出 OK"


def _t_analyzer() -> str:
    from .capture import FlowAnalyzer, PacketRecord
    an = FlowAnalyzer(window_sec=60)
    t0 = time.time()
    for i in range(120):
        an.ingest(PacketRecord(ts=t0 + i * 0.01, src="203.0.113.7", dst="10.0.0.9",
                               proto="tcp", sport=str(1000 + i), dport="8080",
                               flags="S", length=64))
    kinds = [d["kind"] for d in an.detections(t0 + 2)]
    if "tcp_syn_flood" not in kinds:
        raise RuntimeError(f"启发式检测未触发: {kinds}")
    return "流统计/启发式检测 OK"


def _t_diag_quick() -> str:
    from .dashboard import LiveMonitor
    m = LiveMonitor(state_dir="run/selftest", engine="auto")
    d = m.diag_capture(full=False)
    if len(d.get("items", [])) < 4:
        raise RuntimeError("排错项不足")
    return f"排错(快速) OK · 结论={d.get('reason')}"


def _t_dashboard_api() -> str:
    from http.server import ThreadingHTTPServer
    from .dashboard import DashboardService, _Handler
    svc = DashboardService(state_dir="run/selftest_api")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.service = svc  # type: ignore[attr-defined]
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        base = f"http://127.0.0.1:{port}"
        for path in ("/health", "/api/meta", "/api/snapshot", "/api/selfcheck",
                     "/api/ext-tools", "/api/firewall"):
            with urllib.request.urlopen(base + path, timeout=15) as r:
                json.loads(r.read())
        with urllib.request.urlopen(base + "/", timeout=15) as r:
            assert b"ArkIDS" in r.read()
    finally:
        httpd.shutdown()
    return "REST API(health/meta/snapshot/selfcheck/firewall) OK"


def _t_gui() -> str:
    """GUI 可用性: 创建窗口并立即销毁(不进入事件循环)。"""
    try:
        import tkinter  # noqa: F401,PLC0415
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"tkinter 不可用: {exc}") from exc
    from .gui import ArkGUI
    g = ArkGUI()
    g.root.update_idletasks()
    g.root.update()
    g._on_close()
    return "GUI 构建/销毁 OK"


def run() -> int:
    print("ArkIDS 自检(打包产物核心功能测试)")
    print("=" * 56)
    _step("版本与运行环境", _t_version)
    _step("Python 抓包库(scapy)", _t_scapy)
    _step("pcap 解析(内置)", _t_pcap_parse)
    _step("pcapng 解析(内置)", _t_pcapng_parse)
    _step("防火墙规则库", _t_firewall)
    _step("流统计与启发式检测", _t_analyzer)
    _step("抓包环境排错(快速)", _t_diag_quick)
    _step("REST 服务与接口", _t_dashboard_api)
    _step("GUI 构建", _t_gui)
    ok = sum(1 for _, good, _ in RESULTS if good)
    for name, good, detail in RESULTS:
        print(f"[{'PASS' if good else 'FAIL'}] {name}: {detail}")
    print("-" * 56)
    print(f"结果: {ok}/{len(RESULTS)} 通过")
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(run())
