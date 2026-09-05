"""真实流量解析与启发式检测测试(使用生成的合法 pcap 帧作为测试夹具)。"""
import os
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))   # 使 _util 可独立导入

from arkids.capture import (FlowAnalyzer, PacketRecord, RawPcapReader)  # noqa: E402

from _util import cleanup_tmp, make_tmp  # noqa: E402


# ---------------------------------------------------------------- pcap 夹具
def eth_frame(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + payload


def ipv4_tcp(src: str, dst: str, sport: int, dport: int, flags: int) -> bytes:
    s = bytes(map(int, src.split("."))); d = bytes(map(int, dst.split(".")))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags,
                      65535, 0, 0)
    ihl = 5
    total = 20 + len(tcp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000,
                     64, 6, 0, s, d)
    return ip + tcp


def ipv4_udp(src: str, dst: str, sport: int, dport: int) -> bytes:
    s = bytes(map(int, src.split("."))); d = bytes(map(int, dst.split(".")))
    udp = struct.pack(">HHHH", sport, dport, 8, 0)
    total = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x5678, 0x4000,
                     64, 17, 0, s, d)
    return ip + udp


def make_pcap(frames: list[bytes], start_ts: float = 1_700_000_000.0) -> bytes:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, fr in enumerate(frames):
        sec = int(start_ts + i)
        usec = (start_ts + i - sec) * 1_000_000
        out += struct.pack("<IIII", sec, int(usec), len(fr), len(fr))
        out += fr
        out += b"\x00" * ((4 - len(fr) % 4) % 4)
    return bytes(out)


MAC_A = b"\x00\x11\x22\x33\x44\x55"
MAC_B = b"\x66\x77\x88\x99\xaa\xbb"


class TestRawPcapReader(unittest.TestCase):
    def test_decode_tcp_syn_and_udp(self):
        pcap = make_pcap([
            eth_frame(MAC_A, MAC_B, ipv4_tcp("192.168.1.5", "8.8.8.8", 50000, 443, 0x02)),
            eth_frame(MAC_B, MAC_A, ipv4_tcp("8.8.8.8", "192.168.1.5", 443, 50000, 0x12)),
            eth_frame(MAC_A, MAC_B, ipv4_udp("192.168.1.5", "1.1.1.1", 5353, 53)),
        ])
        reader = RawPcapReader()
        recs = reader.feed(pcap)
        self.assertEqual(len(recs), 3)
        self.assertEqual((recs[0].src, recs[0].dst, recs[0].proto), ("192.168.1.5", "8.8.8.8", "tcp"))
        self.assertEqual((recs[0].sport, recs[0].dport, recs[0].flags), ("50000", "443", "S"))
        self.assertIn("A", recs[1].flags)
        self.assertEqual((recs[2].sport, recs[2].dport), ("5353", "53"))


class TestFlowAnalyzer(unittest.TestCase):
    def _mk(self, src="192.168.1.5", dst="10.0.0.1", proto="tcp", sport="1",
            dport="80", flags="S", n=1, t0=None):
        t0 = t0 or time.time()
        for i in range(n):
            yield PacketRecord(ts=t0 + i, src=src, dst=dst, proto=proto,
                               sport=str(int(sport) + i), dport=dport,
                               flags=flags, length=64)

    def test_syn_flood_detected(self):
        an = FlowAnalyzer(window_sec=60)
        for r in self._mk(dst="10.0.0.9", dport="8080", n=120):
            an.ingest(r)
        dets = an.detections(time.time() + 1)
        kinds = [d["kind"] for d in dets]
        self.assertIn("tcp_syn_flood", kinds)

    def test_port_scan_detected(self):
        an = FlowAnalyzer(window_sec=60)
        for i in range(70):
            an.ingest(PacketRecord(ts=time.time() + i, src="203.0.113.7",
                                   dst="192.168.1.10", proto="tcp",
                                   sport="30000", dport=str(1000 + i),
                                   flags="S", length=64))
        kinds = [d["kind"] for d in an.detections(time.time() + 1)]
        self.assertIn("port_scan", kinds)

    def test_burst_detected(self):
        an = FlowAnalyzer(window_sec=60)
        t0 = time.time()
        for i in range(320):
            an.ingest(PacketRecord(ts=t0 + i * 0.01, src="198.51.100.3",
                                   dst=f"10.1.0.{i % 20 + 1}", proto="tcp",
                                   sport=str(1000 + i), dport="22",
                                   flags="S", length=64))
        kinds = [d["kind"] for d in an.detections(t0 + 5)]
        self.assertIn("conn_burst", kinds)


if __name__ == "__main__":
    unittest.main()
