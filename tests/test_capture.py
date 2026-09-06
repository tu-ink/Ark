"""真实流量解析与启发式检测测试(使用生成的合法 pcap 帧作为测试夹具)。"""
import os
import struct
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))   # 使 _util 可独立导入

from arkids.capture import (FlowAnalyzer, PacketRecord, RawPcapReader,  # noqa: E402
                            RawPcapngReader, decode_any_frame)
from arkids.sniffer import PcapWriter  # noqa: E402

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


def _pcapng_block(btype: int, content: bytes) -> bytes:
    content += b"\x00" * ((4 - len(content) % 4) % 4)
    total = 12 + len(content)
    return struct.pack("<II", btype, total) + content + struct.pack("<I", total)


def make_pcapng(frames: list[bytes], ts_base: int = 1_700_000_000_000_000) -> bytes:
    """构造最小 pcapng 文件: SHB + IDB(以太网) + 若干 EPB。

    ts_base 单位为微秒(默认 2003-11-03 前后), 与默认 if_tsresol=1e-6 一致。
    """
    shb_content = (struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + b"\x00\x00\x00\x00")
    idb_content = struct.pack("<HHI", 1, 0, 65535) + b"\x00\x00\x00\x00"
    out = bytearray()
    out += _pcapng_block(0x0A0D0D0A, shb_content)
    out += _pcapng_block(1, idb_content)
    for i, fr in enumerate(frames):
        cap = len(fr)
        ts64 = ts_base + i * 1_000
        epb = struct.pack("<IIIII", 0, ts64 >> 32, ts64 & 0xFFFFFFFF, cap, cap) + fr
        out += _pcapng_block(6, epb)
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


class TestRawPcapngReader(unittest.TestCase):
    def test_decode_pcapng_epb(self):
        frames = [
            eth_frame(MAC_A, MAC_B, ipv4_tcp("10.0.0.1", "192.168.1.2", 12345, 80, 0x12)),
            eth_frame(MAC_A, MAC_B, ipv4_udp("192.168.1.9", "8.8.4.4", 53000, 53)),
        ]
        data = make_pcapng(frames)
        reader = RawPcapngReader()
        recs = reader.feed(data)
        self.assertEqual(len(recs), 2)
        self.assertEqual((recs[0].src, recs[0].dst, recs[0].proto),
                         ("10.0.0.1", "192.168.1.2", "tcp"))
        self.assertEqual((recs[0].sport, recs[0].dport), ("12345", "80"))
        self.assertEqual((recs[1].proto, recs[1].dport), ("udp", "53"))
        # 默认 us 时间精度: 解析出的秒级时间戳应落在 2003 年附近
        self.assertGreaterEqual(recs[0].ts, 1_700_000_000)
        self.assertLess(recs[0].ts, 1_800_000_000)

    def test_pcapng_chunked_feed_and_format_dispatch(self):
        frames = [eth_frame(MAC_A, MAC_B, ipv4_udp("10.1.1.1", "10.2.2.2", 1000, 443))
                  for _ in range(10)]
        data = make_pcapng(frames)
        reader = RawPcapngReader()
        recs: list = []
        for i in range(0, len(data), 7):     # 用小块喂入, 验证增量解析
            recs.extend(reader.feed(data[i:i + 7]))
        self.assertEqual(len(recs), 10)
        # 按魔数自动分发
        from arkids.capture import _reader_for
        self.assertIsInstance(_reader_for(data[:4]), RawPcapngReader)
        self.assertIsInstance(_reader_for(b"\xd4\xc3\xb2\xa1" + b"\x00" * 4),
                              RawPcapReader)
        self.assertIsNone(_reader_for(b"\x00\x01\x02\x03"))

    def test_nanosecond_pcap_magic(self):
        # Wireshark 4.x 默认写“纳秒精度”pcap(魔数 4d3cb2a1), 必须能解析
        frames = [eth_frame(MAC_A, MAC_B, ipv4_udp("192.168.1.5", "8.8.8.8", 5353, 53))]
        pcap = make_pcap(frames)
        ns = bytearray(pcap)
        ns[0:4] = b"\x4d\x3c\xb2\xa1"
        recs = RawPcapReader().feed(bytes(ns))
        self.assertEqual(len(recs), 1)
        self.assertEqual((recs[0].src, recs[0].dport), ("192.168.1.5", "53"))
        self.assertGreater(recs[0].ts, 1_600_000_000)
        # 文件嗅探也应识别纳秒魔数
        from arkids.capture import _reader_for
        self.assertIsInstance(_reader_for(b"\x4d\x3c\xb2\xa1" + b"\x00" * 4),
                              RawPcapReader)


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


class TestRawIpAndSnifferWriter(unittest.TestCase):
    def _raw(self):
        # 原始套接字收到的是“裸 IP 报文”: 先包以太网帧再去除 14B 以太头得到
        return eth_frame(MAC_A, MAC_B,
                         ipv4_tcp("192.168.5.5", "10.0.0.2", 51000, 443, 0x12))[14:]

    def test_decode_raw_ip(self):
        rec = decode_any_frame(0.0, self._raw(), 101)
        self.assertEqual((rec.src, rec.dst, rec.proto), ("192.168.5.5", "10.0.0.2", "tcp"))
        self.assertEqual((rec.sport, rec.dport), ("51000", "443"))
        self.assertIn("A", rec.flags)

    def test_pcap_writer_roundtrip(self):
        td = make_tmp("rawt")
        p = os.path.join(td, "raw101.pcap")
        w = PcapWriter(p, linktype=101)
        ts = 1_700_000_000.5
        w.write(ts, self._raw())
        w.write(ts + 1.0, self._raw())
        w.close()
        recs = RawPcapReader().feed_file(p)
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0].proto, "tcp")
        self.assertAlmostEqual(recs[0].ts, ts, delta=0.01)
        cleanup_tmp("rawt")


if __name__ == "__main__":
    unittest.main()
