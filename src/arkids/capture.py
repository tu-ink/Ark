"""真实流量采集后端: Wireshark/tshark 引擎 + 纯标准库 pcap 解析。

原则(贴合真实应用, 不构造数据):
    - 数据只来自真实来源: ① 本机网卡实时抓包; ② 用户提供的真实抓包文件。
    - 抓包以“原始字节管道”方式驱动: tshark `-F pcap -w -` 把真实包原样写到
      标准输出, 由内建 RawPcapReader 增量解析并同步落盘为 .pcap —— 同一份真实
      数据既驱动监控, 又可交给 Wireshark 打开复核, 不经过任何合成/重建。
    - 无 tshark 时: 内置 PcapReader 直接解析经典 .pcap(真实文件)。
    - 检测为可解释启发式(滑动窗口流统计), 不伪造标签, 不把离线模型硬套真实流量。
"""
from __future__ import annotations

import io
import os
import re
import shutil
import struct
import subprocess
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path

TSHARK_NAMES = ("tshark.exe", "tshark")
STD_DIRS = [Path("C:/Program Files/Wireshark"),
            Path("C:/Program Files (x86)/Wireshark")]


@dataclass
class PacketRecord:
    """归一化的一条真实数据包记录。"""
    ts: float = 0.0
    src: str = ""
    dst: str = ""
    proto: str = "ip"
    sport: str = ""
    dport: str = ""
    flags: str = ""
    length: int = 0
    num: int = 0
    info: str = ""

    def to_dict(self) -> dict:
        return {"ts": self.ts, "src": self.src, "dst": self.dst,
                "proto": self.proto, "sport": self.sport, "dport": self.dport,
                "flags": self.flags, "length": self.length, "num": self.num,
                "info": self.info}


# ------------------------------------------------------------------ 工具发现
def _wireshark_dir_candidates() -> list[Path]:
    """在常见/便携位置查找 Wireshark 目录(含仓库同级工作区与磁盘根)。"""
    cands = list(STD_DIRS)
    bases = []
    try:
        from .config import PROJECT_ROOT  # noqa: PLC0415
        bases.append(PROJECT_ROOT.parent)          # 工作区(如 D:/deepseek_work)
    except Exception:
        pass
    for root in ("C:/", "D:/", "E:/"):
        bases.append(Path(root))
        # 常见工作区形态: <盘>:/deepseek_work/Wireshark
        ws = Path(root) / "deepseek_work"
        if ws.exists():
            bases.append(ws)
    try:
        bases.append(Path.cwd())
        p = Path.cwd()
        for _ in range(4):
            p = p.parent
            bases.append(p)
    except Exception:
        pass
    for base in bases:
        for name in ("Wireshark", "wireshark", "WiresharkPortable",
                     "PortableApps/WiresharkPortable"):
            d = base / name
            if d not in cands:
                cands.append(d)
    return cands


def find_tshark() -> Path | None:
    env = os.environ.get("TSHARK_PATH") or os.environ.get("WIRESHARK_PATH")
    if env:
        p = Path(env)
        cand = p if str(p).lower().endswith(("tshark", "tshark.exe")) else p / "tshark.exe"
        if cand.exists():
            return cand
    hit = shutil.which(TSHARK_NAMES[0]) or shutil.which(TSHARK_NAMES[1])
    if hit:
        return Path(hit)
    for d in _wireshark_dir_candidates():
        p = d / "tshark.exe"
        if p.exists():
            return p
    return None


def find_wireshark() -> Path | None:
    env = os.environ.get("WIRESHARK_GUI")
    if env and Path(env).exists():
        return Path(env)
    for name in ("Wireshark.exe", "wireshark"):
        hit = shutil.which(name)
        if hit:
            return Path(hit)
    for d in _wireshark_dir_candidates():
        p = d / "Wireshark.exe"
        if p.exists():
            return p
    return None


def tshark_version(path: Path | None) -> str:
    if not path:
        return ""
    try:
        out = subprocess.run([str(path), "--version"], capture_output=True,
                             timeout=10).stdout
        line = out.decode("utf-8", errors="replace").splitlines() or [""]
        return line[0].strip()
    except Exception:
        return ""


def list_interfaces(tshark: Path | None) -> list[dict]:
    if not tshark:
        return []
    try:
        out = subprocess.run([str(tshark), "-D"], capture_output=True,
                             timeout=15).stdout
        out = out.decode("utf-8", errors="replace")
    except Exception:
        return []
    ifaces: list[dict] = []
    for line in out.splitlines():
        # 保留完整接口名(含前导 '\\Device\\NPF_...'), 描述在圆括号内
        m = re.match(r"^\s*\d+\.\s*(.+?)\s*\((.*)\)\s*$", line)
        if not m:
            m = re.match(r"^\s*\d+\.\s*(.+?)\s*$", line)
        if m:
            name = m.group(1).strip()
            # Windows 路径规范化: 兼容 '\Device\...' 前导反斜杠
            if name.startswith("Device\\"):
                name = "\\" + name
            ifaces.append({"name": name,
                           "description": (m.group(2) if m.lastindex and m.lastindex >= 2
                                           else "").strip()})
    return ifaces


def probe_interfaces_for_traffic(tshark: Path | None,
                                 ifaces: list[dict],
                                 per_sec: float = 1.2,
                                 max_sec: float = 4.0) -> list[dict]:
    """短时抓包探测各接口是否有真实流量, 按抓包数排序(用于“自动选有流量的网卡”)。

    返回: 在 ifaces 基础上附带 "probe_packets" 的列表(探测失败记 0)。
    """
    out: list[dict] = []
    if not tshark:
        return [dict(i, probe_packets=0) for i in ifaces]
    for i in ifaces:
        name = i["name"]
        try:
            proc = subprocess.run(
                [str(tshark), "-i", name, "-q", "-c", "40", "-a",
                 f"duration:{per_sec}"],
                capture_output=True, timeout=int(max_sec))
            msg = (proc.stdout or b"").decode("utf-8", errors="replace") + \
                  (proc.stderr or b"").decode("utf-8", errors="replace")
            m = re.search(r"(\d+)\s+packets captured", msg)
            count = int(m.group(1)) if m else 0
        except Exception:
            count = 0
        out.append(dict(i, probe_packets=count))
    # 有流量者优先(按包数降序), 其余保持原枚举顺序
    order = {i["name"]: idx for idx, i in enumerate(ifaces)}
    out.sort(key=lambda x: (x["probe_packets"] <= 0,
                            -x["probe_packets"],
                            order.get(x["name"], 0)))
    return out


# ------------------------------------------------------------ pcap 读取器(内建)
class RawPcapReader:
    """增量式经典 pcap(以太网)解析: 适配管道流与文件。

    抓包链路: tshark -F pcap -w - | RawPcapReader —— 真实包原样经此解析。
    """

    def __init__(self, linktype: int = 0) -> None:
        self._buf = bytearray()
        self._linktype = linktype
        self._header_done = False
        self.bytes_total = 0
        self.ts_scale = 1e-6          # 微秒精度; 纳秒精度文件为 1e-9
        self.truncated = False        # 文件/流尾部记录损坏(被截断)
        self.padded = None            # 记录是否 4 字节对齐补齐(None=未判定)
        self.dropped_bytes = 0        # 因损坏丢弃的尾部字节数

    # 单条记录最大长度(超过即判定为损坏的记录头; Wireshark 默认 snaplen=262144)
    MAX_CAPLEN = 262144

    @staticmethod
    def _plausible(ts_s: int, ts_frac: int, cap: int, orig: int) -> bool:
        """记录头合理性判定 —— 用于识别“被截断/损坏的尾部”。"""
        if cap <= 0 or cap > RawPcapReader.MAX_CAPLEN:
            return False
        if orig < cap or orig > RawPcapReader.MAX_CAPLEN:
            return False
        if ts_s > 4_102_444_800 or ts_frac >= 1_000_000_000:   # 2100-01-01
            return False
        return True

    def _header_ok(self, off: int) -> bool:
        """缓冲区 off 处是否是一条合理的记录头。"""
        if len(self._buf) < off + 16:
            return False
        ts_s, ts_frac, cap, orig = self._rec_fmt.unpack_from(bytes(self._buf), off)
        return self._plausible(ts_s, ts_frac, cap, orig)

    # 解析增量; 每次喂入新字节后返回尽量多的记录
    def feed(self, chunk: bytes) -> list[PacketRecord]:
        self._buf += chunk
        out: list[PacketRecord] = []
        if not self._header_done:
            if len(self._buf) < 24:
                return out
            magic = bytes(self._buf[:4])
            # 经典 pcap 四种魔数: 大小端 × 微秒/纳秒精度
            table = {
                b"\xd4\xc3\xb2\xa1": ("little", 1e-6),   # 微秒(小端)
                b"\x4d\x3c\xb2\xa1": ("little", 1e-9),   # 纳秒(小端, Wireshark≥4 默认)
                b"\xa1\xb2\xc3\xd4": ("big", 1e-6),      # 微秒(大端)
                b"\xa1\xb2\x3c\x4d": ("big", 1e-9),      # 纳秒(大端)
            }
            if magic not in table:
                raise ValueError("非 pcap 字节流(无法识别文件魔数, 可能为 pcapng)")
            self._bo, self.ts_scale = table[magic]
            self._big = self._bo == "big"
            self._linktype = int.from_bytes(bytes(self._buf[20:24]), self._bo)
            del self._buf[:24]
            self._header_done = True
        self._rec_fmt = struct.Struct((">" if self._big else "<") + "IIII")
        while True:
            if len(self._buf) < 16:
                break
            ts_s, ts_frac, cap_len, orig_len = self._rec_fmt.unpack_from(bytes(self._buf))
            if not self._plausible(ts_s, ts_frac, cap_len, orig_len):
                # 记录头不可信 —— 文件被截断或写入中断, 丢弃尾部而非解析出垃圾包
                self.truncated = True
                self.dropped_bytes = len(self._buf)
                del self._buf[:]
                break
            body = 16 + cap_len
            if len(self._buf) < body:
                break                                  # 记录数据未到齐
            pad = (4 - cap_len % 4) % 4
            if pad == 0:
                step = body
            else:
                big = body + pad
                if self._header_ok(body):              # 下一条紧邻数据 => 未补齐
                    step = body
                    self.padded = False
                elif self._header_ok(big):             # 下一条在补齐后 => 4 字节对齐
                    step = big
                    self.padded = True
                elif len(self._buf) >= big + 16:
                    # 两条候选都不像记录头(末段损坏或最后一条记录): 沿用已判定风格
                    step = body if self.padded is False else big
                elif len(self._buf) >= big:
                    # 数据够但要等更多字节才能判定: 先按已知风格处理
                    step = body if self.padded is False else big
                else:
                    break                              # 需更多字节才能判定
            pkt = bytes(self._buf[16:16 + cap_len])
            del self._buf[:step]
            self.bytes_total += step
            rec = self._decode_packet(ts_s + ts_frac * self.ts_scale, pkt)
            if rec:
                out.append(rec)
        return out

    def flush_tail(self) -> list[PacketRecord]:
        """处理文件末尾最后一条记录(其后无字节可用于补齐判定); 其余残余视为截断。"""
        out: list[PacketRecord] = []
        if len(self._buf) >= 16:
            ts_s, ts_frac, cap_len, orig_len = self._rec_fmt.unpack_from(bytes(self._buf))
            if self._plausible(ts_s, ts_frac, cap_len, orig_len) \
                    and len(self._buf) >= 16 + cap_len:
                pkt = bytes(self._buf[16:16 + cap_len])
                rec = self._decode_packet(ts_s + ts_frac * self.ts_scale, pkt)
                del self._buf[:16 + cap_len]
                if rec:
                    out.append(rec)
        if self._buf:
            self.truncated = True
            self.dropped_bytes = len(self._buf)
            del self._buf[:]
        return out

    def feed_file(self, path: str | Path, limit: int = 0,
                  skip: int = 0) -> list[PacketRecord]:
        """一次性解析整个 pcap 文件(供回放/测试)。"""
        out: list[PacketRecord] = []
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                for rec in self.feed(chunk):
                    if skip:
                        skip -= 1
                        continue
                    out.append(rec)
                    if limit and len(out) >= limit:
                        return out
        for rec in self.flush_tail():          # 文件末尾最后一条记录
            if skip:
                skip -= 1
                continue
            out.append(rec)
            if limit and len(out) >= limit:
                break
        return out

    def _decode_packet(self, ts: float, pkt: bytes) -> PacketRecord | None:
        if self._linktype != 1:
            # 非以太网链路: RAW(101)/SLL(113) 等交给通用解码器
            return decode_any_frame(ts, pkt, self._linktype)
        pr = PacketRecord(ts=ts)
        if len(pkt) < 14:
            pr.info = "以太网帧过短"
            pr.length = len(pkt)
            return pr
        ethertype = int.from_bytes(pkt[12:14], "big")
        ip = pkt[14:]
        if ethertype == 0x0800 and len(ip) >= 20:        # IPv4
            ihl = (ip[0] & 0x0F) * 4
            if len(ip) < ihl:
                pr.length = len(pkt)
                return pr
            proto = ip[9]
            pr.src = ".".join(str(b) for b in ip[12:16])
            pr.dst = ".".join(str(b) for b in ip[16:20])
            pr.proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(proto, f"ip-{proto}")
            pr.length = len(pkt)
            if proto == 6 and len(ip) >= ihl + 20:       # TCP
                pr.sport = str(int.from_bytes(ip[ihl:ihl + 2], "big"))
                pr.dport = str(int.from_bytes(ip[ihl + 2:ihl + 4], "big"))
                flags = ip[ihl + 13]
                names = [(0x02, "S"), (0x10, "A"), (0x08, "P"), (0x01, "F"),
                         (0x04, "R"), (0x20, "U")]
                pr.flags = "".join(t for bit, t in names if flags & bit)
                pr.info = (f"TCP {pr.sport}→{pr.dport} "
                           f"flags={pr.flags or '-'} len={len(pkt)}")
            elif proto == 17 and len(ip) >= ihl + 8:     # UDP
                pr.sport = str(int.from_bytes(ip[ihl:ihl + 2], "big"))
                pr.dport = str(int.from_bytes(ip[ihl + 2:ihl + 4], "big"))
                pr.info = f"UDP {pr.sport}→{pr.dport} len={len(pkt)}"
            elif proto == 1:
                pr.info = "ICMP"
            else:
                pr.info = f"proto={proto} len={len(pkt)}"
        elif ethertype == 0x86DD and len(ip) >= 40:      # IPv6
            nxt = ip[6]
            pr.src = _fmt_ipv6(ip[8:24])
            pr.dst = _fmt_ipv6(ip[24:40])
            pr.proto = {1: "icmpv6", 6: "tcp", 17: "udp"}.get(nxt, "ipv6")
            pr.length = len(pkt)
            pr.info = "IPv6"
        else:
            pr.info = f"其它链路/ethertype=0x{ethertype:04x} len={len(pkt)}"
            pr.length = len(pkt)
        return pr


def _fmt_ipv6(b: bytes) -> str:
    words = [int.from_bytes(b[i:i + 2], "big") for i in range(0, 16, 2)]
    text = ":".join(f"{w:x}" for w in words)
    return re.sub(r"(^|:)(0(:|$)){2,}", "::", text, count=1) or "::"


def _decode_eth(ts: float, pkt: bytes, linktype: int) -> PacketRecord:
    """共享的以太网/IP 解码器(经典 pcap 与 pcapng 复用)。"""
    pr = PacketRecord(ts=ts)
    if linktype != 1 or len(pkt) < 14:
        pr.info = "非以太网帧(linktype=%d)或过短" % linktype
        pr.length = len(pkt)
        return pr
    ethertype = int.from_bytes(pkt[12:14], "big")
    ip = pkt[14:]
    if ethertype == 0x0800 and len(ip) >= 20:               # IPv4
        ihl = (ip[0] & 0x0F) * 4
        if len(ip) < ihl:
            pr.length = len(pkt)
            return pr
        proto = ip[9]
        pr.src = ".".join(str(b) for b in ip[12:16])
        pr.dst = ".".join(str(b) for b in ip[16:20])
        pr.proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(proto, f"ip-{proto}")
        pr.length = len(pkt)
        if proto == 6 and len(ip) >= ihl + 20:              # TCP
            pr.sport = str(int.from_bytes(ip[ihl:ihl + 2], "big"))
            pr.dport = str(int.from_bytes(ip[ihl + 2:ihl + 4], "big"))
            flags = ip[ihl + 13]
            names = [(0x02, "S"), (0x10, "A"), (0x08, "P"), (0x01, "F"),
                     (0x04, "R"), (0x20, "U")]
            pr.flags = "".join(t for bit, t in names if flags & bit)
            pr.info = (f"TCP {pr.sport}→{pr.dport} "
                       f"flags={pr.flags or '-'} len={len(pkt)}")
        elif proto == 17 and len(ip) >= ihl + 8:            # UDP
            pr.sport = str(int.from_bytes(ip[ihl:ihl + 2], "big"))
            pr.dport = str(int.from_bytes(ip[ihl + 2:ihl + 4], "big"))
            pr.info = f"UDP {pr.sport}→{pr.dport} len={len(pkt)}"
        elif proto == 1:
            pr.info = "ICMP"
        else:
            pr.info = f"proto={proto} len={len(pkt)}"
    elif ethertype == 0x86DD and len(ip) >= 40:             # IPv6
        nxt = ip[6]
        pr.src = _fmt_ipv6(ip[8:24])
        pr.dst = _fmt_ipv6(ip[24:40])
        pr.proto = {1: "icmpv6", 6: "tcp", 17: "udp"}.get(nxt, "ipv6")
        pr.length = len(pkt)
        pr.info = "IPv6"
    else:
        pr.info = f"其它链路/ethertype=0x{ethertype:04x} len={len(pkt)}"
        pr.length = len(pkt)
    return pr


def _decode_raw_ip(ts: float, pkt: bytes) -> PacketRecord:
    """解码“裸 IP 报文”(原始套接字抓到的数据, 无以太网头)。"""
    pr = PacketRecord(ts=ts, length=len(pkt))
    if not pkt:
        pr.info = "空包"
        return pr
    ver = pkt[0] >> 4
    if ver == 4 and len(pkt) >= 20:
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl:
            pr.info = "IPv4 头不完整"
            return pr
        proto = pkt[9]
        pr.src = ".".join(str(b) for b in pkt[12:16])
        pr.dst = ".".join(str(b) for b in pkt[16:20])
        pr.proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(proto, f"ip-{proto}")
        if proto == 6 and len(pkt) >= ihl + 20:
            pr.sport = str(int.from_bytes(pkt[ihl:ihl + 2], "big"))
            pr.dport = str(int.from_bytes(pkt[ihl + 2:ihl + 4], "big"))
            flags = pkt[ihl + 13]
            names = [(0x02, "S"), (0x10, "A"), (0x08, "P"), (0x01, "F"),
                     (0x04, "R"), (0x20, "U")]
            pr.flags = "".join(t for bit, t in names if flags & bit)
            pr.info = f"TCP {pr.sport}→{pr.dport} flags={pr.flags or '-'}"
        elif proto == 17 and len(pkt) >= ihl + 8:
            pr.sport = str(int.from_bytes(pkt[ihl:ihl + 2], "big"))
            pr.dport = str(int.from_bytes(pkt[ihl + 2:ihl + 4], "big"))
            pr.info = f"UDP {pr.sport}→{pr.dport}"
        elif proto == 1:
            pr.info = "ICMP"
        else:
            pr.info = f"IPv4 proto={proto}"
    elif ver == 6 and len(pkt) >= 40:
        nxt = pkt[6]
        pr.src = _fmt_ipv6(pkt[8:24])
        pr.dst = _fmt_ipv6(pkt[24:40])
        pr.proto = {1: "icmpv6", 6: "tcp", 17: "udp"}.get(nxt, "ipv6")
        pr.info = "IPv6"
    else:
        pr.info = f"未知 IP 版本/长度(ver={ver})"
    return pr


def decode_any_frame(ts: float, pkt: bytes, linktype: int) -> PacketRecord:
    """按链路类型解码: 1=以太网, 101=RAW(裸 IP), 113=SLL(Linux cooked)。"""
    if linktype == 1:
        return _decode_eth(ts, pkt, 1)
    if linktype == 101:
        return _decode_raw_ip(ts, pkt)
    if linktype == 113 and len(pkt) >= 16:
        ethertype = int.from_bytes(pkt[14:16], "big")
        if ethertype in (0x0800, 0x86DD):
            return _decode_raw_ip(ts, pkt[16:])
        rec = PacketRecord(ts=ts, length=len(pkt))
        rec.info = f"SLL ethertype=0x{ethertype:04x}"
        return rec
    rec = PacketRecord(ts=ts, length=len(pkt))
    rec.info = f"未支持链路类型 linktype={linktype} len={len(pkt)}"
    return rec


def _reader_for(magic: bytes):
    """按文件头选择内置解析器: 经典 pcap(微秒/纳秒×大小端) 或 pcapng(0a0d0d0a)。"""
    if magic.startswith((b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1",
                         b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")):
        return RawPcapReader()
    if magic.startswith(b"\x0a\x0d\x0d\x0a"):
        return RawPcapngReader()
    return None


class RawPcapngReader:
    """pcapng 增量解析器(纯标准库)。

    支持: Section Header Block / Interface Description Block / Enhanced Packet
    Block / Simple Packet Block; 处理 if_tsresol / if_tsoffset; 其余块安全跳过。
    块结构与 tshark/dpkt 等公开实现输出保持兼容, 用于无 Wireshark 时直读真实 pcapng。
    """

    SHB = 0x0A0D0D0A
    IDB = 0x00000001
    SPB = 0x00000003
    EPB = 0x00000006
    BOM = 0x1A2B3C4D

    def __init__(self) -> None:
        self._buf = bytearray()
        self._endian = "<"          # struct 前缀
        self._bo = "little"         # int.from_bytes 字面量('little'/'big')
        self._linktypes: dict[int, int] = {}
        self._resol: dict[int, float] = {}
        self._tsoff: dict[int, float] = {}
        self.bytes_total = 0

    def feed(self, chunk: bytes) -> list[PacketRecord]:
        self._buf += chunk
        out: list[PacketRecord] = []
        while len(self._buf) >= 12:
            head = bytes(self._buf[:4])
            if head == b"\x0a\x0d\x0d\x0a":             # SHB 魔数(字节序无关)
                if len(self._buf) < 16:
                    break
                bom = int.from_bytes(bytes(self._buf[8:12]), "little")
                if bom == self.BOM:
                    endian = "<"
                elif int.from_bytes(bytes(self._buf[8:12]), "big") == self.BOM:
                    endian = ">"
                else:
                    raise ValueError("无法识别的 pcapng 段字节序")
                total = struct.unpack(endian + "I", bytes(self._buf[4:8]))[0]
                if total < 28 or len(self._buf) < total:
                    break
                self._endian = endian
                self._bo = "little" if endian == "<" else "big"
                del self._buf[:total]
                continue
            block_type = int.from_bytes(head, self._bo)
            total = struct.unpack(self._endian + "I", bytes(self._buf[4:8]))[0]
            if total < 12 or len(self._buf) < total:
                break
            body = bytes(self._buf[8:total - 4])
            del self._buf[:total]
            self.bytes_total += total
            out.extend(self._dispatch(block_type, body))
        return out

    def _dispatch(self, btype: int, body: bytes) -> list[PacketRecord]:
        if btype == self.IDB:
            self._handle_idb(body)
            return []
        if btype == self.EPB:
            return [self._handle_epb(body)] if len(body) >= 24 else []
        if btype == self.SPB:
            return [self._handle_spb(body)] if len(body) >= 4 else []
        return []

    def _handle_idb(self, body: bytes) -> None:
        iface = len(self._linktypes)
        self._linktypes[iface] = struct.unpack(self._endian + "H", body[:2])[0]
        self._resol[iface] = 1e-6
        self._tsoff[iface] = 0.0
        off, n = 8, len(body)
        while off + 4 <= n:
            code = struct.unpack(self._endian + "HH", body[off:off + 4])
            ln = code[1]
            if code[0] == 0 or off + 4 + ln > n:
                break
            val = body[off + 4:off + 4 + ln]
            if code[0] == 9 and ln >= 1:
                v = val[0]
                self._resol[iface] = (2.0 ** -(v & 0x7F)) if v & 0x80 else (10.0 ** -v)
            elif code[0] == 14 and ln >= 8:
                self._tsoff[iface] = float(struct.unpack(self._endian + "q",
                                                         val[:8])[0])
            off += 4 + ln + ((4 - (4 + ln) % 4) % 4)

    def _handle_epb(self, body: bytes) -> PacketRecord | None:
        iface, hi, lo, cap, _orig = struct.unpack(self._endian + "IIIII",
                                                  body[:20])
        pkt = body[20:20 + cap]
        resol = self._resol.get(iface, 1e-6)
        ts = ((hi << 32) | lo) * resol + self._tsoff.get(iface, 0.0) * resol
        return self._decode(ts, pkt, self._linktypes.get(iface, 1))

    def _handle_spb(self, body: bytes) -> PacketRecord | None:
        orig = struct.unpack(self._endian + "I", body[:4])[0]
        pkt = body[4:4 + orig]
        return self._decode(0.0, pkt, self._linktypes.get(0, 1))

    def _decode(self, ts: float, pkt: bytes, linktype: int) -> PacketRecord | None:
        return decode_any_frame(ts, pkt, linktype)

    def feed_file(self, path: str | Path, limit: int = 0) -> list[PacketRecord]:
        out: list[PacketRecord] = []
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                for rec in self.feed(chunk):
                    out.append(rec)
                    if limit and len(out) >= limit:
                        return out
        return out


# ------------------------------------------------------------ 抓包源线程
class CaptureSource(threading.Thread):
    """真实抓包/回放线程。

    mode="live": tshark -i <iface> [-f cap] -q -F pcap -w -
    mode="pcap": tshark -r <file> [-Y filter] -q -F pcap -w -(可读 pcapng);
                 无 tshark 时回退为 RawPcapReader 直读经典 pcap
    """

    def __init__(self, mode: str, target: str, cap_filter: str = "",
                 display_filter: str = "", tshark: Path | None = None,
                 save_dir: str | None = None,
                 on_record=None, on_error=None) -> None:
        super().__init__(daemon=True, name="arkids-capture")
        self.mode = mode
        self.target = target
        self.cap_filter = cap_filter
        self.display_filter = display_filter
        self.tshark = tshark
        self.save_dir = save_dir
        self.on_record = on_record or (lambda r: None)
        self.on_error = on_error or (lambda m: None)
        self._stop_ev = threading.Event()
        self._proc: subprocess.Popen | None = None
        self.started_at = time.time()
        self.packets = 0
        self.saved_path: str | None = None
        self.last_error = ""
        self._save_fh: object | None = None

    # ------------------------------------------------------------ 主循环
    def run(self) -> None:
        try:
            if self.mode == "live":
                if self.tshark is None:
                    raise RuntimeError("未找到 Wireshark/tshark, 无法实时抓包。")
                self._run_pipe(self._live_cmd())
            else:
                p = Path(self.target)
                if not p.exists():
                    raise RuntimeError(f"抓包文件不存在: {self.target}")
                # 优先内置解析器直读(无需子进程); 指定了显示过滤器时才用 tshark 解码
                if self.tshark is not None and self.display_filter:
                    self._run_pipe(self._replay_cmd())
                else:
                    self._run_pure_pcap(p)
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            self.on_error(str(exc))

    def _live_cmd(self) -> list[str]:
        cmd = [str(self.tshark), "-i", self.target, "-q", "-F", "pcap", "-w", "-"]
        if self.cap_filter:
            cmd += ["-f", self.cap_filter]
        return cmd

    def _replay_cmd(self) -> list[str]:
        cmd = [str(self.tshark), "-r", self.target, "-q", "-F", "pcap", "-w", "-"]
        if self.display_filter:
            cmd += ["-Y", self.display_filter]
        return cmd

    # tshark 原始字节管道 -> 内建解析 -> 落盘 + 回调
    def _run_pipe(self, cmd: list[str]) -> None:
        self._open_save()
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"启动抓包进程失败: {exc}") from exc
        reader = RawPcapReader()
        stderr_tail = bytearray()
        out_fd = self._proc.stdout.fileno()  # type: ignore[union-attr]
        # 关键修复: 用 os.read 直读管道 —— 有数据即返回(哪怕 1 字节),
        # 而不是等 stdout.read(n) 攒满 n 字节; 否则小流量时永远“抓不到”。
        while not self._stop_ev.is_set():
            try:
                chunk = os.read(out_fd, 1 << 16)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except OSError:
                break
            if not chunk:
                break
            if self._save_fh:
                try:
                    self._save_fh.write(chunk)  # type: ignore[union-attr]
                except Exception:
                    pass
            try:
                for rec in reader.feed(chunk):
                    self.packets += 1
                    self.on_record(rec)
            except ValueError as exc:
                self.last_error = str(exc)
                self.on_error(str(exc))
                break
        # 少量 stderr 供诊断
        try:
            err = self._proc.stderr.read(4096)  # type: ignore[union-attr]
            if err:
                stderr_tail.extend(err)
        except Exception:
            pass
        if stderr_tail:
            msg = stderr_tail.decode("utf-8", "ignore").strip().splitlines()
            if msg and "error" in " ".join(msg).lower():
                self.last_error = "tshark: " + " ".join(msg[-2:])
        self._close_save()
        self._terminate()

    # 无 tshark: 纯内建读取真实抓包文件(经典 pcap / pcapng)
    def _run_pure_pcap(self, path: Path) -> None:
        with open(path, "rb") as fh:
            head = fh.read(8)
            if not head:
                return
            reader = _reader_for(head)
            if reader is None:
                self.on_error("无法识别的抓包格式(仅支持经典 pcap 与 pcapng)")
                return
            for rec in reader.feed(head):
                self.packets += 1
                self.on_record(rec)
            while not self._stop_ev.is_set():
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                for rec in reader.feed(chunk):
                    self.packets += 1
                    self.on_record(rec)

    # ------------------------------------------------------------ 落盘
    def _open_save(self) -> None:
        if not self.save_dir:
            return
        try:
            Path(self.save_dir).mkdir(parents=True, exist_ok=True)
            name = time.strftime("arkids_%Y%m%d_%H%M%S") + ".pcap"
            path = Path(self.save_dir) / name
            self._save_fh = open(path, "wb")
            self.saved_path = str(path)
        except Exception:
            self._save_fh = None

    def _close_save(self) -> None:
        try:
            if self._save_fh:
                self._save_fh.close()  # type: ignore[union-attr]
        except Exception:
            pass
        self._save_fh = None

    def stop(self) -> None:
        self._stop_ev.set()
        self._terminate()
        self._close_save()

    def _terminate(self) -> None:
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                self._proc.wait(timeout=4)
        except Exception:
            pass


# ------------------------------------------------------------ 流统计与检测
class FlowAnalyzer:
    """滑动窗口连接/主机统计 + 可解释启发式检测(真实流量)。"""

    def __init__(self, window_sec: float = 60.0) -> None:
        self.window_sec = window_sec
        self.flows: dict[str, dict] = {}
        self.host_first: dict[str, list[float]] = {}
        self._syn_events: dict[str, deque] = {}   # 目标 "dst:dport" -> SYN 时间戳
        self._cooldown: dict[str, float] = {}
        self.counter = Counter(packets=0, bytes_=0, tcp=0, udp=0, icmp=0,
                               other=0, syn=0)
        self.total_flows_seen = 0

    def ingest(self, rec: PacketRecord) -> dict:
        now = rec.ts or time.time()
        c = self.counter
        c["packets"] += 1
        c["bytes_"] += rec.length
        if rec.proto in ("tcp", "udp", "icmp", "icmpv6"):
            c[rec.proto] += 1
        else:
            c["other"] += 1
        if rec.proto == "tcp" and "S" in rec.flags and "A" not in rec.flags:
            c["syn"] += 1
            target = f"{rec.dst}:{rec.dport}"
            self._syn_events.setdefault(target, deque()).append(now)
        key = f"{rec.src}|{rec.dst}|{rec.proto}|{rec.sport}→{rec.dport}"
        f = self.flows.get(key)
        if f is None:
            f = {"key": key, "src": rec.src, "dst": rec.dst, "proto": rec.proto,
                 "sport": rec.sport, "dport": rec.dport, "first": now, "last": now,
                 "pkts": 0, "bytes": 0, "syn": 0}
            self.flows[key] = f
            self.total_flows_seen += 1
            # 记录一次“新连接发起”(按源 IP)
            self.host_first.setdefault(rec.src, []).append(now)
        f["pkts"] += 1
        f["bytes"] += rec.length
        f["syn"] += 1 if "S" in rec.flags and "A" not in rec.flags else 0
        f["last"] = now
        self._prune(now)
        return {k: f[k] for k in ("src", "dst", "proto", "sport", "dport",
                                  "pkts", "bytes", "syn", "last")}

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_sec
        for k in [k for k, f in self.flows.items() if f["last"] < cutoff]:
            del self.flows[k]
        for src in [s for s, v in self.host_first.items()
                    if v and v[-1] < cutoff]:
            del self.host_first[src]
        for tgt in [t for t, dq in self._syn_events.items() if not dq or dq[-1] < cutoff]:
            del self._syn_events[tgt]
        for d in [d for d, t in self._cooldown.items() if t < cutoff]:
            del self._cooldown[d]

    # ------------------------------------------------------------- 检测
    def detections(self, now: float | None = None) -> list[dict]:
        now = now or time.time()
        cutoff = now - self.window_sec
        syn_counts: Counter = Counter()
        for tgt, dq in self._syn_events.items():
            syn_counts[tgt] = sum(1 for t in dq if t >= cutoff)
        ports: dict[str, set] = {}
        for f in self.flows.values():
            if f["dport"]:
                ports.setdefault(f["src"], set()).add(f"{f['dst']}:{f['dport']}")
        out: list[dict] = []
        self._syn_flood(out, syn_counts, now)
        self._port_scan(out, ports, now)
        self._burst(out, now)
        return out

    def _ok(self, key: str, now: float, secs: float = 35.0) -> bool:
        if now - self._cooldown.get(key, 0) < secs:
            return False
        self._cooldown[key] = now
        return True

    def _syn_flood(self, out: list, syn_counts: Counter, now: float) -> None:
        for target, n in syn_counts.most_common(3):
            if n < 80:
                continue
            dst, _, dport = target.partition(":")
            if not self._ok(f"syn:{target}", now):
                continue
            out.append({"kind": "tcp_syn_flood", "level": "critical",
                        "title": f"疑似 TCP SYN 洪泛 → {dst}:{dport}",
                        "detail": (f"{self.window_sec:.0f}s 窗口内观测到 {n} 个 "
                                   f"SYN(半开连接), 可能为拒绝服务攻击。"),
                        "confidence": round(min(0.6 + n / 400, 0.98), 3),
                        "src": "", "dst": dst, "dport": dport})

    def _port_scan(self, out: list, ports: dict, now: float) -> None:
        for src, targets in ports.items():
            if len(targets) < 50:
                continue
            if not self._ok(f"scan:{src}", now):
                continue
            out.append({"kind": "port_scan", "level": "warning",
                        "title": f"疑似端口扫描 {src}",
                        "detail": (f"窗口内访问 {len(targets)} 个目标端口/主机, "
                                   f"呈横向探测特征。"),
                        "confidence": round(min(0.6 + len(targets) / 250, 0.96), 3),
                        "src": src, "dst": "", "dport": ""})

    def _burst(self, out: list, now: float) -> None:
        for src, stamps in self.host_first.items():
            if len(stamps) < 250:
                continue
            span = max(1.0, stamps[-1] - stamps[0])
            rate = len(stamps) / span
            if rate < 60 or not self._ok(f"burst:{src}", now, 45):
                continue
            out.append({"kind": "conn_burst", "level": "warning",
                        "title": f"异常高连接速率 {src}",
                        "detail": (f"{span:.0f}s 内新建 {len(stamps)} 条连接"
                                   f"(≈{rate:.0f}/s), 明显高于正常水平。"),
                        "confidence": round(min(0.6, 0.4 + rate / 500), 3),
                        "src": src, "dst": "", "dport": ""})


def open_capture_file(ws: Path | None, path: str, interface: str = "") -> dict:
    """启动 Wireshark GUI 打开接口或文件(内嵌工具联动)。"""
    if ws is None:
        return {"ok": False,
                "error": "未检测到 Wireshark GUI(请安装 Wireshark 或设置 WIRESHARK_GUI)"}
    cmd = [str(ws)]
    if path:
        cmd += ["-r", path]
    elif interface:
        cmd += ["-i", interface]
    try:
        subprocess.Popen(cmd, creationflags=getattr(subprocess,
                                                    "CREATE_NO_WINDOW", 0))
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
