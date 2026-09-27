"""基于 Python 抓包库(scapy)的实时抓包实现。

要点:
    - 优先使用环境中已安装的 scapy; 否则使用本包内嵌的 scapy(_vendor, GPL-2.0);
    - Windows 下通过 Npcap 的 wpcap.dll 工作: 自动把 Wireshark/Npcap 目录加入
      DLL 搜索路径, 使 scapy 无需额外配置即可用同一驱动抓包;
    - 输出与本项目统一的 PacketRecord, 并可同步落盘 pcap(供 Wireshark/010 复核)。
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from .capture import PacketRecord

_VENDOR = Path(__file__).resolve().parent / "_vendor"
_scapy = None
_load_error = ""


def _add_dll_paths() -> None:
    """Windows: 让 wpcap.dll / Packet.dll 可被找到(Npcap/Wireshark 目录)。"""
    if os.name != "nt":
        return
    cands = [Path("C:/Windows/System32/Npcap"), Path("C:/Windows/System32"),
             Path(os.environ.get("WIRESHARK_PATH", "")) if os.environ.get(
                 "WIRESHARK_PATH") else None]
    try:
        from .capture import find_wireshark
        ws = find_wireshark()
        if ws:
            cands.append(ws.parent)
    except Exception:
        pass
    for root in ("C:/", "D:/"):
        ws = Path(root) / "deepseek_work" / "Wireshark"
        if ws.exists():
            cands.append(ws)
    for c in cands:
        if not c or not c.exists():
            continue
        try:
            os.add_dll_directory(str(c))
        except Exception:
            pass


def load_scapy():
    """返回 scapy 模块(已安装优先, 否则内嵌); 失败返回 None。"""
    global _scapy, _load_error
    if _scapy is not None:
        return _scapy
    _add_dll_paths()
    try:
        import scapy.all as sa  # type: ignore # noqa: PLC0415
        _scapy = sa
        return _scapy
    except Exception as exc:  # noqa: BLE001
        _load_error = str(exc)
    # 回退到内嵌源码
    try:
        vendor = str(_VENDOR)
        if vendor not in sys.path:
            sys.path.insert(0, vendor)
        import scapy.all as sa  # type: ignore # noqa: PLC0415
        _scapy = sa
        return _scapy
    except Exception as exc:  # noqa: BLE001
        _load_error = str(exc)
        return None


def available() -> bool:
    return load_scapy() is not None


def version() -> str:
    """scapy 版本: 优先环境安装(元数据), 其次内嵌 VERSION 文件, 最后模块常量。"""
    try:
        from importlib.metadata import version as _v  # noqa: PLC0415
        return str(_v("scapy"))
    except Exception:
        pass
    f = _VENDOR / "scapy" / "VERSION"
    try:
        if f.exists():
            return f.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    sc = load_scapy()
    if sc is None:
        return ""
    try:
        from scapy import VERSION  # type: ignore # noqa: PLC0415
        return str(VERSION)
    except Exception:
        return "2.7.0(内嵌)"


def list_interfaces() -> list[dict]:
    """返回 scapy 可见的网卡(名称/描述), 用于 GUI 与自动选择。"""
    sc = load_scapy()
    if sc is None:
        return []
    out: list[dict] = []
    try:
        for iface in sc.conf.ifaces.values():
            name = getattr(iface, "name", "") or str(iface)
            desc = getattr(iface, "description", "") or name
            out.append({"name": name, "description": desc})
    except Exception:
        try:
            out = [{"name": n, "description": n} for n in sc.get_if_list()]
        except Exception:
            out = []
    return out


def to_record(pkt) -> PacketRecord:
    """scapy 报文 -> 本项目统一 PacketRecord(IP/TCP/UDP/ICMP/IPv6)。"""
    rec = PacketRecord()
    try:
        rec.ts = float(getattr(pkt, "time", time.time()))
        rec.length = len(pkt)
        ip = pkt.getlayer("IP")
        if ip is not None:
            rec.src, rec.dst = ip.src, ip.dst
            proto = int(ip.proto)
            rec.proto = {1: "icmp", 6: "tcp", 17: "udp"}.get(proto, f"ip-{proto}")
            tcp = pkt.getlayer("TCP")
            udp = pkt.getlayer("UDP")
            if tcp is not None:
                rec.sport, rec.dport = str(tcp.sport), str(tcp.dport)
                f = int(tcp.flags)
                names = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                         (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")]
                rec.flags = "".join(t for bit, t in names if f & bit)
                rec.info = f"TCP {rec.sport}→{rec.dport} flags={rec.flags or '-'}"
            elif udp is not None:
                rec.sport, rec.dport = str(udp.sport), str(udp.dport)
                rec.info = f"UDP {rec.sport}→{rec.dport}"
            elif proto == 1:
                rec.info = "ICMP"
            else:
                rec.info = f"IP proto={proto}"
        else:
            ip6 = pkt.getlayer("IPv6")
            if ip6 is not None:
                rec.src, rec.dst = ip6.src, ip6.dst
                rec.proto = "ipv6"
                rec.info = "IPv6"
            else:
                rec.info = "非 IP 报文"
        rec.num = int(getattr(pkt, "number", 0) or 0)
    except Exception:
        pass
    return rec


class ScapySniffer(threading.Thread):
    """基于 scapy 的实时抓包线程(接口与 CaptureSource/SnifferCapture 兼容)。"""

    def __init__(self, iface: str | None = None,
                 save_dir: str | Path | None = None,
                 bpf_filter: str = "",
                 on_record=None, on_error=None) -> None:
        super().__init__(daemon=True, name="arkids-scapy")
        self.mode = "live"
        self.iface = iface
        self.save_dir = save_dir
        self.bpf_filter = bpf_filter
        self.on_record = on_record or (lambda r: None)
        self.on_error = on_error or (lambda m: None)
        self._stop_ev = threading.Event()
        self.packets = 0
        self.saved_path: str | None = None
        self.last_error = ""
        self._writer = None
        self._sniffer = None

    # ---------------------------------------------------------------- 运行
    def run(self) -> None:
        sc = load_scapy()
        if sc is None:
            self.last_error = ("scapy 加载失败: " + (_load_error or "未知") +
                               " —— 实时抓包需 Npcap 驱动。")
            self.on_error(self.last_error)
            return
        self._open_writer(sc)
        try:
            self._sniffer = sc.AsyncSniffer(iface=self.iface or None,
                                            prn=self._handle, store=False,
                                            filter=self.bpf_filter or None)
            self._sniffer.start()
        except Exception as exc:  # noqa: BLE001
            self.last_error = self._explain(exc)
            self.on_error(self.last_error)
            self._close_writer()
            return
        while not self._stop_ev.is_set():
            time.sleep(0.2)
        try:
            self._sniffer.stop()
        except Exception:
            pass
        self._close_writer()

    def _handle(self, pkt) -> None:
        try:
            rec = to_record(pkt)
            self.packets += 1
            if self._writer is not None:
                try:
                    self._writer.write(pkt)
                except Exception:
                    pass
            self.on_record(rec)
        except Exception:
            pass

    @staticmethod
    def _explain(exc: Exception) -> str:
        msg = str(exc)
        low = msg.lower()
        if any(k in low for k in ("permission", "access", "denied", "winerror 5")):
            return (f"scapy 抓包被拒绝: {msg} —— 需要管理员权限(或安装 Npcap 时"
                    "允许非管理员抓包)。")
        if "wpcap" in low or "libpcap" in low:
            return (f"未找到 wpcap/libpcap: {msg} —— 请安装 Npcap(随 Wireshark)。")
        return f"scapy 抓包失败: {msg}"

    # ---------------------------------------------------------------- 落盘
    def _open_writer(self, sc) -> None:
        if not self.save_dir:
            return
        try:
            Path(self.save_dir).mkdir(parents=True, exist_ok=True)
            name = time.strftime("arkids_scapy_%Y%m%d_%H%M%S") + ".pcap"
            path = Path(self.save_dir) / name
            self._writer = sc.PcapWriter(str(path), append=False, sync=True)
            self.saved_path = str(path)
        except Exception:
            self._writer = None

    def _close_writer(self) -> None:
        w, self._writer = self._writer, None
        if w is not None:
            try:
                w.close()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop_ev.set()
