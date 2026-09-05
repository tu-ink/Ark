"""自研抓包引擎(不再依赖 Wireshark/tshark/Npcap 等外部工具)。

原理(参考 GitHub 上公认的原始套接字抓包实现思路, 如
  - Windows: 原始套接字 + SIO_RCVALL(需管理员, 抓取本机全部 IPv4 出入站报文)
  - Linux:   AF_PACKET/SOCK_RAW(需 root, 抓取以太网帧)
无需安装任何第三方驱动/抓包软件; 抓到的原始字节由内建解码器解析并同步落盘为
经典 pcap(链路类型: Windows=101 RAW, Linux=1 Ethernet), 可被 Wireshark 打开复核。
"""
from __future__ import annotations

import os
import socket
import struct
import threading
import time
from pathlib import Path

from .capture import PacketRecord, decode_any_frame

RECV_BUFSIZE = 65535


# ---------------------------------------------------------------- pcap 写入
class PcapWriter:
    """经典 pcap(小端)流式写入器 —— 自研抓包工具的自产格式。"""

    def __init__(self, path: str | Path, linktype: int = 101) -> None:
        self.linktype = linktype
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "wb")
        self._fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                   65535, linktype))
        self.packets = 0

    def write(self, ts: float, data: bytes) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
        self._fh.write(data)
        self._fh.write(b"\x00" * ((4 - len(data) % 4) % 4))
        self.packets += 1

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 嗅探线程
class SnifferCapture(threading.Thread):
    """内置抓包线程: 原始套接字采集 -> 内建解码 -> 回调 + 落盘。

    与 CaptureSource 兼容的接口(mode/saved_path/last_error/is_alive/stop)，
    便于 LiveMonitor 透明切换“内置引擎 / tshark 引擎”。
    """

    def __init__(self, save_dir: str | Path | None = None,
                 on_record=None, on_error=None) -> None:
        super().__init__(daemon=True, name="arkids-sniffer")
        self.mode = "live"
        self.save_dir = save_dir
        self.on_record = on_record or (lambda r: None)
        self.on_error = on_error or (lambda m: None)
        self._stop_ev = threading.Event()
        self.packets = 0
        self.saved_path: str | None = None
        self.last_error = ""
        self.linktype = 101 if os.name == "nt" else 1
        self._sock: socket.socket | None = None
        self._writer: PcapWriter | None = None

    # ---------------------------------------------------------- 兼容属性
    def is_capturing(self) -> bool:
        return self.is_alive()

    # ---------------------------------------------------------- 主循环
    def run(self) -> None:
        try:
            self._open_writer()
            self._sock = self._open_raw_socket()
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"{exc}\n(Windows 内置抓包需【以管理员身份运行】;" \
                              " Linux 需 root; 无需安装任何抓包工具)"
            self.on_error(self.last_error)
            self._close_all()
            return
        try:
            while not self._stop_ev.is_set():
                try:
                    data, _addr = self._sock.recvfrom(RECV_BUFSIZE)
                except OSError:
                    if self._stop_ev.is_set():
                        break
                    continue
                ts = time.time()
                rec = decode_any_frame(ts, data, self.linktype)
                if self._writer:
                    try:
                        self._writer.write(ts, data)
                    except Exception:
                        pass
                self.packets += 1
                self.on_record(rec)
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"抓包循环异常: {exc}"
            self.on_error(self.last_error)
        finally:
            self._close_all()

    def _open_raw_socket(self) -> socket.socket:
        if os.name == "nt":
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            try:
                s.bind(("0.0.0.0", 0))
            except OSError as exc:
                s.close()
                raise PermissionError(
                    "绑定原始套接字失败, 需要管理员权限") from exc
            # 打开混杂接收(SIO_RCVALL) —— Windows 自带的“抓包开关”, 无第三方驱动
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return s
        # Linux: 链路层原始套接字(需要 root)
        if hasattr(socket, "AF_PACKET"):
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.htons(0x0003))
            return s
        raise RuntimeError("当前平台不支持内置原始套接字抓包")

    def _open_writer(self) -> None:
        if not self.save_dir:
            return
        Path(self.save_dir).mkdir(parents=True, exist_ok=True)
        name = time.strftime("arkids_raw_%Y%m%d_%H%M%S") + ".pcap"
        path = Path(self.save_dir) / name
        self._writer = PcapWriter(path, linktype=self.linktype)
        self.saved_path = str(path)

    def stop(self) -> None:
        self._stop_ev.set()
        s, self._sock = self._sock, None
        if s:
            try:
                s.close()  # 唤醒阻塞中的 recvfrom
            except Exception:
                pass
        self._close_all()

    def _close_all(self) -> None:
        s, self._sock = self._sock, None
        if s:
            try:
                if os.name == "nt":
                    try:
                        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except Exception:
                        pass
                s.close()
            except Exception:
                pass
        w, self._writer = self._writer, None
        if w:
            w.close()


def sniff_interfaces() -> list[dict]:
    """内置引擎的“接口”说明(单条: 捕获全部本机 IPv4 流量)。"""
    return [{"name": "any", "description":
             ("内置嗅探引擎: 本机全部 IPv4 出入站流量"
              + (" (Windows 原始套接字, 需管理员, 无需安装)" if os.name == "nt"
                 else " (Linux AF_PACKET, 需 root)"))}]
