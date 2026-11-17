# -*- coding: utf-8 -*-
"""测试公共设施：报文桩、窗口构造、临时目录、日志静默。"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import uuid
from datetime import datetime
from types import SimpleNamespace

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:  # 报文桩需要 Scapy 的层类型做判别键
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    ICMP = IP = TCP = UDP = None  # type: ignore
    SCAPY_AVAILABLE = False

from netflow.stats import WindowStats  # noqa: E402

_TMP_ROOT = os.path.join(_PROJECT_ROOT, ".test-tmp")


def make_temp_dir(prefix: str) -> str:
    """在项目内创建一个测试用临时目录。

    这里刻意不使用 ``tempfile.mkdtemp``：它以 ``0o700`` 创建目录，
    在部分受限环境（容器 / 沙箱）中会被判定为不可写，导致测试误报失败。
    """
    os.makedirs(_TMP_ROOT, exist_ok=True)
    path = os.path.join(_TMP_ROOT, "{0}{1}".format(prefix, uuid.uuid4().hex[:8]))
    os.makedirs(path, exist_ok=True)
    return path


def setUpModule() -> None:
    """测试期间关闭日志输出，保持结果清爽。"""
    logging.disable(logging.CRITICAL)


def tearDownModule() -> None:
    """测试结束后恢复日志并清理临时目录。"""
    logging.disable(logging.NOTSET)
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)

class StubPacket:
    """替代真实 Scapy 报文的最小桩对象（只实现统计层用到的接口）。"""

    def __init__(self, size: int = 100, src: str = "10.0.0.1", proto: str = "tcp",
                 dport: int = 80, syn: bool = False) -> None:
        self.wirelen = size
        self._src = src
        self._proto = proto
        self._dport = dport
        self._syn = syn

    def getlayer(self, layer):
        if layer is IP:
            return SimpleNamespace(src=self._src)
        if layer is TCP and self._proto == "tcp":
            return SimpleNamespace(flags=0x02 if self._syn else 0x10, dport=self._dport)
        if layer is UDP and self._proto == "udp":
            return SimpleNamespace(dport=self._dport)
        if layer is ICMP and self._proto == "icmp":
            return SimpleNamespace()
        return None


def make_window(packets: int = 1000, anomalies: bool = False) -> WindowStats:
    """构造一个用于测试的窗口结果。"""
    now = datetime.now()
    return WindowStats(
        now, now, 5.0,
        packet_count=packets, byte_count=packets * 300,
        tcp_count=int(packets * 0.7), udp_count=int(packets * 0.25),
        icmp_count=int(packets * 0.05), syn_count=0,
        unique_src_ips=40,
        top_src_ips=[("192.168.10.11", 75)], top_dst_ports=[(443, 535)],
    )


def silence_logging() -> None:
    """测试期间关闭日志输出，保持结果清爽。"""
    logging.disable(logging.CRITICAL)


def restore_logging() -> None:
    """恢复日志。"""
    logging.disable(logging.NOTSET)


def cleanup() -> None:
    """删除整个测试临时根目录。"""
    shutil.rmtree(_TMP_ROOT, ignore_errors=True)
