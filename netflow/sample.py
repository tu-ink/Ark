# -*- coding: utf-8 -*-
"""示例流量生成（sample）：造一段「正常流量 + SYN 洪泛」的 pcap。

用途：

1. ``python main.py --demo`` 离线演示 —— 不需要管理员权限、不需要 Npcap；
2. 验证「采集 → 统计 → 评分 → 告警 → 落库」整条链路；
3. 可复现实验 —— 固定随机种子，任何人跑出来的样本完全一致。

两段流量的设计意图：

* **正常段**：40 台内网主机访问少量服务端口，TCP/UDP/ICMP 混合，
  包速率与实时采集场景相当（默认约 400 包/秒）；
* **异常段**：SYN 洪泛 —— 大量伪造源 IP、全部为 SYN 标志、目的端口单一、
  平均包长极小，在 ``syn_ratio`` / ``unique_src_ips`` / ``avg_pkt_len``
  三个特征上显著偏离正常基线。
"""

from __future__ import annotations

import logging
import os
import random
from typing import List, Optional

logger = logging.getLogger(__name__)

#: 默认输出文件名
DEFAULT_SAMPLE_NAME = "sample.pcap"

#: 演示时间轴起点（固定值，保证 pcap 内容可复现）
_EPOCH = 1758000000.0

_SERVICE_PORTS = (80, 443, 8080)
_DNS_PORT = 53


def build_packets(
    duration: float = 16.0,
    rate: float = 400.0,
    flood_duration: float = 5.0,
    flood_rate: float = 1600.0,
    seed: int = 7,
) -> List:
    """构造示例报文列表（需要 Scapy）。"""
    from scapy.all import ICMP, IP, Raw, TCP, UDP, Ether  # type: ignore

    random.seed(seed)
    packets: List = []

    hosts = ["192.168.10.%d" % h for h in range(10, 50)]
    servers = ["10.0.%d.%d" % (i % 4, 10 + i % 200) for i in range(200)]

    # ---------------- 正常段 ----------------
    for i in range(int(duration * rate)):
        ts = _EPOCH + i / rate + random.uniform(-0.001, 0.001)
        src, dst = random.choice(hosts), random.choice(servers)
        roll = random.random()
        if roll < 0.72:  # TCP：约四成是纯 ACK 小包，其余带载荷
            sport, dport = random.randint(1024, 65000), random.choice(_SERVICE_PORTS)
            if random.random() < 0.4:
                pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A")
            else:
                payload = max(0, int(random.gauss(500, 150)))
                pkt = (Ether() / IP(src=src, dst=dst)
                       / TCP(sport=sport, dport=dport, flags="PA") / Raw(b"x" * payload))
        elif roll < 0.97:  # UDP / DNS
            pkt = (Ether() / IP(src=src, dst=dst)
                   / UDP(sport=random.randint(1024, 65000), dport=_DNS_PORT)
                   / Raw(b"x" * random.randint(0, 300)))
        else:  # ICMP
            pkt = Ether() / IP(src=src, dst=dst) / ICMP() / Raw(b"x" * 64)
        pkt.time = ts
        packets.append(pkt)

    # ---------------- 异常段：SYN 洪泛 ----------------
    flood_start = _EPOCH + duration + 2.0
    target = "10.0.0.5"
    for i in range(int(flood_duration * flood_rate)):
        ts = flood_start + i / flood_rate
        src = "203.0.%d.%d" % (random.randint(0, 255), random.randint(1, 254))
        pkt = (Ether() / IP(src=src, dst=target)
               / TCP(sport=random.randint(1024, 65000), dport=80, flags="S"))
        pkt.time = ts
        packets.append(pkt)

    return packets


def generate_sample_pcap(
    path: str = DEFAULT_SAMPLE_NAME,
    duration: float = 16.0,
    rate: float = 400.0,
    flood_duration: float = 5.0,
    flood_rate: float = 1600.0,
    seed: int = 7,
    quiet: bool = False,
) -> str:
    """生成示例 pcap 并返回其绝对路径。"""
    from scapy.all import wrpcap  # type: ignore

    packets = build_packets(duration, rate, flood_duration, flood_rate, seed)
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    wrpcap(path, packets)
    if not quiet:
        size_mb = os.path.getsize(path) / 1024.0 / 1024.0
        logger.info("已生成 %s: %d 个包, %.2f MB", path, len(packets), size_mb)
        logger.info("  正常段: %.0f 秒 @ %.0f 包/秒", duration, rate)
        logger.info("  异常段: %.0f 秒 @ %.0f 包/秒 SYN 洪泛", flood_duration, flood_rate)
    return os.path.abspath(path)


def ensure_sample_pcap(directory: Optional[str] = None,
                       filename: str = DEFAULT_SAMPLE_NAME) -> str:
    """确保示例 pcap 存在（不存在则生成），返回绝对路径。"""
    base = directory or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, filename)
    if os.path.isfile(path):
        return path
    logger.info("未找到示例数据，正在生成 %s ...", path)
    return generate_sample_pcap(path, quiet=True)


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.sample`` 自检：生成一个短样本并报告大小。

    刻意不使用 ``tempfile.TemporaryDirectory``（它以 0o700 建目录，
    在受限环境里可能不可写），改为生成到当前工作目录后立即删除。
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    target = os.path.abspath("sample_selftest.pcap")
    path = generate_sample_pcap(target, duration=2.0, rate=100.0,
                                flood_duration=1.0, flood_rate=300.0, quiet=False)
    size_kb = os.path.getsize(path) / 1024.0
    print("生成成功: {0} ({1:.0f} KB)".format(path, size_kb))
    os.remove(path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
