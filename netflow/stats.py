# -*- coding: utf-8 -*-
"""统计层（stats）：把数据包按固定时间窗口聚合成 10 维特征向量。

特征定义（顺序与 :data:`FEATURE_NAMES` 严格一致）
------------------------------------------------
==============  ==========================================================
特征            含义
==============  ==========================================================
packet_count    窗口内总包数
byte_count      窗口内总字节数（取 IP 层长度，无 IP 层时取线缆长度）
tcp_ratio       TCP 包数 / 总包数
udp_ratio       UDP 包数 / 总包数
icmp_ratio      ICMP 包数 / 总包数
unique_src_ips  窗口内唯一源 IP 数
syn_ratio       带 SYN 标志的 TCP 包数 / 总包数
avg_pkt_len     byte_count / packet_count
pps             packet_count / 窗口实际时长（包/秒）
bps             byte_count / 窗口实际时长（字节/秒，非比特）
==============  ==========================================================

同时记录 Top-N 源 IP 与 Top-N 目的端口，用于告警后的人工复核。
训练脚本与实时推理必须使用完全相同的特征顺序，顺序由 :data:`FEATURE_NAMES` 单点定义。
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import Counter
from datetime import datetime
from queue import Empty, Queue
from typing import Callable, Dict, List, Optional, Sequence, Tuple

try:
    from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover - 未安装 scapy 时降级为纯统计模式
    ICMP = IP = TCP = UDP = IPv6 = None  # type: ignore

logger = logging.getLogger(__name__)

#: 特征向量顺序，训练与推理必须完全一致
FEATURE_NAMES: Tuple[str, ...] = (
    "packet_count",
    "byte_count",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "unique_src_ips",
    "syn_ratio",
    "avg_pkt_len",
    "pps",
    "bps",
)

#: 单个窗口内为 Top-N 统计最多维护多少个不同键，防止极端扫描流量耗尽内存
DEFAULT_MAX_TRACKED_KEYS = 200000


class WindowStats:
    """一个时间窗口内的统计结果（不可变的数据载体）。

    同时承担三个角色：异常检测的输入（:meth:`to_vector`）、
    数据库写入的数据源、界面展示的数据源（:meth:`format_summary`）。
    """

    __slots__ = (
        "start_time", "end_time", "duration",
        "packet_count", "byte_count",
        "tcp_count", "udp_count", "icmp_count", "syn_count",
        "unique_src_ips", "top_src_ips", "top_dst_ports", "truncated",
    )

    def __init__(
        self,
        start_time: datetime,
        end_time: datetime,
        duration: float,
        packet_count: int,
        byte_count: int,
        tcp_count: int,
        udp_count: int,
        icmp_count: int,
        syn_count: int,
        unique_src_ips: int,
        top_src_ips: Sequence[Tuple[str, int]] = (),
        top_dst_ports: Sequence[Tuple[object, int]] = (),
        truncated: bool = False,
    ) -> None:
        self.start_time = start_time
        self.end_time = end_time
        self.duration = max(float(duration), 1e-9)
        self.packet_count = int(packet_count)
        self.byte_count = int(byte_count)
        self.tcp_count = int(tcp_count)
        self.udp_count = int(udp_count)
        self.icmp_count = int(icmp_count)
        self.syn_count = int(syn_count)
        self.unique_src_ips = int(unique_src_ips)
        self.top_src_ips = list(top_src_ips)
        self.top_dst_ports = list(top_dst_ports)
        self.truncated = bool(truncated)

    # ------------------------------------------------------------------ #
    # 特征派生
    # ------------------------------------------------------------------ #
    @property
    def tcp_ratio(self) -> float:
        return self.tcp_count / self.packet_count if self.packet_count else 0.0

    @property
    def udp_ratio(self) -> float:
        return self.udp_count / self.packet_count if self.packet_count else 0.0

    @property
    def icmp_ratio(self) -> float:
        return self.icmp_count / self.packet_count if self.packet_count else 0.0

    @property
    def syn_ratio(self) -> float:
        """SYN 包占**总包数**的比例（分母含非 TCP 包）。"""
        return self.syn_count / self.packet_count if self.packet_count else 0.0

    @property
    def avg_pkt_len(self) -> float:
        return self.byte_count / self.packet_count if self.packet_count else 0.0

    @property
    def pps(self) -> float:
        return self.packet_count / self.duration

    @property
    def bps(self) -> float:
        """字节速率（Byte/s）。如需比特速率请乘以 8。"""
        return self.byte_count / self.duration

    def to_vector(self) -> List[float]:
        """返回与 :data:`FEATURE_NAMES` 顺序一致的 10 维特征向量。"""
        return [
            float(self.packet_count),
            float(self.byte_count),
            self.tcp_ratio,
            self.udp_ratio,
            self.icmp_ratio,
            float(self.unique_src_ips),
            self.syn_ratio,
            self.avg_pkt_len,
            self.pps,
            self.bps,
        ]

    def to_dict(self) -> Dict[str, float]:
        """返回 {特征名: 取值} 字典。"""
        return dict(zip(FEATURE_NAMES, self.to_vector()))

    def to_json(self) -> str:
        """特征快照的 JSON 串，写入 alerts 表用于事后复核。"""
        payload: Dict[str, object] = dict(self.to_dict())
        payload["window_start"] = self.start_time.isoformat(timespec="seconds")
        payload["window_end"] = self.end_time.isoformat(timespec="seconds")
        payload["duration"] = round(self.duration, 3)
        payload["top_src_ips"] = [list(x) for x in self.top_src_ips]
        payload["top_dst_ports"] = [list(x) for x in self.top_dst_ports]
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def format_summary(self, anomaly_score: Optional[float] = None) -> str:
        """生成控制台摘要行。

        形如::

            [2025-01-01 12:00:05] 包数: 1200, 字节: 850000, TCP: 78%, UDP: 20%,
            ICMP: 2%, 唯一源IP: 45, SYN比例: 0.12, 异常分数: -0.0500
        """
        score_text = "N/A" if anomaly_score is None else "{0:.4f}".format(anomaly_score)
        return (
            "[{ts}] 包数: {pkts}, 字节: {nbytes}, TCP: {tcp:.0f}%, UDP: {udp:.0f}%, "
            "ICMP: {icmp:.0f}%, 唯一源IP: {ips}, SYN比例: {syn:.2f}, 异常分数: {score}".format(
                ts=self.end_time.strftime("%Y-%m-%d %H:%M:%S"),
                pkts=self.packet_count,
                nbytes=self.byte_count,
                tcp=self.tcp_ratio * 100.0,
                udp=self.udp_ratio * 100.0,
                icmp=self.icmp_ratio * 100.0,
                ips=self.unique_src_ips,
                syn=self.syn_ratio,
                score=score_text,
            )
        )

    def format_top(self, top_n: int = 5) -> str:
        """Top-N 源 IP 与目的端口的可读字符串。"""
        ips = ", ".join("{0}({1})".format(ip, cnt) for ip, cnt in self.top_src_ips[:top_n]) or "-"
        ports = ", ".join("{0}({1})".format(p, cnt) for p, cnt in self.top_dst_ports[:top_n]) or "-"
        return "Top源IP: {0} | Top目的端口: {1}".format(ips, ports)


def _fallback_size(pkt) -> int:
    """兜底取长度：线缆长度优先，其次整包序列化长度。"""
    wirelen = getattr(pkt, "wirelen", None)
    if wirelen:
        return int(wirelen)
    try:
        return len(bytes(pkt))
    except Exception:  # pragma: no cover - 防御性兜底
        return 0


def _extract_network(pkt) -> Tuple[int, Optional[str]]:
    """一次性取出「报文长度」与「源 IP」。

    原实现里 ``add()`` 先调 ``_packet_size()`` 取长度（内部查一次 IP 层），
    随后又自己查一次 IP 层取源地址，同一个报文要遍历两次层栈。
    合并为一次查找后，每个报文少一次 ``getlayer`` 调用。
    """
    if IP is not None:
        ip = pkt.getlayer(IP)
        if ip is not None:
            # IP 层存在但未声明长度时，仍要回退到线缆长度，不能直接当作 0
            length = int(ip.len) if getattr(ip, "len", None) else _fallback_size(pkt)
            return length, ip.src
    if IPv6 is not None:
        ip6 = pkt.getlayer(IPv6)
        if ip6 is not None:
            length = (int(ip6.plen) + 40 if getattr(ip6, "plen", None)
                      else _fallback_size(pkt))
            return length, ip6.src
    return _fallback_size(pkt), None


class _WindowAccumulator:
    """窗口内的增量累加器（每个窗口都用新实例，避免脏状态）。"""

    def __init__(self, top_n: int = 5, max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS) -> None:
        self.top_n = top_n
        self.max_tracked_keys = max_tracked_keys
        self.packet_count = 0
        self.byte_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.syn_count = 0
        # 源 IP 去重直接靠 Counter 的键，不再额外维护一份 set
        self._src_counter: Counter = Counter()
        self._dst_port_counter: Counter = Counter()
        self.truncated = False

    def add(self, pkt) -> None:
        """累加一个数据包（热点函数，尽量少查层栈）。"""
        self.packet_count += 1
        size, src_ip = _extract_network(pkt)
        self.byte_count += size

        if TCP is not None:
            tcp = pkt.getlayer(TCP)
            if tcp is not None:
                self.tcp_count += 1
                if int(tcp.flags) & 0x02:  # SYN 标志位
                    self.syn_count += 1
                self._count_key(self._dst_port_counter, int(tcp.dport))
        if UDP is not None:
            udp = pkt.getlayer(UDP)
            if udp is not None:
                self.udp_count += 1
                self._count_key(self._dst_port_counter, int(udp.dport))
        if ICMP is not None and pkt.getlayer(ICMP) is not None:
            self.icmp_count += 1

        if src_ip is not None:
            self._count_src(src_ip)

    def _count_src(self, src_ip: str) -> None:
        """源 IP 计数。用 Counter 的键去重，省掉一份额外的字符串集合。"""
        counter = self._src_counter
        if src_ip not in counter and len(counter) >= self.max_tracked_keys:
            # 极端扫描/DDoS 场景下的保护：只计数不新增键，标记窗口已截断
            self.truncated = True
            return
        counter[src_ip] += 1

    def _count_key(self, counter: Counter, key) -> None:
        if key not in counter and len(counter) >= self.max_tracked_keys:
            self.truncated = True
            return
        counter[key] += 1

    def finalize(self, start: datetime, end: datetime, duration: float) -> WindowStats:
        """产出不可变的 :class:`WindowStats` 结果对象。"""
        return WindowStats(
            start_time=start,
            end_time=end,
            duration=duration,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            tcp_count=self.tcp_count,
            udp_count=self.udp_count,
            icmp_count=self.icmp_count,
            syn_count=self.syn_count,
            unique_src_ips=len(self._src_counter),
            top_src_ips=self._src_counter.most_common(self.top_n),
            top_dst_ports=self._dst_port_counter.most_common(self.top_n),
            truncated=self.truncated,
        )


class StatsCollector:
    """消费者线程：把队列中的包聚合成固定时间窗口的统计结果。

    Parameters
    ----------
    packet_queue:
        采集层投递报文的队列（与采集层共享同一对象）。
    window_seconds:
        时间窗口长度，默认 5 秒。
    top_n:
        记录 Top-N 源 IP / 目的端口。
    record_empty:
        是否记录空窗口。默认 ``False``：全零窗口对异常检测无意义，
        反而容易被模型误判为异常。
    is_source_finished:
        可选回调，返回 ``True`` 表示上游数据源已结束（回放读完或达到包数上限），
        此时消费完队列剩余报文后自动退出。
    """

    def __init__(
        self,
        packet_queue: "Queue",
        window_seconds: float = 5.0,
        top_n: int = 5,
        record_empty: bool = False,
        is_source_finished: Optional[Callable[[], bool]] = None,
        max_tracked_keys: int = DEFAULT_MAX_TRACKED_KEYS,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds 必须为正数")
        self.queue = packet_queue
        self.window_seconds = float(window_seconds)
        self.top_n = int(top_n)
        self.record_empty = bool(record_empty)
        self.is_source_finished = is_source_finished
        self.max_tracked_keys = int(max_tracked_keys)

        self.window_count = 0          # 已产出的窗口数
        self.consumed_packets = 0      # 已消费的包数

    # ------------------------------------------------------------------ #
    def _drain(self, acc: _WindowAccumulator) -> int:
        """非阻塞地把队列中剩余报文全部并入累加器，返回并入数量。"""
        drained = 0
        while True:
            try:
                pkt = self.queue.get_nowait()
            except Empty:
                break
            acc.add(pkt)
            drained += 1
        self.consumed_packets += drained
        return drained

    def run(
        self,
        stop_event: threading.Event,
        on_window: Callable[[WindowStats], None],
    ) -> None:
        """消费者主循环。

        Parameters
        ----------
        stop_event:
            置位后先排空队列再输出最后一个（不完整）窗口，然后退出。
        on_window:
            每产出一个窗口调用一次，由编排层注入「评分 + 落库 + 展示」逻辑。
        """
        logger.info("消费者线程启动: 窗口=%.1f 秒", self.window_seconds)
        acc = _WindowAccumulator(self.top_n, self.max_tracked_keys)
        window_start_mono = time.monotonic()
        window_start_dt = datetime.now()
        source_done = False

        try:
            while True:
                elapsed = time.monotonic() - window_start_mono
                remaining = self.window_seconds - elapsed

                if remaining <= 0:
                    self._emit(acc, window_start_dt, elapsed, on_window)
                    acc = _WindowAccumulator(self.top_n, self.max_tracked_keys)
                    window_start_mono = time.monotonic()
                    window_start_dt = datetime.now()
                    if source_done:
                        break
                    continue

                # 每轮最多等待 0.2 秒，保证窗口边界与停止信号的及时响应
                try:
                    pkt = self.queue.get(timeout=min(0.2, remaining))
                except Empty:
                    pkt = None
                if pkt is not None:
                    acc.add(pkt)
                    self.consumed_packets += 1

                if self.is_source_finished is not None and not source_done:
                    if self.is_source_finished() and self.queue.empty():
                        # 数据源结束：先把剩余报文并入，再输出最后一个窗口
                        self._drain(acc)
                        self._emit(acc, window_start_dt,
                                   time.monotonic() - window_start_mono, on_window)
                        source_done = True
                        logger.info("数据源结束，消费者线程收尾完成")
                        break

                if stop_event.is_set():
                    # 优雅退出：先排空队列，避免丢掉最后一批报文
                    self._drain(acc)
                    self._emit(acc, window_start_dt,
                               time.monotonic() - window_start_mono, on_window)
                    logger.info("收到停止信号，消费者线程收尾完成")
                    break
        except Exception:  # pragma: no cover - 保证线程不会静默死亡
            logger.exception("消费者线程异常退出")
            raise
        finally:
            logger.info("消费者线程退出: 处理 %d 个包, 产出 %d 个窗口",
                        self.consumed_packets, self.window_count)

    # ------------------------------------------------------------------ #
    def _emit(
        self,
        acc: _WindowAccumulator,
        start_dt: datetime,
        elapsed: float,
        on_window: Callable[[WindowStats], None],
    ) -> None:
        """输出一个窗口结果（空窗口按配置决定是否上报）。"""
        if acc.packet_count == 0 and not self.record_empty:
            return
        stats = acc.finalize(start_dt, datetime.now(), elapsed)
        self.window_count += 1
        if stats.truncated:
            logger.warning("窗口内不同 IP/端口数超过 %d，Top-N 统计已截断（总包数仍准确）",
                           self.max_tracked_keys)
        try:
            on_window(stats)
        except Exception:  # pragma: no cover - 单窗口失败不应终止整体监测
            logger.exception("处理统计窗口时发生异常，已跳过该窗口")


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.stats`` 自检：用桩对象验证聚合与输出格式。"""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    class _Stub:
        """最小报文桩：仅提供 getlayer / wirelen 接口。"""

        def __init__(self, size, layers=()):
            self.wirelen = size
            self._layers = list(layers)

        def getlayer(self, layer):
            for obj in self._layers:
                if isinstance(obj, layer):
                    return obj
            return None

    acc = _WindowAccumulator()
    for _ in range(10):
        acc.add(_Stub(120))
    stats = acc.finalize(datetime.now(), datetime.now(), 5.0)
    print(stats.format_summary(-0.05))
    print("特征名:", ", ".join(FEATURE_NAMES))
    print("特征向量:", stats.to_vector())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
