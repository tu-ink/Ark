# -*- coding: utf-8 -*-
"""采集层（capture）：把网卡上的报文尽可能快地搬进一个**有界队列**。

两种数据源
----------
1. 实时模式（默认）：Scapy ``AsyncSniffer`` 抓取指定网卡的流量；
2. 回放模式：从 pcap 文件按原始时间戳回放，用于离线演示、模块联调与
   可复现实验（不需要管理员权限，也不需要 Npcap）。

设计要点
--------
* 抓包回调 :meth:`PacketCapture._on_packet` 只做「计数 + 入队」两件事，
  不做协议解析、不写磁盘、不打印日志，避免阻塞抓包线程；
* 队列为有界队列（默认 ``maxsize=10000``），队满时丢弃**新包**并计数
  （drop-tail 策略），保证抓包线程永远不会因为下游处理慢而被阻塞；
* 所有计数器由 ``threading.Lock`` 保护，主线程可随时安全读取快照。
"""

from __future__ import annotations

import logging
import threading
import time
from queue import Full, Queue
from typing import Dict, List, Optional

try:  # Scapy 为可选依赖：缺少时采集不可用，但统计/存储/检测模块仍可导入与测试
    from scapy.all import AsyncSniffer, conf  # type: ignore
    from scapy.utils import PcapReader  # type: ignore

    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR: Optional[Exception] = None
except Exception as exc:  # pragma: no cover - 仅在未安装 scapy 时触发
    AsyncSniffer = None  # type: ignore
    conf = None  # type: ignore
    PcapReader = None  # type: ignore
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = exc

logger = logging.getLogger(__name__)

#: 默认 BPF 过滤器。注意 ``icmp`` 只匹配 IPv4，如需 IPv6 请追加 ``or icmp6``
DEFAULT_BPF_FILTER = "tcp or udp or icmp"

#: 丢包日志的打印间隔（每丢弃多少个包提示一次），避免日志刷屏
_DROP_LOG_INTERVAL = 5000


def ensure_scapy() -> None:
    """在真正需要抓包前检查 Scapy 是否可用，给出可操作的错误提示。"""
    if not SCAPY_AVAILABLE:
        raise RuntimeError(
            "未检测到 Scapy（或导入失败）：{0}\n"
            "请执行:  python -m pip install -r requirements.txt\n"
            "Windows 下实时抓包还需安装 Npcap 驱动（https://npcap.com/）"
            "并以管理员身份运行。".format(SCAPY_IMPORT_ERROR)
        )


def list_interfaces() -> List[str]:
    """返回本机可用于抓包的网卡名称列表（Scapy 不可用时返回空列表）。"""
    if not SCAPY_AVAILABLE:
        return []
    try:
        return sorted(conf.ifaces.keys())
    except Exception:  # pragma: no cover - 取决于底层平台实现
        logger.exception("枚举网卡失败")
        return []


class PacketCapture:
    """把数据包从网卡（或 pcap 文件）搬进有界队列。

    Parameters
    ----------
    iface:
        实时模式下监听的网卡名；``None`` 表示使用 Scapy 默认网卡。
    bpf_filter:
        BPF 过滤表达式，在**内核态**先行过滤，可显著降低用户态开销。
    queue_maxsize:
        有界队列容量，队满时丢弃新包。
    replay_file:
        若不为 ``None``，则进入回放模式，从该 pcap 文件读取报文而不抓网卡。
    replay_speed:
        回放倍速。``0`` 表示不限速（尽快读完）；``1.0`` 表示按原始时间间隔回放。
    packet_limit:
        采集到指定数量的包后自动停止，``None`` 表示不限制。
    promisc:
        实时模式下是否开启混杂模式。
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        bpf_filter: str = DEFAULT_BPF_FILTER,
        queue_maxsize: int = 10000,
        replay_file: Optional[str] = None,
        replay_speed: float = 0.0,
        packet_limit: Optional[int] = None,
        promisc: bool = True,
    ) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.queue: "Queue" = Queue(maxsize=int(queue_maxsize))
        self.replay_file = replay_file
        self.replay_speed = float(replay_speed)
        self.packet_limit = int(packet_limit) if packet_limit else None
        self.promisc = bool(promisc)

        self.stats: Dict[str, int] = {
            "captured": 0,   # 交给回调的包数（含被丢弃的）
            "enqueued": 0,   # 成功入队的包数
            "dropped": 0,    # 因队满被丢弃的包数
            "errors": 0,     # 回调内部异常次数
        }
        #: 数据源自行结束时（回放读完 / 达到 packet_limit）被置位
        self.finished = threading.Event()

        self._lock = threading.Lock()
        self._sniffer = None
        self._replay_thread: Optional[threading.Thread] = None
        self._running = False
        self._start_time: Optional[float] = None

    # ------------------------------------------------------------------ #
    # 抓包回调（性能敏感路径：只做计数与入队）
    # ------------------------------------------------------------------ #
    def _on_packet(self, pkt) -> None:
        """抓包回调：入队 + 计数，每个报文只加一次锁。

        原实现先给 captured 加锁、入队后再给 enqueued 加锁，高包速率下
        锁开销占回调耗时的相当比例。这里把两次计数合并进同一个临界区，
        锁获取次数减半。
        """
        try:
            self.queue.put_nowait(pkt)
            with self._lock:
                stats = self.stats
                stats["captured"] += 1
                stats["enqueued"] += 1
                captured = stats["captured"]
        except Full:
            with self._lock:
                stats = self.stats
                stats["captured"] += 1
                stats["dropped"] += 1
                captured = stats["captured"]
                dropped = stats["dropped"]
            # 丢包提示按数量限流，避免日志成为新的瓶颈
            if dropped % _DROP_LOG_INTERVAL == 0:
                logger.warning(
                    "队列已满，累计丢弃 %d 个包（消费速度跟不上采集速度）", dropped
                )
        except Exception:  # pragma: no cover - 防御性兜底
            with self._lock:
                self.stats["errors"] += 1
            logger.exception("入队失败")
            return

        # 达到包数上限后由 Scapy 的 stop_filter 结束抓包（回调内不调用 stop，
        # 避免在 sniffer 线程内 join 自身造成死锁）
        if self.packet_limit is not None and captured >= self.packet_limit:
            self.finished.set()

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """启动数据源（实时抓包线程或 pcap 回放线程）。"""
        if self._running:
            raise RuntimeError("采集器已在运行中")
        ensure_scapy()
        self._start_time = time.monotonic()
        self._running = True

        if self.replay_file:
            self._replay_thread = threading.Thread(
                target=self._run_replay, name="pcap-replay", daemon=True
            )
            self._replay_thread.start()
            logger.info("回放模式启动: %s (倍速=%s)", self.replay_file,
                        "不限速" if self.replay_speed <= 0 else self.replay_speed)
        else:
            kwargs = dict(
                prn=self._on_packet,
                store=False,
                filter=self.bpf_filter,
                promisc=self.promisc,
            )
            if self.iface:
                kwargs["iface"] = self.iface
            if self.packet_limit is not None:
                kwargs["stop_filter"] = lambda _pkt: self.finished.is_set()
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            logger.info(
                "实时抓包启动: iface=%s, filter=%r, queue_maxsize=%d",
                self.iface or "<默认网卡>", self.bpf_filter, self.queue.maxsize,
            )

    def _run_replay(self) -> None:
        """回放线程：按需限速地把 pcap 中的报文投递到队列。"""
        first_ts: Optional[float] = None
        clock_start = time.monotonic()
        if self.replay_speed <= 0:
            logger.warning(
                "回放倍速为 0（不限速）：报文会在极短时间内全部涌入，"
                "统计窗口将无法对应流量的真实时间轴，仅适合吞吐压力测试。"
            )
        try:
            with PcapReader(self.replay_file) as reader:  # type: ignore[arg-type]
                for pkt in reader:
                    if self.finished.is_set() or not self._running:
                        break
                    if self.replay_speed > 0:
                        ts = float(getattr(pkt, "time", 0.0) or 0.0)
                        if ts:
                            if first_ts is None:
                                first_ts = ts
                                clock_start = time.monotonic()
                            target = (ts - first_ts) / self.replay_speed
                            delay = target - (time.monotonic() - clock_start)
                            if delay > 0:
                                time.sleep(min(delay, 1.0))
                    self._on_packet(pkt)
        except Exception:
            logger.exception("回放 %s 失败", self.replay_file)
        finally:
            self.finished.set()
            logger.info("回放结束: 共投递 %d 个包", self.snapshot()["enqueued"])

    def stop(self, timeout: float = 5.0) -> None:
        """停止采集并等待后台线程退出（可重复调用）。"""
        self.finished.set()
        if self._sniffer is not None:
            try:
                if getattr(self._sniffer, "running", False):
                    self._sniffer.stop(join=False)
            except Exception:  # pragma: no cover - Scapy 内部状态差异
                logger.debug("停止 AsyncSniffer 时出现异常", exc_info=True)
            thread = getattr(self._sniffer, "thread", None)
            if thread is not None and thread.is_alive():
                thread.join(timeout=timeout)
            self._sniffer = None
        if self._replay_thread is not None and self._replay_thread.is_alive():
            self._replay_thread.join(timeout=timeout)
        self._running = False
        logger.info("采集已停止: %s", self.human_summary())

    # ------------------------------------------------------------------ #
    # 状态查询
    # ------------------------------------------------------------------ #
    def snapshot(self) -> Dict[str, int]:
        """返回计数器快照（线程安全）。"""
        with self._lock:
            return dict(self.stats)

    def is_finished(self) -> bool:
        """数据源是否已自然结束（回放读完或达到包数上限）。"""
        return self.finished.is_set()

    def queue_depth(self) -> int:
        """当前队列积压长度。"""
        return self.queue.qsize()

    def queue_maxsize(self) -> int:
        """队列容量。"""
        return int(self.queue.maxsize)

    def capture_rate(self) -> float:
        """自启动以来的平均采集速率（包/秒）。"""
        if not self._start_time:
            return 0.0
        elapsed = time.monotonic() - self._start_time
        if elapsed <= 0:
            return 0.0
        return self.snapshot()["captured"] / elapsed

    def human_summary(self) -> str:
        """人类可读的计数摘要，用于日志与退出统计。"""
        s = self.snapshot()
        drop_rate = (s["dropped"] / s["captured"] * 100.0) if s["captured"] else 0.0
        return (
            "捕获 {captured} 包, 入队 {enqueued} 包, 丢包 {dropped} 包"
            "({rate:.2f}%), 回调异常 {errors} 次".format(rate=drop_rate, **s)
        )


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.capture`` 自检：列出网卡或提示安装依赖。"""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if not SCAPY_AVAILABLE:
        print("Scapy 不可用:", SCAPY_IMPORT_ERROR)
        return 1
    print("Scapy 版本:", conf.version)
    print("可用网卡:", ", ".join(list_interfaces()) or "<未枚举到>")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
