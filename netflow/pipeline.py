# -*- coding: utf-8 -*-
"""编排层（pipeline）：把各层串成一条完整的监测流水线。

职责边界
--------
本层是**唯一**知道全部模块如何协作的地方，其他层互不知情：

* 采集层只负责把包搬进队列；
* 统计层只负责把包聚合成窗口；
* 检测层只负责给窗口打分；
* 存储层只负责落库；
* 界面层只负责展示状态。

因此替换任意一层（例如把 SQLite 换成 PostgreSQL、把 TUI 换成别的界面）
都不需要改动其他层。
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from typing import Any, Dict, List, Optional

from . import __version__
from .capture import PacketCapture
from .config import AppConfig
from .database import TrafficDB
from .logs import get_ring_handler
from .model import AnomalyDetector
from .sample import ensure_sample_pcap
from .stats import StatsCollector, WindowStats
from .ui import (
    BaseUI,
    DashboardState,
    create_ui,
    format_count,
    format_duration,
)

logger = logging.getLogger(__name__)

_SEPARATOR = "=" * 78


class MonitorApp:
    """一次监测运行的完整生命周期。

    Parameters
    ----------
    config:
        合并后的配置对象。
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.state = DashboardState(history=config.history)
        self.ui: BaseUI = create_ui(config, self.state)

        self.db: Optional[TrafficDB] = None
        self.detector: Optional[AnomalyDetector] = None
        self.capture: Optional[PacketCapture] = None
        self.collector: Optional[StatsCollector] = None

        self._stop_event = threading.Event()
        self._consumer: Optional[threading.Thread] = None
        self._started_at = 0.0

    # ------------------------------------------------------------------ #
    # 准备
    # ------------------------------------------------------------------ #
    def prepare(self) -> None:
        """打开数据库、准备模型（必要时引导训练）、装配采集与统计。"""
        cfg = self.config

        # 演示模式：准备示例 pcap 并切换为回放
        if cfg.demo and not cfg.replay:
            try:
                cfg.replay = ensure_sample_pcap()
                cfg.replay_speed = cfg.replay_speed or 1.0
                logger.info("演示模式：回放 %s（倍速 %.1f）", cfg.replay, cfg.replay_speed)
            except Exception:
                logger.exception("准备示例数据失败，请检查 Scapy 是否安装")

        # 模型缺失时自动训练引导模型，保证开箱即可运行
        if not os.path.isfile(cfg.model) and cfg.auto_train and not cfg.strict_model:
            from .train_model import bootstrap_model  # 延迟导入：训练依赖 pandas

            bootstrap_model(cfg.model, cfg.window)

        self.db = TrafficDB(cfg.db)
        self.detector = AnomalyDetector(
            model_path=cfg.model, threshold=cfg.threshold, strict=cfg.strict_model)

        self.capture = PacketCapture(
            iface=cfg.iface,
            bpf_filter=cfg.bpf,
            queue_maxsize=cfg.queue_size,
            replay_file=cfg.replay,
            replay_speed=cfg.replay_speed,
            packet_limit=cfg.packet_limit,
            promisc=cfg.promisc,
        )
        self.collector = StatsCollector(
            packet_queue=self.capture.queue,
            window_seconds=cfg.window,
            top_n=cfg.top_n,
            record_empty=cfg.record_empty,
            is_source_finished=self.capture.is_finished,
        )

        # 界面静态信息
        self.state.source_desc = (
            "pcap 回放 {0}".format(os.path.basename(cfg.replay)) if cfg.replay
            else "网卡 {0}".format(cfg.iface or "默认"))
        self.state.detector_desc = self.detector.describe()
        self.state.window_seconds = cfg.window
        self.state.threshold = self.detector.threshold
        self.state.calibration = self.detector.calibration()

    # ------------------------------------------------------------------ #
    # 单个窗口的处理链：评分 → 落库 → 展示
    # ------------------------------------------------------------------ #
    def _on_window(self, window: WindowStats) -> None:
        result = None
        if self.detector is not None:
            result = self.detector.score_window(window)

        is_anomaly = bool(result is not None and result.is_anomaly and result.score is not None)
        if self.db is not None:
            try:
                self.db.insert_window(
                    window,
                    anomaly_score=result.score if result else None,
                    is_anomaly=is_anomaly,
                    threshold=result.threshold if result else None,
                    message="Isolation Forest 异常评分低于阈值" if is_anomaly else None,
                )
            except Exception:
                logger.exception("写入数据库失败（统计仍会展示）")

        self.ui.on_window(window, result)

    # ------------------------------------------------------------------ #
    # 运行
    # ------------------------------------------------------------------ #
    def run(self) -> int:
        """启动一切并进入主循环，返回进程退出码。"""
        try:
            self.prepare()
        except Exception:
            logger.exception("初始化失败")
            return 2

        assert self.capture is not None and self.collector is not None

        self.ui.show_banner(self._banner_lines())
        if self.ui.name == "tui":
            time.sleep(0.8)  # 让用户看清启动信息，再切到全屏仪表盘
        self.ui.start()

        self._install_signal_handlers()
        self._started_at = time.monotonic()

        self._consumer = threading.Thread(
            target=self.collector.run, args=(self._stop_event, self._on_window),
            name="stats-consumer", daemon=True)

        exit_code = 0
        try:
            self.capture.start()
            self._consumer.start()
            self._main_loop()
        except KeyboardInterrupt:  # 兜底：某些终端下信号直接抛异常
            self._stop_event.set()
        except Exception:
            logger.exception("监测过程中发生未预期异常")
            exit_code = 1
        finally:
            exit_code = self._shutdown() or exit_code

        return exit_code

    def _main_loop(self) -> None:
        """主循环：轮询按键、刷新界面、处理超时退出。"""
        cfg = self.config
        assert self._consumer is not None
        deadline = (self._started_at + cfg.duration) if cfg.duration else None

        while self._consumer.is_alive():
            self.ui.poll_keys()
            if self.state.quit_requested:
                logger.info("收到退出请求，正在优雅退出 ...")
                break
            if deadline is not None and time.monotonic() >= deadline:
                logger.info("已达到运行时长 %.1f 秒，准备停止", cfg.duration)
                break
            self._refresh_capture_state()
            self.ui.render(self.state.snapshot(log_feed=self._log_feed()))
            self._stop_event.wait(cfg.refresh)

    def _refresh_capture_state(self) -> None:
        """把采集层计数器同步到界面状态。"""
        if self.capture is None:
            return
        snapshot = self.capture.snapshot()
        self.state.update_capture({
            "captured": snapshot["captured"],
            "enqueued": snapshot["enqueued"],
            "dropped": snapshot["dropped"],
            "errors": snapshot["errors"],
            "queue": self.capture.queue_depth(),
            "capacity": self.capture.queue_maxsize(),
            "rate": self.capture.capture_rate(),
        })

    @staticmethod
    def _log_feed(limit: int = 6) -> List[Any]:
        """取最近若干条日志用于界面事件面板。"""
        handler = get_ring_handler()
        if handler is None:
            return []
        return [(level, message) for _ts, level, _name, message
                in handler.snapshot(limit=limit)]

    # ------------------------------------------------------------------ #
    # 信号与收尾
    # ------------------------------------------------------------------ #
    def _install_signal_handlers(self) -> None:
        def _handler(signum, _frame):
            if self._stop_event.is_set():
                logger.warning("再次收到信号 %s，强制退出", signum)
                self.ui.stop()
                os._exit(1)
            logger.info("收到信号 %s，正在优雅退出（再按一次可强制退出）...", signum)
            self._stop_event.set()
            self.state.request_quit()

        for name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, name):
                try:
                    signal.signal(getattr(signal, name), _handler)
                except (ValueError, OSError):  # pragma: no cover - 非主线程/平台限制
                    logger.debug("无法注册信号 %s", name)

    def _shutdown(self) -> int:
        """停止采集、等待消费者收尾、输出运行统计。"""
        assert self.capture is not None and self.collector is not None

        self._stop_event.set()
        if self._consumer is not None:
            self._consumer.join(timeout=max(10.0, self.config.window + 5.0))
            if self._consumer.is_alive():
                logger.warning("消费者线程未在超时内退出（可能仍有大量积压报文）")
        self.capture.stop()
        self._refresh_capture_state()
        self.state.set_status("已停止")

        elapsed = time.monotonic() - self._started_at
        summary = self._summary(elapsed)

        self.ui.stop()
        self.ui.show_summary(summary)

        if self.db is not None:
            self.db.close()
        return 0

    # ------------------------------------------------------------------ #
    # 文本
    # ------------------------------------------------------------------ #
    def _banner_lines(self) -> List[str]:
        cfg = self.config
        lines = [
            _SEPARATOR,
            "基于 Isolation Forest 的网络流量监测系统  v{0}".format(__version__),
            _SEPARATOR,
        ]
        for label, value in cfg.describe():
            lines.append("{0:<12}: {1}".format(label, value))
        if self.detector is not None:
            lines.append("{0:<12}: {1}".format("异常检测", self.detector.describe()))
            calibration = self.detector.calibration()
            if calibration:
                lines.append("{0:<12}: {1}".format(
                    "阈值标定",
                    "  ".join("{0}={1:+.4f}".format(k, v) for k, v in calibration.items())))
        names = self.state_feature_names()
        lines.append("{0:<12}: {1} 维 -> {2}".format(
            "特征向量", len(names), ", ".join(names)))
        lines.append(_SEPARATOR)
        return lines

    @staticmethod
    def state_feature_names() -> List[str]:
        """特征名列表（供横幅展示）。"""
        from .stats import FEATURE_NAMES

        return list(FEATURE_NAMES)

    def _summary(self, elapsed: float) -> Dict[str, Any]:
        assert self.capture is not None and self.collector is not None
        stats = self.capture.snapshot()
        db_summary = self.db.summary() if self.db is not None else {}
        dropped = stats["dropped"]
        captured = stats["captured"]
        drop_text = "{0}".format(format_count(dropped))
        if captured:
            drop_text += "（{0:.2f}%）".format(dropped / captured * 100.0)

        rows = [
            ("运行时长", "{0}（{1:.1f} 秒）".format(format_duration(elapsed), elapsed)),
            ("捕获总包数", format_count(captured)),
            ("入队包数", format_count(stats["enqueued"])),
            ("丢包数", drop_text),
            ("消费包数", format_count(self.collector.consumed_packets)),
            ("统计窗口数", "{0}（数据库累计 {1}）".format(
                self.collector.window_count, db_summary.get("windows", 0))),
            ("异常窗口数", "{0}（数据库累计告警 {1} 条）".format(
                self.state.total_anomalies, db_summary.get("alerts", 0))),
            ("平均采集速率", "{0:,.1f} 包/秒".format(captured / elapsed if elapsed > 0 else 0.0)),
            ("数据库文件", self.config.db),
        ]
        hints = [
            "查询命令  : python main.py -d {0} --show-stats 20".format(self.config.db),
            "            python main.py -d {0} --show-alerts 20".format(self.config.db),
        ]
        if dropped > 0:
            hints.append("提示      : 存在丢包，可增大 --queue-size 或收窄 --bpf 过滤范围。")
        return {"rows": rows, "hints": hints, "elapsed": elapsed}
