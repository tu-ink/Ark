# -*- coding: utf-8 -*-
"""界面状态（state）：采集/统计/检测的实时快照容器。

设计要点
--------
* **写入方**是消费者线程（每个窗口一次）与主循环（周期性刷新计数器）；
* **读取方**是 UI 渲染循环；
* 两者用一把可重入锁串行化，并且 :meth:`DashboardState.snapshot` 只返回
  不可变/复制后的数据，渲染期间不会看到半更新的状态。

把状态集中在一个对象里，使得「同一份数据既能画全屏 TUI，也能走纯文本输出」，
UI 层只负责展示，不参与业务。
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from ..model import ScoreResult
from ..stats import FEATURE_NAMES, WindowStats

#: 状态文案
STATUS_RUNNING = "采集中"
STATUS_PAUSED = "已暂停"
STATUS_STOPPED = "已停止"
STATUS_FINISHED = "数据源已结束"


class DashboardState:
    """线程安全的界面状态容器。

    Parameters
    ----------
    history:
        TUI 趋势图保留的窗口条数。
    alert_history:
        界面保留的告警条数。
    log_lines:
        界面事件面板保留的日志条数。
    """

    def __init__(self, history: int = 60, alert_history: int = 12, log_lines: int = 8) -> None:
        self._lock = threading.RLock()
        self._history = int(history)
        self._alert_history = int(alert_history)
        self._log_lines = int(log_lines)

        self.windows: Deque[Tuple[WindowStats, Optional[ScoreResult]]] = deque(maxlen=history)
        self.alerts: Deque[Tuple[WindowStats, ScoreResult]] = deque(maxlen=alert_history)

        self.started_at = time.time()
        self.stopped_at: Optional[float] = None
        self.status = STATUS_RUNNING
        self.paused = False
        self.quit_requested = False

        # 累计量（由 pipeline 写入）
        self.total_windows = 0
        self.total_anomalies = 0
        self.total_packets = 0
        self.total_bytes = 0

        # 采集层快照
        self.capture: Dict[str, Any] = {
            "captured": 0, "enqueued": 0, "dropped": 0, "errors": 0,
            "queue": 0, "capacity": 0, "rate": 0.0,
        }

        # 静态信息（启动时写入一次）
        self.source_desc = ""
        self.detector_desc = ""
        self.window_seconds = 5.0
        self.threshold: Optional[float] = None
        self.calibration: Dict[str, float] = {}

    # ------------------------------------------------------------------ #
    # 写入（消费者线程 / 主循环）
    # ------------------------------------------------------------------ #
    def record_window(self, window: WindowStats, result: Optional[ScoreResult] = None) -> None:
        """记录一个新完成的时间窗口。"""
        with self._lock:
            self.windows.append((window, result))
            self.total_windows += 1
            self.total_packets += window.packet_count
            self.total_bytes += window.byte_count
            if result is not None and result.is_anomaly:
                self.total_anomalies += 1
                self.alerts.append((window, result))

    def update_capture(self, snapshot: Dict[str, Any]) -> None:
        """更新采集层计数器快照。"""
        with self._lock:
            self.capture.update(snapshot)

    def set_status(self, status: str) -> None:
        with self._lock:
            self.status = status
            if status == STATUS_STOPPED and self.stopped_at is None:
                self.stopped_at = time.time()

    def set_paused(self, paused: bool) -> None:
        with self._lock:
            self.paused = bool(paused)
            self.status = STATUS_PAUSED if paused else STATUS_RUNNING

    def toggle_pause(self) -> bool:
        """切换暂停状态并返回切换后的值（暂停仅影响界面刷新节奏）。"""
        with self._lock:
            self.paused = not self.paused
            self.status = STATUS_PAUSED if self.paused else STATUS_RUNNING
            return self.paused

    def request_quit(self) -> None:
        with self._lock:
            self.quit_requested = True

    def clear_history(self) -> None:
        """清空趋势与告警历史（快捷键 r）。"""
        with self._lock:
            self.windows.clear()
            self.alerts.clear()
            self.total_windows = 0
            self.total_anomalies = 0
            self.total_packets = 0
            self.total_bytes = 0

    # ------------------------------------------------------------------ #
    # 读取（UI 渲染线程）
    # ------------------------------------------------------------------ #
    def snapshot(self, log_feed: Optional[List[Tuple[str, str]]] = None) -> Dict[str, Any]:
        """返回一份渲染用的状态快照（内部数据已复制）。"""
        with self._lock:
            windows = list(self.windows)
            alerts = list(self.alerts)
            now = time.time()
            elapsed = (self.stopped_at or now) - self.started_at
            return {
                "status": self.status,
                "paused": self.paused,
                "elapsed": max(elapsed, 0.0),
                "windows": windows,
                "alerts": alerts,
                "current": windows[-1] if windows else None,
                "scores": [(item[1].score if item[1] else None) for item in windows],
                "totals": {
                    "windows": self.total_windows,
                    "anomalies": self.total_anomalies,
                    "packets": self.total_packets,
                    "bytes": self.total_bytes,
                },
                "capture": dict(self.capture),
                "source_desc": self.source_desc,
                "detector_desc": self.detector_desc,
                "window_seconds": self.window_seconds,
                "threshold": self.threshold,
                "calibration": dict(self.calibration),
                "logs": list(log_feed or []),
            }

    def latest(self) -> Optional[Tuple[WindowStats, Optional[ScoreResult]]]:
        """返回最近一个窗口（无数据时返回 ``None``）。"""
        with self._lock:
            return self.windows[-1] if self.windows else None

    def duration(self) -> float:
        """已运行时长（秒）。"""
        with self._lock:
            return max((self.stopped_at or time.time()) - self.started_at, 0.0)


# ---------------------------------------------------------------------- #
# 派生工具：供 UI 复用的纯函数
# ---------------------------------------------------------------------- #
def score_series(snapshot: Dict[str, Any], limit: int) -> List[Optional[float]]:
    """取出最近 ``limit`` 个窗口的分数序列。"""
    return list(snapshot.get("scores") or [])[-limit:]


def format_duration(seconds: float) -> str:
    """把秒数格式化为 ``HH:MM:SS``。"""
    seconds = max(int(seconds), 0)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return "{0:02d}:{1:02d}:{2:02d}".format(hours, minutes, secs)


def format_bytes(value: float) -> str:
    """把字节数格式化为带单位的可读文本。"""
    units = ("B", "KB", "MB", "GB", "TB")
    value = float(value)
    for unit in units:
        if abs(value) < 1024.0 or unit == units[-1]:
            return "{0:.1f} {1}".format(value, unit) if unit != "B" else "{0:.0f} B".format(value)
        value /= 1024.0
    return "{0:.1f} B".format(value)


def format_count(value: float) -> str:
    """把计数格式化为带千分位的文本。"""
    return "{0:,.0f}".format(float(value))


def feature_names() -> Tuple[str, ...]:
    """暴露特征名，供帮助面板展示。"""
    return FEATURE_NAMES
