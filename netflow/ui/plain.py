# -*- coding: utf-8 -*-
"""纯文本输出（plain）：不带 ANSI 控制序列的控制台模式。

适用场景：

* 输出被重定向到文件或管道（``python main.py > log.txt``）；
* 终端不支持 ANSI（老式 conhost、某些 IDE 控制台）；
* 用户显式指定 ``--ui plain``。

输出格式与设计要求完全一致，每完成一个窗口打印一行摘要，异常时追加 ``[ALERT]``。
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict, Optional, Sequence

from ..model import ScoreResult
from ..stats import WindowStats
from .base import BaseUI

logger = logging.getLogger(__name__)


class PlainUI(BaseUI):
    """逐行打印的纯文本界面。"""

    name = "plain"

    def __init__(self, state, config=None) -> None:
        super().__init__(state, config)

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self.state.set_status("采集中")

    def stop(self) -> None:
        self.state.set_status("已停止")

    # ------------------------------------------------------------------ #
    def on_window(self, window: WindowStats, result: Optional[ScoreResult] = None) -> None:
        """每完成一个窗口输出一行摘要，异常时追加告警行。"""
        super().on_window(window, result)
        score = result.score if result else None
        print(window.format_summary(score))
        if window.unique_src_ips > 1:
            print("    " + window.format_top(5))
        if result is not None and result.is_anomaly:
            threshold = ("{0:.4f}".format(result.threshold)
                         if result.threshold is not None else "N/A")
            print("[ALERT] 异常流量 detected! 分数: {0} (阈值: {1})".format(
                result.format_score(), threshold))
            print("    " + window.format_top(5))
        try:
            sys.stdout.flush()
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------ #
    def show_banner(self, lines: Sequence[str]) -> None:
        print("\n".join(lines))
        print()
        try:
            sys.stdout.flush()
        except Exception:  # pragma: no cover
            pass

    def show_summary(self, summary: Dict[str, Any]) -> None:
        print()
        print("=" * 78)
        print("运行统计")
        print("=" * 78)
        for label, value in summary.get("rows", []):
            print("{0:<14}: {1}".format(label, value))
        for hint in summary.get("hints", []):
            print(hint)
        print("=" * 78)

    def poll_keys(self) -> Optional[str]:
        """纯文本模式不支持键盘交互（便于重定向）。"""
        return None

    def render(self, snapshot: Dict[str, Any]) -> None:
        """纯文本模式不需要重绘。"""
        return


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.ui.plain`` 自检：打印一个示例窗口。"""
    from datetime import datetime

    from ..stats import WindowStats as _WindowStats
    from .state import DashboardState

    ui = PlainUI(DashboardState())
    ui.start()
    now = datetime.now()
    window = _WindowStats(now, now, 5.0, 1200, 850000, 936, 240, 24, 144, 45,
                          top_src_ips=[("192.168.10.37", 75)], top_dst_ports=[(443, 535)])
    ui.on_window(window, ScoreResult(score=-0.25, is_anomaly=True, threshold=-0.1, enabled=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
