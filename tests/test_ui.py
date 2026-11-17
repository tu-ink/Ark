# -*- coding: utf-8 -*-
"""界面层单元测试：显示宽度、面板定宽、格式化辅助函数。"""

from __future__ import annotations

import os
import sys
import unittest

from tests import helpers
from tests.helpers import make_window

from netflow.model import ScoreResult
from netflow.ui.ansi import display_width, pad, truncate, visible_width
from netflow.ui.dashboard import render_dashboard, render_help
from netflow.ui.state import DashboardState, format_bytes, format_duration

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

def setUpModule() -> None:
    helpers.silence_logging()

def tearDownModule() -> None:
    helpers.restore_logging()
    helpers.cleanup()
# ====================================================================== #
# 界面层
# ====================================================================== #
class TestAnsi(unittest.TestCase):
    def test_display_width_counts_cjk_as_two(self) -> None:
        self.assertEqual(display_width("abc"), 3)
        self.assertEqual(display_width("中文"), 4)
        self.assertEqual(display_width("a中"), 3)

    def test_pad_and_truncate(self) -> None:
        self.assertEqual(display_width(pad("中文", 10)), 10)
        self.assertEqual(display_width(pad("abc", 5, "right")), 5)
        self.assertEqual(display_width(truncate("中文中文中文", 8)), 8)
        self.assertLessEqual(display_width(truncate("abcdef", 4)), 4)


class TestDashboard(unittest.TestCase):
    @staticmethod
    def _snapshot(state: DashboardState):
        snapshot = state.snapshot(log_feed=[("INFO", "测试事件")])
        snapshot["source_desc"] = "网卡 eth0"
        snapshot["detector_desc"] = "异常检测: 已启用"
        snapshot["threshold"] = 0.0
        return snapshot

    def _state(self, windows: int = 6) -> DashboardState:
        state = DashboardState(history=20)
        for index in range(windows):
            anomaly = index >= windows - 2
            state.record_window(
                make_window(1000 + index),
                ScoreResult(score=-0.3 if anomaly else 0.15, is_anomaly=anomaly,
                            threshold=0.0, enabled=True))
        return state

    def test_fixed_size_for_various_terminals(self) -> None:
        snapshot = self._snapshot(self._state())
        for width, height in ((80, 24), (100, 30), (120, 40), (60, 16), (200, 60)):
            lines = render_dashboard(snapshot, width, height, style="ascii", color=False)
            self.assertEqual(len(lines), height, "行数必须等于终端高度")
            for line in lines:
                self.assertEqual(display_width(line), width,
                                 "每行显示宽度必须等于终端宽度: {0!r}".format(line[:40]))

    def test_no_content_truncation(self) -> None:
        """面板内容不得被截断（截断会在边框前留下省略号 ``..``）。"""
        lines = render_dashboard(self._snapshot(self._state()), 100, 30, color=False)
        for line in lines:
            self.assertNotIn("..|", line, "行内容超出面板宽度被截断: {0!r}".format(line))
            self.assertNotIn("..+", line, "面板标题行宽度溢出: {0!r}".format(line))

    def test_unicode_style_is_aligned(self) -> None:
        lines = render_dashboard(self._snapshot(self._state()), 100, 30,
                                 style="unicode", color=False)
        self.assertEqual(len(lines), 30)
        for line in lines:
            self.assertEqual(display_width(line), 100)

    def test_empty_state_renders(self) -> None:
        state = DashboardState()
        lines = render_dashboard(self._snapshot(state), 90, 24)
        self.assertEqual(len(lines), 24)
        self.assertTrue(any("等待第一个统计窗口" in line for line in lines))

    def test_color_mode_keeps_width(self) -> None:
        lines = render_dashboard(self._snapshot(self._state()), 100, 30, color=True)
        for line in lines:
            # ANSI 颜色序列不计入可见宽度
            self.assertEqual(visible_width(line), 100)

    def test_help_page_is_fixed_size(self) -> None:
        lines = render_help(100, 30, "ascii")
        self.assertEqual(len(lines), 30)
        for line in lines:
            self.assertEqual(display_width(line), 100)


class TestFormatHelpers(unittest.TestCase):
    def test_format_duration(self) -> None:
        self.assertEqual(format_duration(0), "00:00:00")
        self.assertEqual(format_duration(61), "00:01:01")
        self.assertEqual(format_duration(3661), "01:01:01")

    def test_format_bytes(self) -> None:
        self.assertEqual(format_bytes(512), "512 B")
        self.assertTrue(format_bytes(2048).endswith("KB"))
        self.assertTrue(format_bytes(5 * 1024 ** 2).endswith("MB"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
