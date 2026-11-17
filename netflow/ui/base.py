# -*- coding: utf-8 -*-
"""界面基类与工厂。

界面层只做「展示」与「按键采集」两件事，所有业务数据都从
:class:`netflow.ui.state.DashboardState` 读取，因此新增一种界面
（例如导出 HTML 报告）只需实现本模块的 :class:`BaseUI` 接口，不影响业务代码。
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Sequence

from ..model import ScoreResult
from ..stats import WindowStats

logger = logging.getLogger(__name__)


class BaseUI:
    """界面抽象基类。

    Parameters
    ----------
    state:
        :class:`netflow.ui.state.DashboardState` 实例（线程安全）。
    config:
        :class:`netflow.config.AppConfig`（可为 ``None``，便于单元测试）。
    """

    #: 界面名称，用于日志
    name: str = "base"

    def __init__(self, state, config=None) -> None:
        self.state = state
        self.config = config

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """界面启动（进入全屏、隐藏光标等）。"""
        return

    def stop(self) -> None:
        """界面结束（恢复终端状态）。"""
        return

    # ------------------------------------------------------------------ #
    # 数据回调
    # ------------------------------------------------------------------ #
    def on_window(self, window: WindowStats, result: Optional[ScoreResult] = None) -> None:
        """收到一个完成的统计窗口（默认只更新状态容器）。"""
        self.state.record_window(window, result)

    def render(self, snapshot: Dict[str, Any]) -> None:
        """按刷新周期重绘（纯文本界面为空实现）。"""
        return

    def poll_keys(self) -> Optional[str]:
        """非阻塞读取按键；返回 ``None`` 表示无按键。"""
        return None

    # ------------------------------------------------------------------ #
    # 文本输出
    # ------------------------------------------------------------------ #
    def show_banner(self, lines: Sequence[str]) -> None:
        """启动横幅。"""
        print("\n".join(lines))

    def show_summary(self, summary: Dict[str, Any]) -> None:
        """退出统计。"""
        for label, value in summary.get("rows", []):
            print("{0}: {1}".format(label, value))

    def show_error(self, message: str) -> None:
        """在界面可用的情况下报告错误。"""
        logger.error(message)


def resolve_ui_mode(config) -> str:
    """把 ``auto`` 解析为具体的 ``tui`` 或 ``plain``。

    判定依据：stdout 支持 ANSI 转义，且 stdin 支持非阻塞按键读取。
    这样把输出重定向到文件时不会写进一堆控制字符。
    """
    from .ansi import supports_ansi
    from .keys import KeyReader

    mode = getattr(config, "ui", "auto") if config is not None else "auto"
    if mode in ("tui", "plain"):
        return mode
    if not supports_ansi():
        return "plain"
    with KeyReader() as reader:
        return "tui" if reader.enabled else "plain"


def create_ui(config, state) -> BaseUI:
    """按配置创建界面实例（``auto`` 会自动降级到纯文本）。"""
    from .dashboard import DashboardUI
    from .plain import PlainUI

    mode = resolve_ui_mode(config)
    if mode == "plain":
        logger.debug("界面模式: plain")
        return PlainUI(state, config)
    logger.debug("界面模式: tui")
    return DashboardUI(state, config)


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.ui.base`` 自检：报告自动选择的界面类型。"""
    from .state import DashboardState

    ui = create_ui(None, DashboardState())
    print("自动选择的界面:", ui.name)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
