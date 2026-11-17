# -*- coding: utf-8 -*-
"""界面层（表现层）。

包含两种实现，接口一致（见 :class:`netflow.ui.base.BaseUI`）：

* :class:`~netflow.ui.dashboard.DashboardUI` —— 全屏 ANSI 仪表盘（默认）；
* :class:`~netflow.ui.plain.PlainUI` —— 纯文本逐行输出（重定向 / 老终端）。

:func:`create_ui` 会按终端能力自动选择，因此业务层不需要关心用哪种界面。
"""

from __future__ import annotations

from .base import BaseUI, create_ui
from .state import DashboardState, format_bytes, format_count, format_duration

__all__ = [
    "BaseUI",
    "create_ui",
    "DashboardState",
    "format_bytes",
    "format_count",
    "format_duration",
]
