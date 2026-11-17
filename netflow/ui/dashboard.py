# -*- coding: utf-8 -*-
"""全屏 TUI 仪表盘：布局编排与交互。

界面布局（自适应终端高度，空间不足时按优先级裁剪下半部分）::

    + NetFlow Monitor · Isolation Forest ------------------- 网卡 eth0 · 12:00:05 +
    | 状态: ● 采集中  运行 00:00:12  队列 12/10000  丢包 0 (0.00%)  窗口 5  告警 2 |
    +------------------------------------+--------------------------------------+
    | 窗口统计                           | 异常评分                             |
    |  包数        2,197  包速率 439 pps |  当前分数 0.0989   阈值 0.0000       |
    +------------------------------------+--------------------------------------+
    | 协议分布  TCP 72% ##################-----------------                     |
    +------------------------------------+--------------------------------------+
    | 最近告警                                                                   |
    +----------------------------------------------------------------------------+
    | q 退出   p 暂停   r 清空历史   ? 帮助                                       |
    +----------------------------------------------------------------------------+

:func:`render_dashboard` 是**纯函数**：输入状态快照与终端尺寸，输出若干行定宽文本，
因此排版逻辑可以被单元测试逐行断言。具体控件绘制见 :mod:`netflow.ui.widgets`。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from .base import BaseUI
from .keys import KeyReader
from .widgets import (
    _alerts_panel,
    _footer,
    _header,
    _log_panel,
    _panel,
    _protocol_panel,
    _score_panel,
    _side_by_side,
    _stats_panel,
    _status_row,
    _top_panel,
)
from .ansi import pad, strip_ansi, visible_width


# ---------------------------------------------------------------------- #
# 主渲染入口
# ---------------------------------------------------------------------- #
def render_dashboard(
    snapshot: Dict[str, Any],
    width: int,
    height: int,
    style: str = "ascii",
    color: bool = False,
) -> List[str]:
    """把状态快照渲染成 ``height`` 行、每行显示宽度为 ``width`` 的文本。

    参数
    ----
    snapshot:
        :meth:`netflow.ui.state.DashboardState.snapshot` 的返回值。
    width / height:
        终端列数与行数。
    style:
        ``ascii`` 或 ``unicode``。
    color:
        是否插入 ANSI 颜色（纯文本导出时应为 ``False``）。
    """
    width = max(int(width), 40)
    height = max(int(height), 12)

    lines: List[str] = [
        _header(width, snapshot, style, color),
        _status_row(width, snapshot, style, color),
    ]

    # 主区：窗口统计 + 异常评分（并排）
    left_width = width // 2
    right_width = width - left_width
    stats_lines = _stats_panel(left_width, snapshot, style)
    score_lines = _score_panel(right_width, snapshot, style, color)
    main_block = _side_by_side(stats_lines, score_lines, left_width, width, style)

    # 可选分区按「优先级 + 剩余空间」裁剪
    optional: List[List[str]] = []
    optional.append(_protocol_panel(width, snapshot, style))
    top_left, top_right = _top_panel(left_width, right_width, snapshot, style)
    optional.append(_side_by_side(top_left, top_right, left_width, width, style))
    optional.append(_alerts_panel(width, snapshot, style, color))
    optional.append(_log_panel(width, snapshot, style))

    budget = height - len(lines) - 1  # 预留 footer 一行
    if budget >= len(main_block):
        lines.extend(main_block)
        budget -= len(main_block)
        for block in optional:
            if budget >= len(block):
                lines.extend(block)
                budget -= len(block)

    lines.append(_footer(width, style, color))

    # 严格对齐：不足补空行，超出截断。
    # 注意用 visible_width 判断，否则 ANSI 颜色序列会被误当成可见字符而把整行截短。
    while len(lines) < height:
        lines.append(" " * width)
    aligned: List[str] = []
    for line in lines[:height]:
        aligned.append(line if visible_width(line) == width else pad(strip_ansi(line), width))
    return aligned


def render_to_text(snapshot: Dict[str, Any], width: int = 100, height: int = 30,
                   style: str = "ascii") -> str:
    """渲染为多行字符串（便于测试与导出，不带 ANSI 颜色）。"""
    return "\n".join(render_dashboard(snapshot, width, height, style=style, color=False))


# ---------------------------------------------------------------------- #
# 帮助页
# ---------------------------------------------------------------------- #
_HELP_SECTIONS: List[Tuple[str, List[str]]] = [
    ("快捷键", [
        "q / Ctrl+C   退出程序（优雅停止：先排空队列，再输出最后一个窗口）",
        "p            暂停 / 继续界面刷新",
        "r            清空趋势与告警历史（不影响数据库中的记录）",
        "? 或 h       显示 / 隐藏本帮助页",
    ]),
    ("界面说明", [
        "窗口统计   最近一个时间窗口的聚合结果（窗口长度由 -w 指定，默认 5 秒）",
        "异常评分   Isolation Forest 的 decision_function 分数，越低越异常",
        "趋势       最近若干窗口分数构成的迷你趋势图（字符越靠左代表越异常）",
        "协议分布   各协议占比条；SYN 一行为 SYN 标志位占全部包的比例",
        "Top 列表   窗口内出现次数最高的前 5 个源 IP / 目的端口",
    ]),
    ("特征向量（10 维，训练与推理必须完全一致）", [
        "packet_count, byte_count, tcp_ratio, udp_ratio, icmp_ratio,",
        "unique_src_ips, syn_ratio, avg_pkt_len, pps, bps",
    ]),
    ("判定规则", [
        "score < threshold 即判定为异常：写入 alerts 表并在界面高亮。",
        "阈值来自训练产物（sklearn 自带校准点）；可用 --threshold 覆盖。",
    ]),
    ("已知局限（详见 README「检测效果说明」）", [
        "分数饱和：样本再怎么超出训练范围，分数也不会无限降低；",
        "特征稀释：只有少数特征异常时，其余正常特征会抬高路径长度。",
        "因此阈值应按可接受的误报率标定，训练脚本会打印标定参考表。",
    ]),
]


def render_help(width: int, height: int, style: str, color: bool = False) -> List[str]:
    """渲染帮助页（同样是定宽纯文本，便于测试）。"""
    width = max(int(width), 40)
    height = max(int(height), 12)
    body: List[str] = []
    for title, rows in _HELP_SECTIONS:
        if body:
            body.append("")
        body.append("  " + title)
        for row in rows:
            body.append("    " + row)
    panel = _panel("帮助（? 关闭）", body[: max(height - 3, 1)], width, style)

    lines = [_header(width, {"source_desc": "帮助"}, style, color)]
    lines.extend(panel)
    while len(lines) < height:
        lines.append(" " * width)
    return [pad(line, width) for line in lines[:height]]


# ---------------------------------------------------------------------- #
# TUI 界面实现
# ---------------------------------------------------------------------- #
class DashboardUI(BaseUI):
    """全屏 ANSI 仪表盘界面。

    与业务的关系是单向的：业务线程只往 :class:`DashboardState` 写数据，
    本类在渲染循环里读取快照并重绘，因此界面卡顿不会影响采集与统计。
    """

    name = "tui"

    def __init__(self, state, config=None) -> None:
        super().__init__(state, config)
        self.style = getattr(config, "ui_style", "ascii") if config is not None else "ascii"
        self.color = True
        self._keys = KeyReader()
        self._show_help = False
        self._started = False

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        from . import ansi

        ansi.enable_virtual_terminal()
        self._keys.__enter__()
        ansi.write(ansi.clear_screen() + ansi.hide_cursor())
        self._started = True
        self.state.set_status("采集中")

    def stop(self) -> None:
        from . import ansi

        if self._started:
            ansi.write(ansi.show_cursor() + ansi.clear_screen() + ansi.move_home())
        try:
            self._keys.__exit__()
        except Exception:  # pragma: no cover
            pass
        self._started = False
        self.state.set_status("已停止")

    # ------------------------------------------------------------------ #
    def poll_keys(self) -> Optional[str]:
        """读取按键并就地处理，返回原始按键（便于外部扩展）。"""
        key = self._keys.poll()
        if not key:
            return None
        if key in ("q", "<ctrl-c>", "<esc>"):
            self.state.request_quit()
        elif key == "p":
            self.state.toggle_pause()
        elif key == "r":
            self.state.clear_history()
        elif key in ("?", "h"):
            self._show_help = not self._show_help
        return key

    # ------------------------------------------------------------------ #
    def render(self, snapshot: Dict[str, Any]) -> None:
        from . import ansi

        if self.state.paused:
            return
        width, height = ansi.terminal_size()
        usable = max(height - 1, 12)  # 底部留一行，避免最后一行的换行触发滚动
        if self._show_help:
            lines = render_help(width, usable, self.style, self.color)
        else:
            lines = render_dashboard(snapshot, width, usable, style=self.style,
                                     color=self.color)
        self._draw(lines)

    @staticmethod
    def _draw(lines: Sequence[str]) -> None:
        """整屏重绘：回到左上角 → 逐行写入并清除行尾残留。"""
        from . import ansi

        buffer = [ansi.move_home()]
        last = len(lines) - 1
        for index, line in enumerate(lines):
            buffer.append(line)
            buffer.append(ansi.clear_to_eol())
            if index != last:
                buffer.append("\r\n")
        ansi.write("".join(buffer))


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.ui.dashboard`` 自检：用假数据渲染一帧。"""
    from datetime import datetime

    from ..model import ScoreResult
    from ..stats import WindowStats
    from .state import DashboardState

    state = DashboardState(history=30)
    now = datetime.now()
    for index in range(12):
        window = WindowStats(now, now, 5.0, 2000 + index * 7, 640000, 1440, 480, 60, 0, 40,
                             top_src_ips=[("192.168.10.%d" % (10 + index), 75)],
                             top_dst_ports=[(443, 535)])
        score = ScoreResult(score=0.1 if index < 9 else -0.2, is_anomaly=index >= 9,
                            threshold=0.0, enabled=True)
        state.record_window(window, score)
    snapshot = state.snapshot(log_feed=[("INFO", "示例事件：窗口已产出")])
    snapshot["source_desc"] = "网卡 eth0"
    snapshot["detector_desc"] = "异常检测: 已启用"
    snapshot["threshold"] = 0.0
    print(render_to_text(snapshot, width=100, height=32))
    return 0
