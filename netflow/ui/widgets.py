# -*- coding: utf-8 -*-
"""TUI 控件库：面板、条形图、迷你趋势图与各分区渲染。

把「怎么画」和「画什么」分开：本模块只关心单元格宽度、边框、对齐，
不关心数据从哪来。所有函数都是纯函数，输入文本/数值、输出定宽字符串，
因此可以被单元测试直接断言。
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .ansi import Color, colorize, display_width, pad, truncate
from .state import format_bytes, format_count, format_duration

# ---------------------------------------------------------------------- #
# 边框字符集
# ---------------------------------------------------------------------- #
_CHARSET = {
    "ascii": {
        "tl": "+", "tr": "+", "bl": "+", "br": "+",
        "h": "-", "v": "|", "cross_l": "+", "cross_r": "+",
        "bar_full": "#", "bar_empty": "-",
    },
    "unicode": {
        "tl": "┌", "tr": "┐", "bl": "└", "br": "┘",
        "h": "─", "v": "│", "cross_l": "├", "cross_r": "┤",
        "bar_full": "█", "bar_empty": "░",
    },
}

#: ASCII 迷你趋势图的字符（从低到高）
_SPARK_ASCII = " .:-=+*#%@"
#: Unicode 迷你趋势图（方块字符）
_SPARK_UNICODE = " ▁▂▃▄▅▆▇█"


def _cs(style: str) -> Dict[str, str]:
    return _CHARSET.get(style, _CHARSET["ascii"])


# ---------------------------------------------------------------------- #
# 基础排版
# ---------------------------------------------------------------------- #
def _panel(title: str, body: Sequence[str], width: int, style: str) -> List[str]:
    """生成一个定宽面板：顶部带标题、左右竖线、底部横线。"""
    cs = _cs(style)
    width = max(width, 4)
    inner = width - 2
    lines: List[str] = []

    if title:
        label = " " + truncate(title, max(inner - 3, 1)) + " "
        # 总宽 = tl(1) + h(1) + label + rest + tr(1) = width  →  rest = inner - 1 - label
        rest = max(inner - 1 - display_width(label), 0)
        top = cs["tl"] + cs["h"] + label + cs["h"] * rest + cs["tr"]
    else:
        top = cs["tl"] + cs["h"] * inner + cs["tr"]
    lines.append(truncate(top, width))

    for row in body:
        lines.append(cs["v"] + pad(row, inner) + cs["v"])
    lines.append(cs["bl"] + cs["h"] * inner + cs["br"])
    return lines


def _side_by_side(left: Sequence[str], right: Sequence[str], left_width: int,
                  width: int, style: str) -> List[str]:
    """把两个面板并排放置（右面板自动补足剩余宽度）。"""
    left_width = max(min(left_width, width - 8), 12)
    right_width = max(width - left_width, 4)
    height = max(len(left), len(right))
    out: List[str] = []
    for index in range(height):
        lcell = left[index] if index < len(left) else " " * left_width
        rcell = right[index] if index < len(right) else " " * right_width
        out.append(pad(lcell, left_width) + pad(rcell, right_width))
    return out



def _bar(ratio: float, width: int, style: str) -> str:
    """生成一条水平条形图。"""
    cs = _cs(style)
    width = max(width, 1)
    ratio = min(max(ratio, 0.0), 1.0)
    filled = int(round(ratio * width))
    return cs["bar_full"] * filled + cs["bar_empty"] * (width - filled)


def _sparkline(values: Sequence[Optional[float]], width: int, style: str) -> str:
    """把分数序列渲染成迷你趋势图（低分=异常靠近左侧字符）。"""
    chars = _SPARK_UNICODE if style == "unicode" else _SPARK_ASCII
    values = list(values)[-width:]
    if not values:
        return ""
    known = [v for v in values if v is not None]
    if not known:
        return " " * len(values)
    low, high = min(known), max(known)
    span = (high - low) or 1.0
    out: List[str] = []
    for value in values:
        if value is None:
            out.append(" ")
            continue
        index = int(round((value - low) / span * (len(chars) - 1)))
        out.append(chars[min(max(index, 0), len(chars) - 1)])
    return "".join(out)


# ---------------------------------------------------------------------- #
# 各分区
# ---------------------------------------------------------------------- #
def _header(width: int, snapshot: Dict[str, Any], style: str, color: bool) -> str:
    cs = _cs(style)
    title = " NetFlow Monitor · Isolation Forest "
    source = " {0} · {1} ".format(
        truncate(snapshot.get("source_desc") or "-", 34),
        time.strftime("%H:%M:%S"),
    )
    inner = width - 2
    rest = max(inner - display_width(title) - display_width(source), 0)
    head = cs["tl"] + title + cs["h"] * rest + source + cs["tr"]
    return colorize(truncate(head, width), Color.BRIGHT_CYAN, enabled=color)


def _status_row(width: int, snapshot: Dict[str, Any], style: str, color: bool) -> str:
    cs = _cs(style)
    status = snapshot.get("status") or "-"
    dot = "o" if snapshot.get("paused") else "*"
    phase_color = Color.YELLOW if snapshot.get("paused") else Color.BRIGHT_GREEN
    capture = snapshot.get("capture") or {}
    totals = snapshot.get("totals") or {}
    captured = float(capture.get("captured") or 0)
    dropped = float(capture.get("dropped") or 0)
    drop_ratio = (dropped / captured * 100.0) if captured else 0.0

    left = " 状态: {0} {1}   运行 {2}   队列 {3}/{4}   丢包 {5} ({6:.2f}%)   窗口 {7}   告警 {8}".format(
        dot, status, format_duration(snapshot.get("elapsed") or 0.0),
        capture.get("queue", 0), capture.get("capacity", 0),
        format_count(dropped), drop_ratio,
        totals.get("windows", 0), totals.get("anomalies", 0),
    )
    return colorize(pad("|" + left, width - 1) + cs["v"], phase_color, enabled=color)


def _two_column_rows(width: int):
    """返回一个 ``row(l1, v1, l2, v2)`` 工厂，用于在面板内画两列键值行。

    列宽按面板实际宽度动态计算，保证整行**恰好**填满内容区、不会被截断。
    """
    inner = max(width - 2, 8)
    col = max((inner - 1) // 2, 10)
    label_w = max(min(9, col - 6), 4)
    value_w = max(col - label_w, 5)

    def row(label1: str, value1: str, label2: str = "", value2: str = "") -> str:
        return (" " + pad(label1, label_w) + pad(value1, value_w, "right")
                + " " + pad(label2, label_w) + pad(value2, value_w, "right"))

    return row, inner, label_w


def _stats_panel(width: int, snapshot: Dict[str, Any], style: str) -> List[str]:
    row, _inner, _label_w = _two_column_rows(width)
    current = snapshot.get("current")
    if current is None:
        body = ["", "  等待第一个统计窗口 ...",
                "  （窗口长度 {0:g} 秒）".format(snapshot.get("window_seconds") or 5.0)]
        return _panel("窗口统计", body, width, style)

    window, _result = current
    body = [
        row("包数", format_count(window.packet_count),
            "包速率", "{0:,.1f} pps".format(window.pps)),
        row("字节", format_bytes(window.byte_count),
            "字节速率", "{0}/s".format(format_bytes(window.bps))),
        row("唯一源 IP", format_count(window.unique_src_ips),
            "平均包长", "{0:.0f} B".format(window.avg_pkt_len)),
        row("SYN 比例", "{0:.3f}".format(window.syn_ratio),
            "采样时刻", window.end_time.strftime("%H:%M:%S")),
    ]
    return _panel("窗口统计（最近 {0:g} 秒）".format(snapshot.get("window_seconds") or 5.0),
                  body, width, style)


def _score_panel(width: int, snapshot: Dict[str, Any], style: str, color: bool) -> List[str]:
    row, inner, label_w = _two_column_rows(width)
    current = snapshot.get("current")
    threshold = snapshot.get("threshold")
    if current is None:
        return _panel("异常评分", ["", "  尚无评分数据"], width, style)

    _window, result = current
    score = result.score if result else None
    is_anomaly = bool(result and result.is_anomaly)
    if score is None:
        score_text, verdict, verdict_color = "N/A", "未启用", Color.GREY
    else:
        score_text = "{0:+.4f}".format(score)
        verdict = "异常" if is_anomaly else "正常"
        verdict_color = Color.BRIGHT_RED if is_anomaly else Color.BRIGHT_GREEN
    margin = "-" if (score is None or threshold is None) else "{0:+.4f}".format(score - threshold)

    spark = _sparkline(snapshot.get("scores") or [], max(inner - label_w - 2, 8), style)
    body = [
        row("当前分数", score_text, "判定阈值",
            "N/A" if threshold is None else "{0:+.4f}".format(threshold)),
        row("判定结果", verdict, "距阈值", margin),
        " " + pad("趋势", label_w) + pad(spark, max(inner - label_w - 1, 1)),
        row("累计告警", "{0} 次".format((snapshot.get("totals") or {}).get("anomalies", 0))),
    ]
    lines = _panel("异常评分", body, width, style)
    if color and score is not None:
        # 给「判定结果」所在行整体着色（在排版完成之后着色，不影响宽度）
        for index, line in enumerate(lines):
            if "判定结果" in line:
                lines[index] = colorize(line, verdict_color, enabled=True)
    return lines


def _protocol_panel(width: int, snapshot: Dict[str, Any], style: str) -> List[str]:
    current = snapshot.get("current")
    if current is None:
        return _panel("协议分布", ["  暂无数据"], width, style)
    window, _ = current
    inner = width - 6
    bar_width = max(inner - 16, 8)
    rows = [
        ("TCP", window.tcp_ratio, "{0:.0f}%".format(window.tcp_ratio * 100)),
        ("UDP", window.udp_ratio, "{0:.0f}%".format(window.udp_ratio * 100)),
        ("ICMP", window.icmp_ratio, "{0:.0f}%".format(window.icmp_ratio * 100)),
        ("SYN", window.syn_ratio, "{0:.3f}".format(window.syn_ratio)),
    ]
    body = []
    for label, ratio, text in rows:
        body.append(" {0}{1} {2}".format(
            pad(label, 6), pad(text, 8, "right"), _bar(ratio, bar_width, style)))
    return _panel("协议与标志位分布", body, width, style)


def _top_panel(left_width: int, right_width: int, snapshot: Dict[str, Any],
               style: str) -> Tuple[List[str], List[str]]:
    current = snapshot.get("current")
    if current is None:
        return (_panel("Top 源 IP", ["  暂无数据"], left_width, style),
                _panel("Top 目的端口", ["  暂无数据"], right_width, style))
    window, _ = current
    left_body = [" {0}{1}".format(pad(str(ip), max(left_width - 14, 8)),
                                  pad(format_count(count), 8, "right"))
                 for ip, count in (window.top_src_ips or [])[:5]] or ["  -"]
    right_body = [" {0}{1}".format(pad(str(port), max(right_width - 14, 8)),
                                   pad(format_count(count), 8, "right"))
                  for port, count in (window.top_dst_ports or [])[:5]] or ["  -"]
    return (_panel("Top 源 IP", left_body, left_width, style),
            _panel("Top 目的端口", right_body, right_width, style))


def _alerts_panel(width: int, snapshot: Dict[str, Any], style: str, color: bool,
                  max_rows: int = 5) -> List[str]:
    alerts = snapshot.get("alerts") or []
    if not alerts:
        return _panel("最近告警", ["  暂无告警"], width, style)
    body: List[str] = []
    for window, result in list(alerts)[-max_rows:][::-1]:
        body.append(" {0}  {1}  包 {2}  唯一源IP {3}  SYN {4:.2f}".format(
            window.end_time.strftime("%H:%M:%S"),
            pad("{0:+.4f}".format(result.score if result.score is not None else 0.0), 9, "right"),
            pad(format_count(window.packet_count), 8, "right"),
            pad(format_count(window.unique_src_ips), 7, "right"),
            window.syn_ratio,
        ))
    lines = _panel("最近告警（共 {0} 条）".format(len(alerts)), body, width, style)
    if color:
        for index, line in enumerate(lines):
            if ":" in line and "告警" not in line:
                lines[index] = colorize(line, Color.BRIGHT_RED, enabled=True)
    return lines


def _log_panel(width: int, snapshot: Dict[str, Any], style: str, max_rows: int = 4) -> List[str]:
    logs = snapshot.get("logs") or []
    if not logs:
        return _panel("事件", ["  （暂无事件）"], width, style)
    body = []
    for level, message in list(logs)[-max_rows:]:
        body.append(" {0} {1}".format(pad(level[:4], 5), truncate(message, width - 9)))
    return _panel("事件", body, width, style)


def _footer(width: int, style: str, color: bool) -> str:
    cs = _cs(style)
    text = " q 退出   p 暂停/继续   r 清空历史   ? 帮助"
    return colorize(pad("|" + text, width - 1) + cs["v"], Color.GREY, enabled=color)
