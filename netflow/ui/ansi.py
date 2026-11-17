# -*- coding: utf-8 -*-
"""ANSI 终端控制：颜色、光标、清屏与**显示宽度计算**。

全部基于标准库实现，不依赖 curses（Windows 的 CPython 不带 curses），
也不依赖任何第三方 TUI 库，符合「不使用 Web 技术、依赖仅 Python 库」的要求。

关键点：中文在终端里占 **2 个字符宽度**，用 ``len()`` 排版会导致表格错位，
因此所有单元格都用 :func:`display_width` / :func:`truncate` / :func:`pad` 处理。
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import unicodedata
from typing import List, Tuple

CSI = "\x1b["

#: 匹配 ANSI CSI 转义序列（颜色、光标移动等）
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# ---------------------------------------------------------------------- #
# 颜色
# ---------------------------------------------------------------------- #
class Color:
    """前景色 / 样式常量。"""

    RESET = CSI + "0m"
    BOLD = CSI + "1m"
    DIM = CSI + "2m"
    RED = CSI + "31m"
    GREEN = CSI + "32m"
    YELLOW = CSI + "33m"
    BLUE = CSI + "34m"
    MAGENTA = CSI + "35m"
    CYAN = CSI + "36m"
    WHITE = CSI + "37m"
    GREY = CSI + "90m"
    BRIGHT_RED = CSI + "91m"
    BRIGHT_GREEN = CSI + "92m"
    BRIGHT_YELLOW = CSI + "93m"
    BRIGHT_CYAN = CSI + "96m"


def colorize(text: str, *styles: str, enabled: bool = True) -> str:
    """给文本套上 ANSI 样式；``enabled=False`` 时原样返回（便于重定向输出）。"""
    if not enabled or not styles:
        return text
    return "".join(styles) + text + Color.RESET


# ---------------------------------------------------------------------- #
# 终端能力探测
# ---------------------------------------------------------------------- #
def enable_virtual_terminal() -> bool:
    """在 Windows 上开启 ANSI 转义支持（VT100 处理）。

    Python 3.6+ 在 Windows 控制台写中文没问题，但 ANSI 转义序列需要显式开启
    ``ENABLE_VIRTUAL_TERMINAL_PROCESSING``。失败时返回 ``False``，调用方应回退到
    纯文本模式。
    """
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        for handle_id in (-11, -12):  # STDOUT, STDERR
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
                return False
        return True
    except Exception:
        return False


def supports_ansi(stream=None) -> bool:
    """判断当前输出流是否适合使用 ANSI 全屏界面。"""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        if not stream.isatty():
            return False
    except Exception:
        return False
    if os.name == "nt":
        # Windows Terminal / VS Code / ConEmu 等都支持；传统 conhost 需要 VT 模式
        return enable_virtual_terminal()
    return True


def terminal_size(default: Tuple[int, int] = (100, 30)) -> Tuple[int, int]:
    """返回终端 (列, 行)；获取失败时返回默认值。"""
    try:
        size = shutil.get_terminal_size(fallback=default)
        return max(int(size.columns), 40), max(int(size.lines), 12)
    except Exception:
        return default


# ---------------------------------------------------------------------- #
# 显示宽度
# ---------------------------------------------------------------------- #
def char_width(ch: str) -> int:
    """单个字符占用的终端列宽（组合字符 0，东亚宽字符 2，其余 1）。"""
    if unicodedata.combining(ch):
        return 0
    if unicodedata.east_asian_width(ch) in ("W", "F"):
        return 2
    return 1


def display_width(text: str) -> int:
    """字符串在终端中占用的列宽。"""
    return sum(char_width(ch) for ch in text)


def strip_ansi(text: str) -> str:
    """去掉 ANSI 转义序列，得到纯可见文本。"""
    return _ANSI_RE.sub("", text)


def visible_width(text: str) -> int:
    """字符串的**可见**列宽（忽略 ANSI 颜色/光标序列）。

    排版校验必须用它而不是 :func:`display_width`，否则颜色序列会被当成可见字符
    而导致误判。
    """
    return display_width(strip_ansi(text))


def truncate(text: str, width: int, ellipsis: str = "..") -> str:
    """按显示宽度截断字符串，必要时追加省略号。"""
    if width <= 0:
        return ""
    if display_width(text) <= width:
        return text
    limit = max(width - display_width(ellipsis), 0)
    out: List[str] = []
    used = 0
    for ch in text:
        w = char_width(ch)
        if used + w > limit:
            break
        out.append(ch)
        used += w
    return "".join(out) + (ellipsis if limit > 0 else "")


def pad(text: str, width: int, align: str = "left", filler: str = " ") -> str:
    """把字符串补齐到指定显示宽度（先截断再补齐）。"""
    text = truncate(text, width)
    space = width - display_width(text)
    if space <= 0:
        return text
    if align == "right":
        return filler * space + text
    if align == "center":
        left = space // 2
        return filler * left + text + filler * (space - left)
    return text + filler * space


# ---------------------------------------------------------------------- #
# 光标 / 屏幕控制
# ---------------------------------------------------------------------- #
def hide_cursor() -> str:
    return CSI + "?25l"


def show_cursor() -> str:
    return CSI + "?25h"


def clear_screen() -> str:
    return CSI + "2J" + CSI + "H"


def move_home() -> str:
    return CSI + "H"


def clear_to_eol() -> str:
    """从光标处清除到行尾（CSI 0K），用于整屏重绘时擦掉上一帧的残留。"""
    return CSI + "0K"


def write(text: str) -> None:
    """写字符串到 stdout 并立即刷新。"""
    sys.stdout.write(text)
    sys.stdout.flush()


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.ui.ansi`` 自检：打印宽度与补齐效果。"""
    samples = ["netflow", "中文测试", "混合 abc 中文", "TCP: 78%"]
    for text in samples:
        print("{0!r:<24} len={1:<4} width={2}".format(text, len(text), display_width(text)))
    print("补齐 ->", "[{0}]".format(pad("中文", 12)))
    print("右对齐 ->", "[{0}]".format(pad("中文", 12, "right")))
    print("截断 ->", truncate("这是一个很长的中文字符串用于测试截断", 20))
    print("ANSI 支持:", supports_ansi())
    print("终端尺寸:", terminal_size())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
