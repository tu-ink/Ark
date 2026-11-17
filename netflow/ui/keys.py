# -*- coding: utf-8 -*-
"""跨平台非阻塞按键读取（标准库实现）。

* **Windows**：``msvcrt.kbhit()`` / ``msvcrt.getch()``；
* **POSIX**：``termios`` 关掉行缓冲与回显 + ``select`` 探测可读。

进入上下文管理器时切换终端为 cbreak 模式，退出时恢复原状，
因此不会在程序异常退出后把用户终端留在奇怪的状态。
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

logger = logging.getLogger(__name__)

#: Windows 下 getch() 对功能键返回的前导字节
_WIN_SPECIAL_PREFIXES = (b"\x00", b"\xe0")


class KeyReader:
    """非阻塞按键读取器。"""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = bool(enabled) and self._stream_is_tty()
        self._fd: Optional[int] = None
        self._saved_termios = None

    @staticmethod
    def _stream_is_tty() -> bool:
        try:
            return bool(sys.stdin and sys.stdin.isatty())
        except Exception:
            return False

    # ------------------------------------------------------------------ #
    def __enter__(self) -> "KeyReader":
        if not self.enabled:
            return self
        try:
            if os.name == "nt":
                import msvcrt

                # 确认标准库的按键接口确实可用（会抛 ImportError 的裁剪版解释器）
                self.enabled = hasattr(msvcrt, "kbhit") and hasattr(msvcrt, "getch")
            else:
                import termios
                import tty

                self._fd = sys.stdin.fileno()
                self._saved_termios = termios.tcgetattr(self._fd)
                tty.setcbreak(self._fd)
        except Exception:
            logger.debug("无法进入原始按键模式，已禁用键盘交互", exc_info=True)
            self.enabled = False
        return self

    def __exit__(self, *exc_info) -> None:
        if self.enabled and self._fd is not None and self._saved_termios is not None:
            try:
                import termios

                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved_termios)
            except Exception:  # pragma: no cover
                logger.debug("恢复终端属性失败", exc_info=True)
        self._fd = None
        self._saved_termios = None

    # ------------------------------------------------------------------ #
    def poll(self) -> Optional[str]:
        """非阻塞读取一个按键；无按键时返回 ``None``。

        返回值为小写字符（如 ``"q"``、``"p"``、``"r"``），
        方向键等特殊键返回 ``"<up>"`` 形式，其余返回 ``"?"``。
        """
        if not self.enabled:
            return None
        try:
            if os.name == "nt":
                return self._poll_windows()
            return self._poll_posix()
        except Exception:  # pragma: no cover - 终端异常不应中断监测
            logger.debug("读取按键失败", exc_info=True)
            self.enabled = False
            return None

    # ------------------------------------------------------------------ #
    @staticmethod
    def _poll_windows() -> Optional[str]:
        import msvcrt

        if not msvcrt.kbhit():
            return None
        ch = msvcrt.getch()
        if ch in _WIN_SPECIAL_PREFIXES:  # 功能键：吃掉第二个字节
            code = msvcrt.getch()
            mapping = {b"H": "<up>", b"P": "<down>", b"K": "<left>", b"M": "<right>"}
            return mapping.get(code, "?")
        if ch in (b"\r", b"\n"):
            return "<enter>"
        if ch == b"\x03":  # Ctrl+C
            return "<ctrl-c>"
        if ch == b"\x1b":
            return "<esc>"
        try:
            return ch.decode("utf-8", errors="ignore").lower() or "?"
        except Exception:
            return "?"

    @staticmethod
    def _poll_posix() -> Optional[str]:
        import select

        fd = sys.stdin.fileno()
        ready, _, _ = select.select([fd], [], [], 0)
        if not ready:
            return None
        data = os.read(fd, 1)
        if not data:
            return None
        if data == b"\x1b":  # ESC 序列（方向键）
            more, _, _ = select.select([fd], [], [], 0.005)
            if more:
                seq = os.read(fd, 2)
                mapping = {b"[A": "<up>", b"[B": "<down>", b"[C": "<right>", b"[D": "<left>"}
                return mapping.get(seq, "<esc>")
            return "<esc>"
        if data in (b"\r", b"\n"):
            return "<enter>"
        if data == b"\x03":
            return "<ctrl-c>"
        try:
            return data.decode("utf-8", errors="ignore").lower() or "?"
        except Exception:
            return "?"


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.ui.keys`` 自检：报告是否支持键盘交互。"""
    with KeyReader() as reader:
        print("键盘交互可用:", reader.enabled)
        print("按任意键结束 ...")
        import time

        deadline = time.time() + 5
        while time.time() < deadline:
            key = reader.poll()
            if key:
                print("读到按键:", key)
                break
            time.sleep(0.05)
        else:
            print("5 秒内无按键输入")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
