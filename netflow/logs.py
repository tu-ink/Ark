# -*- coding: utf-8 -*-
"""日志层：统一初始化控制台 / 文件 / 内存三路日志。

存在三种输出目标：

* **控制台**：普通模式下输出到 stdout；全屏 TUI 模式下必须关闭，
  否则日志会把仪表盘画面冲乱。
* **文件**：始终可用，UTF-8，便于事后排查。
* **内存环形缓冲**：保留最近若干条记录，供 TUI 的「事件」面板实时展示。

三路可以独立开关，因此 TUI 模式下推荐 ``--log-file`` 保留完整日志。
"""

from __future__ import annotations

import logging
import sys
from collections import deque
from typing import Deque, List, Optional, Tuple

#: 内存中保留的日志条数
RING_CAPACITY = 200

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


class RingBufferHandler(logging.Handler):
    """把最近若干条日志保存在内存里，供界面层读取。"""

    def __init__(self, capacity: int = RING_CAPACITY) -> None:
        super().__init__()
        self.records: Deque[Tuple[float, str, str, str]] = deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - 简单转发
        try:
            self.records.append(
                (record.created, record.levelname, record.name, record.getMessage())
            )
        except Exception:  # 日志本身绝不能抛异常
            pass

    def snapshot(self, limit: Optional[int] = None) -> List[Tuple[float, str, str, str]]:
        """返回最近的日志记录（按时间正序）。"""
        items = list(self.records)
        return items[-limit:] if limit else items


#: 全局唯一的内存日志处理器，:func:`setup_logging` 之后可用
_ring_handler: Optional[RingBufferHandler] = None


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    console: bool = True,
) -> RingBufferHandler:
    """初始化根日志器。

    Parameters
    ----------
    level:
        日志级别名称。
    log_file:
        可选的文件路径（UTF-8）；其父目录会自动创建。
    console:
        是否输出到控制台。全屏 TUI 模式下必须传 ``False``。

    Returns
    -------
    RingBufferHandler
        内存日志处理器，界面层可用它渲染事件面板。
    """
    global _ring_handler

    root = logging.getLogger()
    for handler in list(root.handlers):  # 支持重复调用（测试/嵌入式场景）
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    if console:
        stream = logging.StreamHandler(sys.stdout)
        stream.setFormatter(logging.Formatter(_LOG_FORMAT, _LOG_DATEFMT))
        root.addHandler(stream)

    if log_file:
        import os

        directory = os.path.dirname(os.path.abspath(log_file))
        if directory:
            os.makedirs(directory, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _LOG_DATEFMT))
        root.addHandler(file_handler)

    _ring_handler = RingBufferHandler()
    _ring_handler.setLevel(logging.DEBUG)
    root.addHandler(_ring_handler)

    # 第三方库降噪
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # 输出被重定向到文件时，避免中文因编码问题抛异常
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

    return _ring_handler


def get_ring_handler() -> Optional[RingBufferHandler]:
    """返回当前的内存日志处理器（未初始化时为 ``None``）。"""
    return _ring_handler
