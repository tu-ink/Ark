#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""网络流量监测系统 —— 程序入口。

真正的实现在 :mod:`netflow.cli` 中，本文件只负责把项目根目录加入 ``sys.path``
并转发调用，因此下面两种方式完全等价::

    python main.py --demo                    # 直接运行源码
    pip install . && netflow-monitor --demo  # 安装后使用控制台命令
"""

from __future__ import annotations

import os
import sys

# 允许在未安装（未 pip install）的情况下直接运行本文件
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from netflow.cli import main  # noqa: E402  (必须在 sys.path 处理之后导入)

if __name__ == "__main__":
    sys.exit(main())
