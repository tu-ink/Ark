# -*- coding: utf-8 -*-
"""`python -m netflow.training` 的入口。

真正的实现在 :mod:
etflow.training.cli，本文件只做转发，
避免 runpy 重复导入 `__main__` 造成的 RuntimeWarning。
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
