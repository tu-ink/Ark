# -*- coding: utf-8 -*-
"""ArkIDS 冻结(frozen)入口: 双击 exe / 无参数时进入可视化控制台。

仅用于 PyInstaller 打包; 源码运行请使用 `python -m arkids` 或 `arkids`。
"""
import sys

from arkids.cli import main

if __name__ == "__main__":
    sys.exit(main())
