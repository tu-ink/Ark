# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置: 构建 ArkIDS 单文件可执行程序(Windows)。

    python -m PyInstaller --noconfirm --clean arkids.spec

产物: dist/ArkIDS/ArkIDS.exe(含内置 webui 前端与默认演示模型, 双击即用)。
"""
from pathlib import Path

ROOT = Path(SPECPATH)

a = Analysis(
    [str(ROOT / "scripts" / "entry.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=[
        (str(ROOT / "src" / "arkids" / "webui"), "arkids/webui"),   # 前端页面
        (str(ROOT / "models" / "arkids_rf.joblib"), "models"),      # 默认演示模型
    ],
    hiddenimports=[
        # scikit-learn / scipy 的部分延迟导入路径, 保证冻结环境下可用
        "sklearn.utils._typedefs",
        "sklearn.neighbors._partition_nodes",
        "scipy.special.cython_special",
        # 原生 GUI(tkinter)与懒加载模块
        "tkinter",
        "arkids.gui",
        "arkids.exttools",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["IPython", "matplotlib", "PyQt5", "PySide6", "pytest"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ArkIDS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    icon=str(ROOT / "assets" / "arkids.ico"),
    version=str(ROOT / "assets" / "version_info.txt"),
)
