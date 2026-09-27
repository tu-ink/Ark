# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置(目录版/onedir): dist/ArkIDS/ArkIDS.exe + 依赖目录。

    python -m PyInstaller --noconfirm --clean arkids_onedir.spec
"""
from pathlib import Path

ROOT = Path(SPECPATH)

a = Analysis(
    [str(ROOT / "scripts" / "entry.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=[
        (str(ROOT / "src" / "arkids" / "webui"), "arkids/webui"),
        (str(ROOT / "src" / "arkids" / "_vendor"), "arkids/_vendor"),  # 内嵌 scapy
        (str(ROOT / "models" / "arkids_rf.joblib"), "models"),
    ],
    hiddenimports=[
        "sklearn.utils._typedefs",
        "sklearn.neighbors._partition_nodes",
        "scipy.special.cython_special",
        # 原生 GUI(tkinter)与懒加载模块
        "tkinter",
        "arkids.gui",
        "arkids.exttools",
        "arkids.scapylib",
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
    [],
    exclude_binaries=True,
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

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="ArkIDS",
)
