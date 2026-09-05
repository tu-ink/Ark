# -*- coding: utf-8 -*-
"""ArkIDS 一键发布脚本: icon → wheel → PyInstaller exe → 压缩发布包。

用法(需在已安装依赖与 PyInstaller 的环境执行):
    python scripts/build_release.py

产物(输出到 dist/):
    arkids-<ver>-py3-none-any.whl          标准 Python 安装包
    ArkIDS.exe                             单文件版(双击即用, 自动进控制台)
    ArkIDS/                               目录版(文件夹分发, 冷启动更快)
    ArkIDS-<ver>-win64.zip                 目录版 + 说明/授权/图标
"""
from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def run(cmd: list[str]) -> None:
    print("$", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def main() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    from arkids.version import __version__

    DIST.mkdir(exist_ok=True)
    # 1) 图标(如未生成)
    if not (ROOT / "assets" / "arkids.ico").exists():
        run([sys.executable, str(ROOT / "scripts" / "make_icon.py")])
    # 2) wheel
    run([sys.executable, str(ROOT / "scripts" / "make_wheel.py")])
    # 3) exe(单文件 + 目录版)
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
         str(ROOT / "arkids.spec")])
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
         str(ROOT / "arkids_onedir.spec")])
    # 4) 目录版压缩包(含说明/授权/图标)
    folder = DIST / "ArkIDS"
    zip_name = DIST / f"ArkIDS-{__version__}-win64.zip"
    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(DIST).as_posix())
        for extra in (ROOT / "LICENSE", ROOT / "assets" / "arkids.png"):
            z.write(extra, extra.name)
    print(f"[ok] 发布产物已生成于 {DIST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
