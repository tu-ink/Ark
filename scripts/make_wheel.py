# -*- coding: utf-8 -*-
"""手工构建 arkids wheel(纯标准库, 无临时目录/无子进程, 适配受限构建环境)。

    python scripts/make_wheel.py [out_dir]

产物: out_dir/arkids-<version>-py3-none-any.whl
说明: 包元数据与 pyproject.toml / version.py 保持一致(单文件小改动需同步两处)。
"""
from __future__ import annotations

import csv
import hashlib
import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
WEBUI = SRC / "arkids" / "webui"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist"

# ---- 从单一来源读取版本
ver_ns: dict = {}
exec((SRC / "arkids" / "version.py").read_text(encoding="utf-8"), ver_ns)
VERSION = ver_ns["__version__"]
DIST = f"arkids-{VERSION}.dist-info"
WHEEL_NAME = f"arkids-{VERSION}-py3-none-any.whl"

METADATA = f"""Metadata-Version: 2.1
Name: arkids
Version: {VERSION}
Summary: 基于人工智能的网络攻击智能检测与防御系统(ArkIDS) —— AI 流量检测 + 证据累积式智能防御 + 可视化控制台
Home-page: https://github.com/tu-ink/Ark
Author: tu-ink
Author-email: 2538503336@qq.com
License: MIT
Keywords: intrusion-detection,network-security,machine-learning,ai-defense,ids
Requires-Python: >=3.9
Description-Content-Type: text/markdown
Classifier: Development Status :: 4 - Beta
Classifier: Intended Audience :: Developers
Classifier: Intended Audience :: Education
Classifier: Programming Language :: Python :: 3
Classifier: License :: OSI Approved :: MIT License
Classifier: Topic :: Security
Requires-Dist: numpy>=1.24
Requires-Dist: pandas>=2.0
Requires-Dist: scikit-learn>=1.3
Requires-Dist: joblib>=1.3

# ArkIDS
基于人工智能的网络攻击智能检测与防御系统: AI 流量检测 + 证据累积式智能防御 + 可视化控制台。
控制台: python -m arkids dashboard
"""

WHEEL_META = """Wheel-Version: 1.0
Generator: arkids-make-wheel
Root-Is-Purelib: true
Tag: py3-none-any
"""

ENTRY_POINTS = """[console_scripts]
arkids = arkids.cli:main
"""


def files_to_add() -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    for py in sorted(SRC.rglob("*.py")):
        rel = py.relative_to(SRC).as_posix()
        out.append((rel, py.read_bytes()))
    for asset in sorted(WEBUI.iterdir()):
        if asset.is_file():
            out.append(("arkids/webui/" + asset.name, asset.read_bytes()))
    out.append((f"{DIST}/METADATA", METADATA.encode("utf-8")))
    out.append((f"{DIST}/WHEEL", WHEEL_META.encode("utf-8")))
    out.append((f"{DIST}/entry_points.txt", ENTRY_POINTS.encode("utf-8")))
    return out


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    records: list[tuple[str, str, str]] = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files_to_add():
            z.writestr(name, data)
            records.append((name, hashlib.sha256(data).hexdigest(), str(len(data))))
        # RECORD 最后写入(不含自身哈希, 内容在循环外生成)
        rec_rows = [(n, f"sha256={h}", s) for n, h, s in records] + \
                   [(f"{DIST}/RECORD", "", "")]
        out_io = io.StringIO()
        writer = csv.writer(out_io, lineterminator="\n")
        writer.writerows(rec_rows)
        z.writestr(f"{DIST}/RECORD", out_io.getvalue().encode("utf-8"))
    target = OUT / WHEEL_NAME
    target.write_bytes(buf.getvalue())
    print(f"[ok] {target}  ({len(buf.getvalue()) / 1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
