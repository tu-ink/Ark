"""按需获取内嵌 Python 抓包库(scapy)到 src/arkids/_vendor(不入库)。

用途: 仓库不再提交 scapy 源码(体积/GPL 许可), 但打包与离线运行需要它。
首次克隆后执行一次本脚本即可; 也可由 scripts/release_check.py 自动调用。

用法:  python scripts/fetch_scapy.py [--version 2.7.0]
"""
from __future__ import annotations

import io
import json
import shutil
import ssl
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "src" / "arkids" / "_vendor"


def main() -> int:
    want = None
    if "--version" in sys.argv:
        want = sys.argv[sys.argv.index("--version") + 1]
    ctx = ssl._create_unverified_context()
    meta = json.loads(urllib.request.urlopen(
        "https://pypi.org/pypi/scapy/json", timeout=60, context=ctx).read())
    ver = want or meta["info"]["version"]
    urls = meta["urls"] if not want else None
    wheel_url = None
    if urls:
        for u in urls:
            if u["packagetype"] == "bdist_wheel" and u["filename"].endswith(
                    "py3-none-any.whl"):
                wheel_url = u["url"]
                ver = meta["info"]["version"]
                break
    if not wheel_url:
        # 指定版本: 走版本化 JSON
        meta2 = json.loads(urllib.request.urlopen(
            f"https://pypi.org/pypi/scapy/{ver}/json", timeout=60,
            context=ctx).read())
        for u in meta2["urls"]:
            if u["packagetype"] == "bdist_wheel":
                wheel_url = u["url"]
                break
    if not wheel_url:
        print("!! 未找到 scapy wheel 下载地址")
        return 1
    print("下载:", wheel_url)
    data = urllib.request.urlopen(wheel_url, timeout=300, context=ctx).read()
    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)
    z = zipfile.ZipFile(io.BytesIO(data))
    for n in z.namelist():
        if n.startswith("scapy/") and not n.endswith("/"):
            t = DEST / n
            t.parent.mkdir(parents=True, exist_ok=True)
            t.write_bytes(z.read(n))
    lic = [n for n in z.namelist() if n.endswith("LICENSE")][0]
    (DEST / "scapy" / "LICENSE").write_bytes(z.read(lic))
    (DEST / "__init__.py").write_text(
        '"""第三方源码内嵌目录(仅 scapy: GPL-2.0, 见 scapy/LICENSE)。'
        '由 scripts/fetch_scapy.py 获取, 不入库。"""\n', encoding="utf-8")
    files = list((DEST / "scapy").rglob("*.py"))
    print(f"[ok] 已内嵌 scapy {ver}: {len(files)} 个模块 -> {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
