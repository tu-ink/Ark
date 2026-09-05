"""生成发布 zip(目录版 + 单文件版) —— 不入库, 输出至 dist/。"""
import zipfile
from pathlib import Path

DIST = Path("dist")
ROOT = Path(".")
VER = "0.3.0"
NOTE = """ArkIDS v%(v)s — 基于人工智能的网络攻击智能检测与防御系统
========================================================
双击 ArkIDS.exe 即进入可视化控制台(实时攻防网络/防火墙编辑/攻击日志/AI 建议)，
并将自动打开浏览器: http://127.0.0.1:8642

打包版内置默认演示模型(合成数据训练); 如需训练真实模型, 请使用源码版:
    pip install arkids-%(v)s-py3-none-any.whl
    arkids train --data <NSL-KDD/KDDTrain+.txt> --out models/my_model.joblib
    arkids dashboard --model models/my_model.joblib

命令行用法(打包版同样支持):
    ArkIDS.exe dashboard --port 8642      # 可视化控制台(--no-browser 不自动开浏览器)
    ArkIDS.exe train ...                  # 训练等其它子命令与源码版一致
    ArkIDS.exe --version / --help

说明:
  * 单文件版(ArkIDS.exe)首次启动需自解压到临时目录, 启动稍慢;
  * 目录版(ArkIDS/ 文件夹)运行更快; 请整体保留 ArkIDS 文件夹(含 _internal);
  * 运行期告警/封禁/规则写入当前目录 run/ 子文件夹;
  * 图标 assets/arkids.ico 可用作快捷方式图标。
License: MIT  Copyright (c) 2025 tu-ink
""" % {"v": VER}

# 1) 目录版
folder = DIST / "ArkIDS"
z1 = DIST / f"ArkIDS-{VER}-win64.zip"
with zipfile.ZipFile(z1, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(folder.rglob("*")):
        if p.is_file():
            z.write(p, Path("ArkIDS") / p.relative_to(folder))
    z.write("LICENSE", "LICENSE")
    z.writestr("使用说明.txt", NOTE)
print(f"[ok] {z1}  {z1.stat().st_size/1e6:.1f} MB")

# 2) 单文件版(带说明)
z2 = DIST / f"ArkIDS-{VER}-win64-single.zip"
with zipfile.ZipFile(z2, "w", zipfile.ZIP_DEFLATED) as z:
    z.write(DIST / "ArkIDS.exe", "ArkIDS.exe")
    z.write("LICENSE", "LICENSE")
    z.writestr("使用说明.txt", NOTE)
    z.write("assets/arkids.ico", "arkids.ico")
print(f"[ok] {z2}  {z2.stat().st_size/1e6:.1f} MB")
