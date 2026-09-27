"""生成发布 zip(目录版 + 单文件版) —— 不入库, 输出至 dist/。"""
import zipfile
from pathlib import Path

DIST = Path("dist")
VER = "0.11.0"
NOTE = """ArkIDS v%(v)s — 基于人工智能的网络攻击智能检测与防御系统
========================================================
主界面: 原生 GUI(双击 ArkIDS.exe 即打开; 无需浏览器)
抓包引擎: auto = Python 抓包库 scapy(内置, 经 Npcap) → tshark → 自研嗅探

快速使用:
    ArkIDS.exe                      # 桌面 GUI(推荐)
    ArkIDS.exe gui                  # 同上
    ArkIDS.exe dashboard --port 8642# 可选 Web 控制台
    ArkIDS.exe dashboard --pcap a.pcapng   # 回放真实抓包
抓包说明:
  * Windows 实时抓包需要 Npcap(随 Wireshark 安装), 受限安装时需以管理员运行;
  * 非管理员可在 GUI“工具箱→深度抓包排错”查看结论(denied/no_device/no_traffic);
  * 无抓包权限时仍可“回放文件”加载真实 .pcap/.pcapng 完成全流程。
内置真实样例: 工具箱可下载 Wireshark 官方样例并自动回放。
License: MIT Copyright (c) 2025 tu-ink
""" % {"v": VER}


def main() -> int:
    folder = DIST / "ArkIDS"
    z1 = DIST / f"ArkIDS-{VER}-win64.zip"
    with zipfile.ZipFile(z1, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                z.write(p, Path("ArkIDS") / p.relative_to(folder))
        z.write("LICENSE", "LICENSE")
        z.writestr("使用说明.txt", NOTE)
    print(f"[ok] {z1}  {z1.stat().st_size / 1e6:.1f} MB")

    z2 = DIST / f"ArkIDS-{VER}-win64-single.zip"
    with zipfile.ZipFile(z2, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(DIST / "ArkIDS.exe", "ArkIDS.exe")
        z.write("LICENSE", "LICENSE")
        z.writestr("使用说明.txt", NOTE)
        z.write("assets/arkids.ico", "arkids.ico")
    print(f"[ok] {z2}  {z2.stat().st_size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
