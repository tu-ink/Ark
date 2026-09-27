"""生成便携发布包(仅目录版) —— 不入库, 输出至 dist/。

说明: 不再生成单文件 exe/zip —— 单文件自解压易被临时目录权限/杀软拦截, 导致
“双击打不开”; 目录版(解压即用)稳定可靠。
"""
import shutil
import zipfile
from pathlib import Path

DIST = Path("dist")
VER = "0.11.1"
NOTE = """ArkIDS v%(v)s — 基于人工智能的网络攻击智能检测与防御系统
=========================================================
【如何使用】
  1) 解压本压缩包到任意目录(路径不含中文更稳妥);
  2) 双击 ArkIDS\\ArkIDS.exe 打开桌面 GUI(无需浏览器; 不要只拖出单个 exe);
  3) 首次运行建议点“工具箱 → 环境自检 / 深度抓包排错”。

【为什么不提供单文件 exe】
  单文件版运行时需把内置组件自解压到临时目录, 在受限权限/杀毒拦截环境下会
  出现“双击无反应/闪退”。目录版直接把依赖放在同目录, 稳定可用。

【抓包(采用 Python 抓包库 scapy)】
  * 引擎 auto 默认优先 Python 库 scapy(经 Npcap 的 wpcap.dll), 其次 tshark, 最后自研嗅探;
  * Windows 实时抓包需要 Npcap(随 Wireshark 安装); 若 Npcap 安装时勾选了
    “限制为管理员”, 则需右键以管理员身份运行本程序(工具箱有“以管理员运行”按钮);
  * 抓不到包时使用“工具箱 → 深度抓包排错”, 会明确区分:
      denied(权限) / no_device(驱动) / no_traffic(接口无流量);
  * 无抓包权限也可“回放 .pcap/.pcapng”完成检测、处置与 AI 研判全流程。

【版本与自检】
  * 版本号见同目录 VERSION.txt; 命令行 `ArkIDS.exe --version`;
  * 打包产物内置核心功能自检: `ArkIDS.exe selftest`(9 项: 环境/scapy/pcap/pcapng/
    防火墙/启发式检测/排错/REST/GUI)。
License: MIT  Copyright (c) 2025 tu-ink
""" % {"v": VER}


def main() -> int:
    folder = DIST / "ArkIDS"
    if not folder.exists():
        raise SystemExit("缺少 dist/ArkIDS 目录版产物, 请先打包")
    zip_path = DIST / f"ArkIDS-{VER}-win64-portable.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                z.write(p, Path("ArkIDS") / p.relative_to(folder))
        z.write("LICENSE", "LICENSE")
        if (DIST / "VERSION.txt").exists():
            z.write(DIST / "VERSION.txt", "VERSION.txt")
        z.writestr("使用说明.txt", NOTE)
    print(f"[ok] {zip_path}  {zip_path.stat().st_size / 1e6:.1f} MB")

    # 清理历史单文件产物, 避免误用导致“打不开”
    for stale in (DIST / "ArkIDS.exe",):
        if stale.exists():
            stale.unlink()
            print("[clean] 已移除单文件 exe(易自解压失败):", stale.name)
    for old in DIST.glob("ArkIDS-*-win64-single.zip"):
        old.unlink()
        print("[clean] 已移除单文件 zip:", old.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
