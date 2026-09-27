"""发布门禁: 打包前后自动执行「运行测试 + 核心功能测试」并标定版本号。

流程:
    1) 依据 src/arkids/version.py 生成 assets/version_info.txt(Windows 版本资源);
    2) 运行单元测试(python -m unittest discover -s tests);
    3) 构建发布产物(目录版 exe + wheel + 便携 zip) —— 仅目录版, 规避单文件自解压问题;
    4) 对**打包产物**执行核心功能测试: exe selftest;
    5) GUI 启动冒烟: ARKIDS_GUI_AUTOCLOSE=1500 exe gui;
    6) 写入 dist/VERSION.txt(版本/提交/构建时间/组件版本), 并打印汇总。

任一环节失败即以非 0 退出。
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
PY = sys.executable
LOG_DIR = DIST / "release_logs"

# Windows 控制台常为 GBK: 统一为 UTF-8 容错, 避免打印日志时抛编码异常
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass


def sh(cmd: list[str], cwd: Path | None = None, env: dict | None = None,
       timeout: int = 1800) -> tuple[int, str]:
    print("$", " ".join(str(c) for c in cmd))
    e = dict(os.environ)
    if env:
        e.update(env)
    p = subprocess.run(cmd, cwd=str(cwd or ROOT), env=e, capture_output=True,
                       timeout=timeout)
    out = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace")
    tail = "\n".join(out.strip().splitlines()[-25:])
    # 全量日志落盘, 便于排查(避免控制台编码问题)
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        name = "_".join(Path(str(c[0])).stem for c in cmd[:3])[:60] or "cmd"
        (LOG_DIR / f"{name}_{int(time.time())}.log").write_text(out, encoding="utf-8")
    except Exception:
        pass
    try:
        print(tail)
    except UnicodeEncodeError:  # 极端情况下退化为 ASCII 安全输出
        print(tail.encode("ascii", "backslashreplace").decode("ascii"))
    return p.returncode, out


def write_version_info(ver: str) -> Path:
    parts = ver.split(".")
    while len(parts) < 4:
        parts.append("0")
    quad = ", ".join(parts[:4])
    text = f"""# UTF-8 (由 release_check.py 自动生成)
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({quad}),
    prodvers=({quad}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', 'tu-ink'),
        StringStruct('FileDescription', 'ArkIDS - AI Network Attack Detection & Defense'),
        StringStruct('FileVersion', '{ver}'),
        StringStruct('InternalName', 'ArkIDS'),
        StringStruct('LegalCopyright', 'Copyright (c) 2025 tu-ink (MIT)'),
        StringStruct('OriginalFilename', 'ArkIDS.exe'),
        StringStruct('ProductName', 'ArkIDS 基于人工智能的网络攻击智能检测与防御系统'),
        StringStruct('ProductVersion', '{ver}')
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    p = ROOT / "assets" / "version_info.txt"
    p.write_text(text, encoding="utf-8", newline="\n")
    return p


def write_version_stamp(ver: str, scapy_ver: str) -> Path:
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                                cwd=str(ROOT), capture_output=True,
                                text=True).stdout.strip()
    except Exception:
        commit = "unknown"
    stamp = (f"ArkIDS 版本: {ver}\n"
             f"构建时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
             f"Git 提交: {commit}\n"
             f"Python: {sys.version.split()[0]}\n"
             f"内嵌抓包库: scapy {scapy_ver}\n"
             f"发布形态: Windows 目录版(portable zip + wheel)\n"
             f"说明: 不再提供单文件 exe(其自解压易被权限/杀软拦截导致无法打开)\n")
    p = DIST / "VERSION.txt"
    p.write_text(stamp, encoding="utf-8", newline="\n")
    print(stamp)
    return p


def main() -> int:
    DIST.mkdir(exist_ok=True)
    sys.path.insert(0, str(ROOT / "src"))
    from arkids.version import __version__ as ver
    from arkids import scapylib
    scapy_ver = scapylib.version() or "n/a"
    print(f"== 发布门禁开始: ArkIDS v{ver} (scapy {scapy_ver}) ==")

    # 1) 版本资源
    write_version_info(ver)
    print("[1/6] 已生成 Windows 版本资源(版本号已标定)")

    # 2) 单元测试
    rc, _ = sh([PY, "-m", "unittest", "discover", "-s", "tests"], timeout=900)
    if rc != 0:
        print("!! 单元测试失败, 终止发布")
        return 1
    print("[2/6] 单元测试通过")

    # 3) 构建(目录版 + wheel)
    os.environ["PYTHONPATH"] = str(ROOT / "src")
    rc, _ = sh([PY, str(ROOT / "scripts" / "make_wheel.py")])
    if rc != 0:
        print("!! wheel 构建失败")
        return 1
    rc, _ = sh([PY, "-m", "PyInstaller", "--noconfirm", "--clean",
                str(ROOT / "arkids_onedir.spec")], timeout=1800)
    if rc != 0:
        print("!! 目录版打包失败")
        return 1
    exe = DIST / "ArkIDS" / "ArkIDS.exe"
    if not exe.exists():
        print("!! 未找到打包产物:", exe)
        return 1
    print("[3/6] 打包完成:", exe)

    # 4) 打包产物核心功能测试
    rc, out = sh([str(exe), "selftest"], timeout=600)
    if rc != 0 or "FAIL" in out:
        print("!! 打包产物自检未全部通过")
        return 1
    print("[4/6] 打包产物核心功能测试通过")

    # 5) GUI 启动冒烟
    rc, _ = sh([str(exe), "gui"], env={"ARKIDS_GUI_AUTOCLOSE": "1500"}, timeout=180)
    if rc != 0:
        print("!! GUI 启动冒烟失败")
        return 1
    print("[5/6] GUI 启动冒烟通过(exe gui 可正常打开/关闭)")

    # 6) 版本戳 + 便携 zip
    write_version_stamp(ver, scapy_ver)
    rc, _ = sh([PY, str(ROOT / "scripts" / "_make_release_zips.py")], timeout=900)
    if rc != 0:
        print("!! 便携 zip 生成失败")
        return 1
    print(f"[6/6] 发布完成: dist/ArkIDS-{ver}-win64-portable.zip + wheel + VERSION.txt")
    print("== 发布门禁全部通过 ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
