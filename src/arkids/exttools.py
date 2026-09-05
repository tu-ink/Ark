"""外部安全工具联动: 发现并调用工作区已装工具(Wireshark/Burp/蚁剑/010/CyberChef)。

定位原则:
    - 仅发现本机/工作区真实存在的工具, 不随程序分发任何第三方二进制;
    - 仅提供“启动 / 打开文件”能力, 不读取工具内部数据、不调用其破解组件。
用途(工具台“外部工具联动”区):
    Wireshark/tshark —— 抓包引擎与抓包复核(打开 .pcap)
    Burp Suite       —— 代理调试/HTTP 安全测试(启动或抓包文件)
    010 Editor       —— 十六进制/模板解析(打开 .pcap 原始结构)
    AntSword(蚁剑)    —— 会话/WebShell 管理(实验室场景, 启动即用)
    CyberChef        —— 编解码/解密“瑞士军刀”(浏览器打开)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import webbrowser
from pathlib import Path

from .capture import find_tshark, find_wireshark


def _bases() -> list[Path]:
    bases = []
    try:
        from .config import PROJECT_ROOT  # noqa: PLC0415
        bases.append(PROJECT_ROOT.parent)               # 工作区(含 Ark 同级工具)
    except Exception:
        pass
    for root in ("C:/", "D:/", "E:/"):
        bases.append(Path(root))
        ws = Path(root) / "deepseek_work"
        if ws.exists():
            bases.append(ws)                            # 便携工作区深层
    try:
        bases.append(Path.cwd())
        p = Path.cwd()
        for _ in range(4):
            p = p.parent
            bases.append(p)
    except Exception:
        pass
    return bases


def _find_named(name: str) -> Path | None:
    """在工作区同级目录/磁盘根 一层内查找指定文件夹。"""
    for base in _bases():
        cand = base / name
        if cand.exists():
            return cand
    return None


def _find_file(folder: Path | None, names: list[str], pattern: str = "") -> Path | None:
    if not folder or not folder.exists():
        return None
    for n in names:
        p = folder / n
        if p.exists():
            return p
    if pattern:
        hits = sorted(folder.glob(pattern))[:5]
        for h in hits:
            if h.is_file():
                return h
    return None


class ExtTools:
    """工具发现(带进程级缓存)与启动。"""

    def __init__(self) -> None:
        self._cache: dict | None = None

    def list(self, refresh: bool = False) -> list[dict]:
        if self._cache is None or refresh:
            self._cache = self._scan()
        return self._cache

    # ------------------------------------------------------------ 扫描
    def _scan(self) -> list[dict]:
        out: list[dict] = []
        # 1) Wireshark(Wireshark.exe / tshark.exe)
        ws = find_wireshark()
        ts = find_tshark()
        out.append({"id": "wireshark", "name": "Wireshark",
                    "found": bool(ws), "path": str(ws) if ws else "",
                    "note": ("抓包复核 / GUI 分析 · tshark " +
                             (Path(str(ts)).name if ts else "未找到"))
                    if ws else "未发现(Wireshark 目录)",
                    "exe": str(ws) if ws else ""})
        # 2) Burp Suite(工作区 Burp_Suite 启动脚本或 jar)
        burp_dir = _find_named("Burp_Suite")
        launch = None
        if burp_dir:
            launch = _find_file(burp_dir,
                                ["BurpSuite.vbs", "Burp_Chs.vbs", "burpsuite.vbs"])
            if launch is None:
                jar = _find_file(burp_dir, [], "burpsuite*.jar")
                if jar:
                    launch = jar
        out.append({"id": "burp", "name": "Burp Suite",
                    "found": bool(launch), "path": str(launch) if launch else "",
                    "note": "HTTP 代理 / 渗透测试调试" if launch
                    else "未发现(Burp_Suite 目录)",
                    "exe": str(launch) if launch else ""})
        # 3) 蚁剑 AntSword
        ant_dir = _find_named("蚁剑") or _find_named("AntSword")
        loader = None
        if ant_dir:
            for sub in ("AntSword-Loader-4.0.3", "AntSword-Loader",
                        "AntSword-Loader-master"):
                d = ant_dir / sub
                if d.exists():
                    loader = _find_file(d, [], "*.exe")
                    if loader:
                        break
            if loader is None:
                loader = _find_file(ant_dir, [], "*.exe")
        out.append({"id": "antsword", "name": "蚁剑 AntSword",
                    "found": bool(loader),
                    "path": str(loader) if loader else "",
                    "note": "WebShell/会话管理(实验室场景)" if loader
                    else "未发现(蚁剑目录)",
                    "exe": str(loader) if loader else ""})
        # 4) 010 Editor
        hex_dir = _find_named("010editor") or _find_named("010 Editor")
        hexexe = _find_file(hex_dir, ["010Editor.exe"])
        out.append({"id": "hex010", "name": "010 Editor",
                    "found": bool(hexexe), "path": str(hexexe) if hexexe else "",
                    "note": "十六进制 / 二进制模板解析(pcap 结构查看)"
                    if hexexe else "未发现(010editor 目录)",
                    "exe": str(hexexe) if hexexe else ""})
        # 5) CyberChef(解密/编解码)
        chef_dir = None
        for base in _bases():
            cands = sorted(base.glob("CyberChef*")) if base.exists() else []
            if cands:
                chef_dir = cands[0]
                break
        chef_html = None
        if chef_dir:
            chef_html = _find_file(chef_dir, ["CyberChef_v9.46.0.html",
                                              "CyberChef.html", "index.html"])
        out.append({"id": "cyberchef", "name": "CyberChef(解密/编解码)",
                    "found": bool(chef_html), "path": str(chef_html) if chef_html else "",
                    "note": "加解密/编码/解码工具箱" if chef_html
                    else "未发现(CyberChef 目录)",
                    "exe": ""})
        # 仅标记“程序实际使用”的工具(其余不参与自动联动, 避免无意义占位)
        usage = {
            "wireshark": (True, "open_capture",
                          "抓包引擎 + 用 Wireshark 打开当前抓包复核"),
            "hex010": (True, "open_capture",
                       "用 010 Editor 打开当前抓包查看十六进制/模板"),
            "cyberchef": (True, "decode",
                          "打开 CyberChef 对载荷做解码/解密分析"),
            "burp": (False, "", "未纳入自动联动(需要时手动启动)"),
            "antsword": (False, "", "未纳入自动联动(需要时手动启动)"),
        }
        for t in out:
            integ, role, unote = usage.get(t["id"], (False, "", ""))
            t["integrated"] = integ
            t["role"] = role
            base = t["note"] or ""
            t["note"] = (base + (" · " if base else "")) + unote if not integ \
                else base + (" · " + unote if base and integ else unote)
        return out

    # ------------------------------------------------------------ 启动
    def open(self, tool_id: str, file_path: str = "") -> dict:
        tools = {t["id"]: t for t in self.list()}
        t = tools.get(tool_id)
        if not t or not t["found"]:
            return {"ok": False, "error": "工具不可用或未找到"}
        try:
            if tool_id == "cyberchef":
                webbrowser.open(Path(t["path"]).as_uri())
                return {"ok": True}
            cmd: list[str] = []
            if tool_id == "wireshark":
                cmd = [t["path"]]
                if file_path:
                    cmd += ["-r", file_path]
            elif tool_id == "hex010":
                cmd = [t["path"]]
                if file_path:
                    cmd += [file_path]
            elif tool_id == "burp":
                cmd = self._burp_cmd(Path(t["path"]))
                if not cmd:
                    return {"ok": False, "error": "缺少可用的 Java 运行环境"}
            else:  # antsword
                cmd = [t["path"]]
            subprocess.Popen(cmd, creationflags=getattr(subprocess,
                                                        "CREATE_NO_WINDOW", 0))
            return {"ok": True}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def _burp_cmd(self, launcher: Path) -> list[str]:
        if launcher.suffix.lower() == ".vbs":
            return ["wscript.exe", str(launcher)]
        # jar: 优先用 Burp_Suite 自带 jdk
        java = None
        jdk = _find_named("Burp_Suite")
        if jdk:
            for p in (jdk / "jdk-18.0.1" / "bin" / "java.exe",
                      jdk / "jdk" / "bin" / "java.exe"):
                if p.exists():
                    java = str(p)
                    break
        if not java:
            java = shutil.which("java") or shutil.which("java.exe") or ""
        if not java:
            return []
        return [java, "-jar", str(launcher)]
