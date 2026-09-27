"""ArkIDS 原生 GUI(桌面端, tkinter)——替代 WebUI 作为主要界面。

设计:
    - 复用 dashboard.LiveMonitor 同一套真实抓包/分析内核(不重复实现逻辑);
    - 界面线程只负责轮询渲染(root.after), 抓包在后台线程进行;
    - 内置“以管理员运行”“深度抓包排错”“非管理员抓包指引”等抓包可用性处理。

运行: python -m arkids gui  (打包版双击 exe 默认进入本界面)
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from .dashboard import LiveMonitor
from .version import __version__

NAVY = "#0f1c31"
PANEL = "#15233c"
TEXT = "#e7eef9"
DIM = "#9db1cf"
ACCENT = "#3fd4ff"
OK = "#2ee6a8"
WARN = "#ffc24b"
DANGER = "#ff6b76"

LEVEL_ZH = {"critical": "严重", "warning": "警告", "info": "提示"}
KIND_ZH = {"tcp_syn_flood": "TCP SYN 洪泛", "port_scan": "端口扫描",
           "conn_burst": "连接突发"}
STATUS_ZH = {"idle": "空闲", "live": "实时抓包中", "replay": "文件回放中",
             "replay_done": "回放完成", "error": "异常"}


def try_run_as_admin() -> tuple[bool, str]:
    """尝试以管理员身份重新启动本程序(UAC)。成功返回 (True, 说明)。"""
    if _is_admin():
        return True, "当前已具备管理员权限。"
    try:
        import ctypes
        exe = sys.executable
        if getattr(sys, "frozen", False):
            params = ""
        else:
            params = "-m arkids gui"
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params,
                                                  None, 1)
        if ret > 32:
            return True, "已请求管理员运行(请在 UAC 弹窗点“是”), 新窗口将以管理员启动。"
        return False, "启动管理员权限被取消或失败(错误码 %s)。" % ret
    except Exception as exc:  # noqa: BLE001
        return False, f"无法请求管理员权限: {exc}"


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ------------------------------------------------------------------ GUI 应用
class ArkGUI:
    """主窗口: 监控 / 封包 / 威胁 / 防火墙 / 工具箱。"""

    def __init__(self) -> None:
        self.monitor = LiveMonitor(state_dir="run/gui")
        self.root = tk.Tk()
        self.root.title(f"ArkIDS {__version__} — 网络攻击智能检测与防御(原生 GUI)")
        self.root.geometry("1220x780")
        self.root.minsize(1000, 640)
        self.root.configure(bg=NAVY)
        self._build_style()
        self._build_ui()
        self._last_pkt_seq = 0
        self._engine_sync = 0
        self._th_count = -1
        self._poll_tick = 0
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll()

    # ---------------------------------------------------------------- 样式
    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=NAVY, foreground=TEXT,
                        font=("Microsoft YaHei UI", 10))
        style.configure("TFrame", background=NAVY)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=NAVY, foreground=TEXT)
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
        style.configure("Dim.TLabel", background=PANEL, foreground=DIM)
        style.configure("Accent.TLabel", background=PANEL, foreground=ACCENT)
        style.configure("Warn.TLabel", background=PANEL, foreground=WARN)
        style.configure("Ok.TLabel", background=PANEL, foreground=OK)
        style.configure("Danger.TLabel", background=PANEL, foreground=DANGER)
        style.configure("Title.TLabel", background=NAVY, foreground=TEXT,
                        font=("Microsoft YaHei UI", 14, "bold"))
        style.configure("TButton", padding=5)
        style.configure("Accent.TButton", foreground="#0b2c44")
        style.configure("Treeview", background="#0c1729", fieldbackground="#0c1729",
                        foreground=TEXT, rowheight=22)
        style.configure("Treeview.Heading", background="#1c2c4a",
                        foreground=TEXT, font=("Microsoft YaHei UI", 9, "bold"))
        style.map("Treeview", background=[("selected", ACCENT)])
        style.configure("TNotebook", background=NAVY, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 6))
        style.configure("TLabelframe", background=PANEL, foreground=TEXT)
        style.configure("TLabelframe.Label", background=PANEL, foreground=TEXT)
        style.configure("TCombobox", fieldbackground="#0c1729",
                        foreground=TEXT, arrowcolor=TEXT)
        style.configure("TEntry", fieldbackground="#0c1729", foreground=TEXT)

    # ---------------------------------------------------------------- 控件
    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="ArkIDS 工具台(GUI)", style="Title.TLabel").pack(side="left")
        self.lbl_status = ttk.Label(top, text="空闲", style="Dim.TLabel")
        self.lbl_status.pack(side="left", padx=(18, 0))
        self.lbl_engine = ttk.Label(top, text="引擎: 自动(scapy → tshark → 自研)",
                                    style="Dim.TLabel")
        self.lbl_engine.pack(side="left", padx=12)
        self.lbl_priv = ttk.Label(top, text="", style="Warn.TLabel")
        self.lbl_priv.pack(side="right")

        ctrl = ttk.Frame(self.root, padding=(10, 0))
        ctrl.pack(fill="x")
        self.cmb_engine = ttk.Combobox(ctrl, width=22, state="readonly",
                                       values=["auto(优先scapy)", "scapy", "tshark",
                                               "sniffer"])
        self.cmb_engine.current(0)
        self.cmb_engine.grid(row=0, column=0, padx=(0, 6))
        self.cmb_iface = ttk.Combobox(ctrl, width=34, state="readonly")
        self.cmb_iface.grid(row=0, column=1, padx=6)
        self.btn_refresh = ttk.Button(ctrl, text="刷新网卡", command=self._refresh_ifaces)
        self.btn_refresh.grid(row=0, column=2, padx=6)
        self.ent_filter = ttk.Entry(ctrl, width=18)
        self.ent_filter.insert(0, "过滤器(tshark 模式)")
        self.ent_filter.grid(row=0, column=3, padx=6)
        self.btn_start = ttk.Button(ctrl, text="▶ 开始抓包", style="Accent.TButton",
                                    command=self._start)
        self.btn_start.grid(row=0, column=4, padx=6)
        self.btn_stop = ttk.Button(ctrl, text="■ 停止", command=self._stop)
        self.btn_stop.grid(row=0, column=5, padx=6)
        self.btn_pcap = ttk.Button(ctrl, text="回放 .pcap/.pcapng…", command=self._open_pcap)
        self.btn_pcap.grid(row=0, column=6, padx=6)
        ttk.Label(ctrl, text="", style="Dim.TLabel").grid(row=0, column=7, sticky="e")
        ctrl.columnconfigure(7, weight=1)

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=(8, 6))
        self._tab_stats(nb)
        self._tab_packets(nb)
        self._tab_threats(nb)
        self._tab_firewall(nb)
        self._tab_tools(nb)

        bar = ttk.Frame(self.root, padding=(10, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="数据真实性: 仅消费本机实时抓包或真实 .pcap/.pcapng, 不构造流量。",
                  style="Dim.TLabel").pack(side="left")

    def _packet_tree_columns(self, tree: ttk.Treeview) -> None:
        cols = (("num", "#", 60), ("time", "时间", 90), ("src", "源", 130),
                ("dst", "目标", 130), ("proto", "协议", 60),
                ("sport", "源端口", 70), ("dport", "目标端口", 70),
                ("flags", "TCP标志", 70), ("len", "长度", 60))
        ids = [c[0] for c in cols]
        tree.configure(columns=ids, show="headings")
        for cid, txt, w in cols:
            tree.heading(cid, text=txt)
            tree.column(cid, width=w, anchor="w", stretch=(cid in ("src", "dst")))
        tree.column("#0", width=0, stretch=False)

    # ---------------------------------------------------------------- 页签
    def _tab_stats(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8); nb.add(f, text="实时总览")
        for label in ("数据包", "速率 pps", "活跃连接", "字节", "告警", "严重"):
            box = tk.Frame(f, bg=PANEL, highlightthickness=1,
                           highlightbackground="#22334f")
            box.pack(side="left", fill="both", expand=True, padx=4, pady=4)
            tk.Label(box, text=label, bg=PANEL, fg=DIM).pack(pady=(10, 2))
        self.var_kpis: dict[str, tk.StringVar] = {}
        self._kpi_boxes: dict[str, tk.Label] = {}
        idx = 0
        for key in ("packets", "pps", "flows", "bytes", "det", "crit"):
            var = tk.StringVar(value="0")
            lab = tk.Label(f.winfo_children()[idx], textvariable=var, bg=PANEL,
                           fg=ACCENT, font=("Consolas", 16, "bold"))
            lab.pack(pady=(0, 10))
            self.var_kpis[key] = var
            self._kpi_boxes[key] = lab
            idx += 1
        info = tk.Frame(f, bg=PANEL, highlightthickness=1, highlightbackground="#22334f")
        info.pack(fill="both", expand=True, pady=(8, 0))
        self.txt_log = tk.Text(info, bg="#0c1729", fg=TEXT, relief="flat",
                               font=("Consolas", 10), height=10)
        self.txt_log.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_log.insert("end", "提示: 选择“开始抓包”; 抓包需 Npcap 与管理员权限,"
                                   "或用“回放文件”加载真实 pcap。\n")
        self.txt_log.configure(state="disabled")

    def _tab_packets(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8); nb.add(f, text="封包浏览")
        bar = ttk.Frame(f); bar.pack(fill="x")
        self.ent_search = ttk.Entry(bar, width=28)
        self.ent_search.pack(side="left")
        self.ent_search.bind("<KeyRelease>", lambda e: self._render_packets())
        ttk.Button(bar, text="导出 CSV", command=self._export_packets).pack(side="left", padx=8)
        self.lbl_pkt = ttk.Label(bar, text="", style="Dim.TLabel")
        self.lbl_pkt.pack(side="right")
        wrap = ttk.Frame(f); wrap.pack(fill="both", expand=True, pady=(6, 0))
        self.tree_pkt = ttk.Treeview(wrap, show="headings")
        self._packet_tree_columns(self.tree_pkt)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tree_pkt.yview)
        self.tree_pkt.configure(yscrollcommand=vs.set)
        self.tree_pkt.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")

    def _tab_threats(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8); nb.add(f, text="威胁与处置")
        bar = ttk.Frame(f); bar.pack(fill="x")
        ttk.Label(bar, text="检测为 60s 流统计启发式, 处置默认人工确认。",
                  style="Dim.TLabel").pack(side="left")
        wrap = ttk.Frame(f); wrap.pack(fill="both", expand=True, pady=(6, 0))
        self.tree_th = ttk.Treeview(wrap, show="headings")
        th_cols = (("time", "时间", 90), ("level", "级别", 60),
                   ("kind", "类型", 90), ("title", "事件", 330),
                   ("conf", "置信", 60), ("act", "源IP(处置对象)", 150))
        self.tree_th.configure(columns=[c[0] for c in th_cols])
        for cid, txt, w in th_cols:
            self.tree_th.heading(cid, text=txt)
            self.tree_th.column(cid, width=w, anchor="w", stretch=(cid == "title"))
        self.tree_th.column("#0", width=0, stretch=False)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tree_th.yview)
        self.tree_th.configure(yscrollcommand=vs.set)
        self.tree_th.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        bar2 = ttk.Frame(f); bar2.pack(fill="x", pady=(6, 0))
        self.btn_block = ttk.Button(bar2, text="阻断选中项源IP(加入 deny 规则)",
                                    command=self._block_selected)
        self.btn_block.pack(side="left")
        ttk.Button(bar2, text="打开防火墙页查看规则", command=lambda: nb.select(3)
                   ).pack(side="left", padx=8)

    def _tab_firewall(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8); nb.add(f, text="防火墙规则")
        form = ttk.Frame(f); form.pack(fill="x")
        self.ent_fw = ttk.Entry(form, width=18)
        self.ent_fw.pack(side="left")
        self.ent_fw.insert(0, "源 IP")
        ttk.Button(form, text="添加 deny 规则", command=self._fw_add).pack(side="left", padx=6)
        ttk.Button(form, text="刷新", command=self._render_firewall).pack(side="left")
        wrap = ttk.Frame(f); wrap.pack(fill="both", expand=True, pady=(6, 0))
        self.tree_fw = ttk.Treeview(wrap, show="headings")
        fw_cols = (("act", "动作", 70), ("ip", "源 IP", 160),
                   ("proto", "协议/端口", 120), ("src", "来源", 90),
                   ("state", "状态", 70), ("note", "备注", 180))
        self.tree_fw.configure(columns=[c[0] for c in fw_cols])
        for cid, txt, w in fw_cols:
            self.tree_fw.heading(cid, text=txt)
            self.tree_fw.column(cid, width=w, anchor="w")
        self.tree_fw.column("#0", width=0, stretch=False)
        self.tree_fw.pack(side="left", fill="both", expand=True)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tree_fw.yview)
        self.tree_fw.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        self.txt_fw_script = tk.Text(f, bg="#0a1220", fg="#9fe8c4", relief="flat",
                                     font=("Consolas", 9), height=6)
        self.txt_fw_script.pack(fill="x", pady=(6, 0))

    def _tab_tools(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8); nb.add(f, text="工具箱·排错")
        row = ttk.Frame(f); row.pack(fill="x")
        ttk.Button(row, text="环境自检(9项)", command=self._selfcheck).pack(side="left")
        ttk.Button(row, text="深度抓包排错(约6-10s)", command=self._diag).pack(
            side="left", padx=8)
        ttk.Button(row, text="以管理员运行本程序(UAC)", command=self._elevate).pack(
            side="left", padx=8)
        ttk.Button(row, text="打开 Wireshark", command=self._open_ws).pack(side="left", padx=8)
        ttk.Button(row, text="打开抓包文件(010)", command=self._open_010).pack(side="left", padx=8)
        ttk.Button(row, text="解码工具(CyberChef)", command=self._open_chef).pack(
            side="left", padx=8)
        wrap = tk.Frame(f, bg=PANEL); wrap.pack(fill="both", expand=True, pady=(8, 0))
        self.txt_tools = tk.Text(wrap, bg="#0c1729", fg=TEXT, relief="flat",
                                 font=("Consolas", 10))
        self.txt_tools.pack(fill="both", expand=True, padx=4, pady=4)
        self.txt_tools.insert("end", "提示: 若“抓不到包”, 先点“深度抓包排错”, 它会区分:\n"
                                     "  denied(权限受限→以管理员运行或 Npcap 允许非管理员) /\n"
                                     "  no_device(驱动/接口异常→重装 Npcap) /\n"
                                     "  no_traffic(接口无流量→换与 Wireshark 一致的网卡)\n")
        self.txt_tools.configure(state="disabled")

    # ---------------------------------------------------------------- 动作
    def _refresh_ifaces(self) -> None:
        self.monitor.ifaces = []
        from .capture import list_interfaces  # noqa: PLC0415
        self.monitor.ifaces = list_interfaces(self.monitor.tshark) or []
        values = [i["description"] or i["name"] for i in self.monitor.ifaces]
        self.cmb_iface["values"] = values
        if values:
            self.cmb_iface.current(0)

    def _start(self) -> None:
        raw = self.cmb_engine.get()
        engine = "auto" if raw.startswith("auto") else raw
        idx = self.cmb_iface.current()
        iface = self.monitor.ifaces[idx]["name"] if idx >= 0 and \
            idx < len(self.monitor.ifaces) else None
        if engine == "tshark" and not self.monitor.tshark:
            self._log("未检测到 tshark, 改用内置/ scapy 引擎")
            engine = "auto"
        res = self.monitor.start_live(interface=iface, engine=engine)
        self._log("开始抓包(" + engine + "): " + (res.get("error") or res.get("mode", "ok")))
        if not res.get("ok") and "权限" in (res.get("error") or ""):
            self._elevate()
        self._sync_state()

    def _stop(self) -> None:
        self.monitor.stop()
        self._log("已停止")
        self._sync_state()

    def _open_pcap(self) -> None:
        path = filedialog.askopenfilename(
            title="选择真实抓包文件", filetypes=[("抓包文件", "*.pcap *.pcapng *.cap")])
        if not path:
            return
        res = self.monitor.start_pcap(path)
        self._log("回放: " + path if res.get("ok") else ("失败: " + res.get("error", "")))
        self._sync_state()

    def _elevate(self) -> None:
        ok, msg = try_run_as_admin()
        messagebox.showinfo("管理员权限", msg if ok else msg)
        if ok and "已请求" in msg:
            self._sync_state()

    def _selfcheck(self) -> None:
        sc = self.monitor.selfcheck()
        self._set_tools_text("环境自检: " + sc["diagnostic"] + "\n\n" +
                             "\n".join(f"[{'OK' if i['ok'] else '!!'}] {i['name']}: "
                                       f"{i.get('detail','')}" for i in sc["items"]))

    def _diag(self) -> None:
        self._log("深度抓包排错进行中(约 6-10s)…")
        self.root.after(100, lambda: self._diag_run())

    def _diag_run(self) -> None:
        def work() -> None:
            try:
                d = self.monitor.diag_capture(full=True)
                lines = ["结论: " + (d.get("reason") or "ok") + " | " + d.get("advice", "")]
                lines += [f"[{'OK' if i['ok'] else '!!'}] {i['name']}: {i.get('detail','')}"
                          for i in d.get("items", [])]
                lines += ["测试: " + "; ".join(
                    f"{t.get('desc') or t.get('interface')}={t.get('packets')}包({t.get('state')})"
                    for t in d.get("tests", []))]
                self.root.after(0, lambda: self._set_tools_text("\n".join(lines)))
            except Exception as exc:  # noqa: BLE001
                self.root.after(0, lambda: self._set_tools_text("排错失败: " + str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def _set_tools_text(self, text: str) -> None:
        self.txt_tools.configure(state="normal")
        self.txt_tools.delete("1.0", "end")
        self.txt_tools.insert("end", text + "\n")
        self.txt_tools.configure(state="disabled")

    def _log(self, msg: str) -> None:
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", time.strftime("[%H:%M:%S] ") + msg + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _open_ws(self) -> None:
        self._open_ext("wireshark")
    def _open_010(self) -> None:
        self._open_ext("hex010")
    def _open_chef(self) -> None:
        self._open_ext("cyberchef")

    def _open_ext(self, tool_id: str) -> None:
        from .exttools import ExtTools  # noqa: PLC0415
        res = ExtTools().open(tool_id, file_path=self.monitor.saved_path or "")
        self._log("打开" + tool_id + ": " + ("成功" if res.get("ok") else res.get("error", "")))

    # ---------------------------------------------------------------- 处置
    def _block_selected(self) -> None:
        sel = self.tree_th.selection()
        if not sel:
            messagebox.showinfo("提示", "请先在威胁页选中一行")
            return
        ip = self.tree_th.item(sel[0], "values")[5]
        if not ip:
            return
        self.monitor.fw.add(
            __import__("arkids.firewall", fromlist=["FirewallRule"]).FirewallRule(
                src_ip=ip, action="deny", protocol="any", note="GUI 处置"))
        self._log("已添加 deny 规则: " + ip)
        self._render_firewall()

    def _fw_add(self) -> None:
        ip = self.ent_fw.get().strip()
        if not ip or ip == "源 IP":
            return
        from .firewall import FirewallRule  # noqa: PLC0415
        self.monitor.fw.add(FirewallRule(src_ip=ip, action="deny", protocol="any",
                                         note="GUI 手工规则"))
        self.ent_fw.delete(0, "end")
        self._render_firewall()

    def _render_firewall(self) -> None:
        rows = self.monitor.fw.rules()
        self.tree_fw.delete(*self.tree_fw.get_children())
        for r in rows:
            proto = r["protocol"] + (("/" + str(r["dport"])) if r["dport"] else "")
            self.tree_fw.insert("", "end", values=(
                r["action"], r["src_ip"], proto, r["source"],
                "启用" if r["enabled"] else "停用", r["note"]))
        self.txt_fw_script.delete("1.0", "end")
        self.txt_fw_script.insert("1.0", self.monitor.fw.script_text() or "# 暂无规则")

    def _export_packets(self) -> None:
        rows = []
        for iid in self.tree_pkt.get_children():
            rows.append(self.tree_pkt.item(iid, "values"))
        if not rows:
            return
        import csv, io  # noqa: PLC0415
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["#", "时间", "源", "目标", "协议", "源端口", "目标端口", "标志", "长度"])
        w.writerows(rows)
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            initialfile="arkids_packets.csv")
        if path:
            open(path, "w", encoding="utf-8-sig", newline="").write(buf.getvalue())
            self._log("已导出: " + path)

    # ---------------------------------------------------------------- 渲染
    def _sync_state(self) -> None:
        meta = self.monitor.meta()
        self.lbl_status.configure(text=STATUS_ZH.get(meta.get("status"),
                                                     meta.get("status", "")),
                                  style="Ok.TLabel" if meta.get("capturing")
                                  else "Dim.TLabel")
        self.lbl_engine.configure(text="引擎: " + str(meta.get("engine", "")))
        if not _is_admin():
            self.lbl_priv.configure(text="非管理员 — 受限 Npcap 下抓包会被拒, 可点工具箱"
                                         "“以管理员运行”")
            self.lbl_priv.configure(style="Warn.TLabel")
        else:
            self.lbl_priv.configure(text="管理员", style="Ok.TLabel")

    def _render_packets(self) -> None:
        snap = self.monitor.snapshot()
        q = self.ent_search.get().strip().lower()
        packets = [p for p in snap.get("packets", [])
                   if not q or q in " ".join(
                       [str(p.get("src", "")), str(p.get("dst", "")),
                        str(p.get("proto", "")), str(p.get("dport", ""))]).lower()]
        self.tree_pkt.delete(*self.tree_pkt.get_children())
        for p in packets[-300:]:
            self.tree_pkt.insert("", "end", values=(
                p.get("num") or p.get("seq") or "-", time.strftime("%H:%M:%S",
                time.localtime(p.get("ts", 0))) + ".%03d" % int(p.get("ts", 0) % 1 * 1000),
                p.get("src", ""), p.get("dst", ""), p.get("proto", ""),
                p.get("sport", "-"), p.get("dport", "-"),
                p.get("flags", "-") or "-", p.get("length", "-")))
        self.lbl_pkt.configure(text=f"显示 {min(len(packets), 300)}/"
                                    f"{len(snap.get('packets', []))} 条(最新 300)")

    def _poll(self) -> None:
        self._poll_tick += 1
        try:
            snap = self.monitor.snapshot()
            s = snap.get("stats", {})
            self.var_kpis["packets"].set(fmt(s.get("packets", 0)))
            self.var_kpis["pps"].set(str(round(s.get("pps", 0))))
            self.var_kpis["flows"].set(fmt(s.get("flows_now", 0)))
            self.var_kpis["bytes"].set(fmt(s.get("bytes", 0)))
            self.var_kpis["det"].set(fmt(s.get("detections", 0)))
            self.var_kpis["crit"].set(fmt(s.get("critical_now", 0)))
            # 威胁表: 数量变化才刷新(避免整表闪烁)
            n = len(snap.get("detections", []))
            if n != self._th_count:
                self._th_count = n
                self.tree_th.delete(*self.tree_th.get_children())
                for d in reversed(list(snap.get("detections", []))[:100]):
                    self.tree_th.insert("", 0, values=(
                        d.get("time", ""),
                        LEVEL_ZH.get(d.get("level", ""), d.get("level", "")),
                        KIND_ZH.get(d.get("kind", ""), d.get("kind", "")),
                        d.get("title", ""),
                        f"{round((d.get('confidence') or 0) * 100)}%",
                        d.get("src", "") or ""))
            # 封包页: 低频整表刷新(最新 300), 保证列表有更新且不频繁闪烁
            if self._poll_tick % 8 == 0:
                self._render_packets()
            self._sync_state()
        except Exception:
            pass
        self.root.after(900, self._poll)

    def _render_threats(self) -> None:
        dets = self.monitor.detections if hasattr(self.monitor, "detections") else []
        snap = self.monitor.snapshot()
        for d in reversed(list(snap.get("detections", []))[:100]):
            self.tree_th.insert("", 0, values=(
                d.get("time", ""), LEVEL_ZH.get(d.get("level", ""), d.get("level", "")),
                KIND_ZH.get(d.get("kind", ""), d.get("kind", "")), d.get("title", ""),
                f"{round((d.get('confidence') or 0) * 100)}%", d.get("src", "") or ""))

    def _on_close(self) -> None:
        try:
            self.monitor.stop()
        except Exception:
            pass
        self.root.destroy()

    def run(self) -> None:
        self._refresh_ifaces()
        self._render_firewall()
        self.root.after(300, self._poll)
        # 自动关闭(供打包后 GUI 冒烟测试使用): ARKIDS_GUI_AUTOCLOSE=毫秒
        auto = os.environ.get("ARKIDS_GUI_AUTOCLOSE", "")
        if auto.isdigit():
            self.root.after(int(auto), self._on_close)
        self.root.mainloop()


def fmt(n) -> str:
    return f"{int(n or 0):,}"


def main() -> int:
    gui = ArkGUI()
    gui.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
