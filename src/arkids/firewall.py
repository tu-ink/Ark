"""防火墙规则管理: 支持 Web 界面在线增删改(启停)规则, 并同步导出脚本。

设计:
    - 规则与“检测→封禁”解耦: 自动封禁写入 deny 规则, 人工策略也可编辑;
    - 持久化于 state_dir/firewall.json;
    - 导出的防火墙脚本(state_dir/firewall_rules.sh)合并“启用的 deny 规则 +
      允许规则”, 便于在真实 nftables/iptables 环境执行。
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

from .config import RUN_DIR

PROTOCOLS = ("any", "tcp", "udp", "icmp")
ACTIONS = ("deny", "allow")


class FirewallRule:
    __slots__ = ("id", "src_ip", "dst_ip", "protocol", "dport", "action",
                 "enabled", "note", "ts", "source")

    def __init__(self, src_ip: str, action: str = "deny", protocol: str = "any",
                 dst_ip: str = "0.0.0.0", dport: int | str = "",
                 note: str = "", source: str = "manual", enabled: bool = True,
                 rid: str | None = None, ts: float | None = None) -> None:
        self.id = rid or uuid.uuid4().hex[:12]
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol if protocol in PROTOCOLS else "any"
        self.dport = "" if dport in ("", None, "*") else str(dport)
        self.action = action if action in ACTIONS else "deny"
        self.enabled = enabled
        self.note = note or ""
        self.ts = ts if ts is not None else time.time()
        self.source = source

    def to_dict(self) -> dict:
        return {
            "id": self.id, "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "protocol": self.protocol, "dport": self.dport,
            "action": self.action, "enabled": bool(self.enabled),
            "note": self.note, "ts": self.ts, "source": self.source,
        }

    @staticmethod
    def from_dict(d: dict) -> "FirewallRule":
        return FirewallRule(
            src_ip=d.get("src_ip", ""), action=d.get("action", "deny"),
            protocol=d.get("protocol", "any"), dst_ip=d.get("dst_ip", "0.0.0.0"),
            dport=d.get("dport", ""), note=d.get("note", ""),
            source=d.get("source", "manual"), enabled=bool(d.get("enabled", True)),
            rid=d.get("id"), ts=d.get("ts"),
        )

    def to_shell_line(self) -> str:
        """导出为 nftables 规则(注释保留来源与说明)。"""
        proto = self.protocol if self.protocol != "any" else ""
        sport_part = f" dport {self.dport}" if self.dport else ""
        verdict = "drop" if self.action == "deny" else "accept"
        chain = "input" if self.action == "deny" else "input"
        src = self.src_ip
        target = f"ip saddr {src}"
        expr = f"nft add rule inet filter {chain} {target} {('tcp' if self.protocol in ('tcp','udp') else proto)}"
        # 简化生成可读规则行
        if self.action == "deny":
            if self.protocol in ("tcp", "udp"):
                line = (f"nft add rule inet filter input ip saddr {src} "
                        f"{self.protocol} dport {self.dport or 'any'} drop")
            elif self.protocol == "icmp":
                line = f"nft add rule inet filter input ip saddr {src} icmp type echo-request drop"
            else:
                line = f"nft add rule inet filter input ip saddr {src} drop"
        else:
            line = f"# allow 规则需配合默认 DROP 链使用: {src} ({self.note})"
        return line

    def __repr__(self) -> str:
        return f"<Rule {self.action} {self.src_ip} {self.protocol}/{self.dport} {'on' if self.enabled else 'off'}>"


class FirewallStore:
    """防火墙规则的持久化仓库与脚本导出。"""

    def __init__(self, state_dir: str | Path = RUN_DIR) -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._path = self.state_dir / "firewall.json"
        self._rules: list[FirewallRule] = []
        self._load()

    # ------------------------------------------------------------- 查询
    def rules(self) -> list[dict]:
        return [r.to_dict() for r in self._rules]

    def enabled_deny_rules(self) -> list[FirewallRule]:
        return [r for r in self._rules if r.enabled and r.action == "deny"]

    def find(self, rid: str) -> FirewallRule | None:
        for r in self._rules:
            if r.id == rid:
                return r
        return None

    def is_src_blocked(self, ip: str) -> bool:
        return any(r.action == "deny" and r.enabled and r.src_ip == ip
                   for r in self._rules)

    # ------------------------------------------------------------- 写操作
    def add(self, rule: FirewallRule) -> FirewallRule:
        if rule.action == "deny" and rule.enabled and self.is_src_blocked(rule.src_ip):
            existing = next(r for r in self._rules
                            if r.action == "deny" and r.enabled and r.src_ip == rule.src_ip)
            return existing
        self._rules.append(rule)
        self._save()
        self.export_script()
        return rule

    def update(self, rid: str, **fields) -> FirewallRule | None:
        rule = self.find(rid)
        if not rule:
            return None
        for key, val in fields.items():
            if key in ("src_ip", "dst_ip", "protocol", "dport", "note", "source"):
                setattr(rule, key, val)
            elif key == "action" and val in ACTIONS:
                rule.action = val
            elif key == "enabled":
                rule.enabled = bool(val)
        self._save()
        self.export_script()
        return rule

    def delete(self, rid: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rid]
        if len(self._rules) != before:
            self._save()
            self.export_script()
            return True
        return False

    # ------------------------------------------------------------- 持久化
    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self._rules = [FirewallRule.from_dict(d) for d in data]
            except (json.JSONDecodeError, KeyError):
                self._rules = []

    def _save(self) -> None:
        self._path.write_text(
            json.dumps([r.to_dict() for r in self._rules], ensure_ascii=False, indent=2),
            encoding="utf-8")

    def export_script(self, out: str | None = None) -> str:
        """把所有启用的 deny 规则导出为可执行脚本, 返回脚本文本。"""
        target = Path(out) if out else self.state_dir / "firewall_rules.sh"
        lines = ["#!/usr/bin/env bash",
                 "# 由 ArkIDS 防火墙编辑器自动生成(deny=drop)",
                 "# 执行前请按实际 nftables 表链定义调整: nft add table inet filter",
                 "set -e", ""]
        for r in self.enabled_deny_rules():
            lines.append("# " + (r.note or r.source) + "  " + time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(r.ts)))
            lines.append(r.to_shell_line())
        text = "\n".join(lines) + "\n"
        target.write_text(text, encoding="utf-8")
        return text

    def script_text(self) -> str:
        """返回当前脚本内容(供前端预览)。"""
        lines = []
        for r in self.enabled_deny_rules():
            lines.append("# " + (r.note or r.source))
            lines.append(r.to_shell_line())
        return "\n".join(lines)
