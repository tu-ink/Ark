"""防御执行引擎: 将检测结果转化为可落地的安全动作(告警/封禁/规则/回调)。

设计要点(对应“检测→决策→防御”闭环中的防御环节):
    - 状态保存于 run/ 目录(JSON), 供外部安全设备/脚本读取联动;
    - 基于“同一源 IP 在滑动时间窗口内多次被判定为攻击”的累积证据触发封禁,
      降低单样本误报造成误封的风险(证据累积机制);
    - 提供与主流防火墙(nftables/iptables)兼容的规则导出, 便于落地到真实环境。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import RUN_DIR

DEFAULT_BLOCK_HITS = 3     # 触发封禁所需的最小告警次数
DEFAULT_WINDOW_SEC = 60.0  # 证据滑动时间窗口(秒)


@dataclass
class DefenseEvent:
    """一次检测事件(供防御引擎决策)。"""

    src_ip: str
    dst_ip: str = "0.0.0.0"
    verdict: str = "normal"          # 模型判决类别(normal/dos/probe/r2l/u2r/other)
    score: float = 0.0               # 攻击概率 [0,1]
    attack: bool = False             # 是否攻击
    ts: float = field(default_factory=time.time)
    flow: dict = field(default_factory=dict)


class DefenseEngine:
    """带证据累积的智能防御执行器。

    用法:
        engine = DefenseEngine()
        engine.handle(event)          # 每次检测事件都调用
        engine.blocked_ips()          # 当前封禁列表
    """

    def __init__(
        self,
        state_dir: str | Path = RUN_DIR,
        block_hits: int = DEFAULT_BLOCK_HITS,
        window_sec: float = DEFAULT_WINDOW_SEC,
        dry_run: bool = False,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.block_hits = max(1, block_hits)
        self.window_sec = window_sec
        self.dry_run = dry_run                      # True: 仅打印规则不写文件
        self._evidence: dict[str, list[float]] = {}  # src_ip -> 告警时间戳
        self._alerts: list[dict] = []
        self._load()

    # ------------------------------------------------------------- 事件入口
    def handle(self, ev: DefenseEvent) -> dict | None:
        """处理一条检测事件, 命中证据阈值时执行封禁。返回动作记录或 None。"""
        if not ev.attack:
            return None
        self._prune()
        stamp = ev.ts
        self._evidence.setdefault(ev.src_ip, []).append(stamp)
        alert = {
            "ts": stamp, "src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
            "verdict": ev.verdict, "score": round(float(ev.score), 4),
            "action": "alert",
        }
        self._alerts.append(alert)
        hits = len(self._evidence[ev.src_ip])
        if hits >= self.block_hits and not self._is_blocked(ev.src_ip):
            return self._block(ev, hits)
        return alert

    # ------------------------------------------------------------- 封禁动作
    def admin_block(self, ip: str, verdict: str = "manual", dst_ip: str = "0.0.0.0") -> dict:
        """管理后台强制封禁(不依赖证据累积), 返回动作记录。"""
        if self._is_blocked(ip):
            return {"src_ip": ip, "action": "already_blocked"}
        ev = DefenseEvent(src_ip=ip, dst_ip=dst_ip, verdict=verdict,
                          score=1.0, attack=True)
        return self._block(ev, hits=999)

    def _block(self, ev: DefenseEvent, hits: int) -> dict:
        record = {
            "ts": ev.ts, "src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
            "reason": f"{hits} 次攻击告警(窗口 {self.window_sec:.0f}s)",
            "verdict": ev.verdict, "score": round(float(ev.score), 4),
            "action": "block",
        }
        self._blocks.setdefault("ips", []).append(record)
        if not self.dry_run:
            self._append_firewall_rule(record)
            self._save()
        self._log_action(record)
        return record

    # ------------------------------------------------------------- 规则导出
    def _append_firewall_rule(self, record: dict) -> None:
        ip = record["src_ip"]
        rules = self.state_dir / "firewall_rules.sh"
        with open(rules, "a", encoding="utf-8") as fh:
            fh.write(
                f"# {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record['ts']))} "
                f"{record['action']} src={ip} reason={record['reason']}\n"
            )
            fh.write(f"nft add rule inet filter input ip saddr {ip} drop\n")
            fh.write(f"iptables -A INPUT -s {ip} -j DROP  # 兼容备份规则\n")

    def _log_action(self, record: dict) -> None:
        ip = record["src_ip"]
        act = record["action"]
        print(f"[defense] {act.upper():6s} src_ip={ip:<16s} "
              f"verdict={record['verdict']:<6s} score={record['score']:.3f}")

    # ------------------------------------------------------------- 状态维护
    def _prune(self) -> None:
        now = time.time()
        for ip in list(self._evidence):
            self._evidence[ip] = [t for t in self._evidence[ip] if now - t <= self.window_sec]
            if not self._evidence[ip]:
                self._evidence.pop(ip, None)

    def _is_blocked(self, ip: str) -> bool:
        return any(b["src_ip"] == ip for b in self._blocks.get("ips", []))

    def blocked_ips(self) -> list[str]:
        return [b["src_ip"] for b in self._blocks.get("ips", [])]

    def alert_count(self) -> int:
        return len(self._alerts)

    def stats(self) -> dict:
        return {
            "alerts": len(self._alerts),
            "blocked": len(self._blocks.get("ips", [])),
            "active_evidence_srcs": len(self._evidence),
        }

    # ------------------------------------------------------------- 持久化
    def _state_paths(self) -> tuple[Path, Path]:
        return self.state_dir / "alerts.jsonl", self.state_dir / "blocklist.json"

    def _save(self) -> None:
        with open(self._state_paths()[1], "w", encoding="utf-8") as fh:
            json.dump(self._blocks, fh, ensure_ascii=False, indent=2)

    def _load(self) -> None:
        self._blocks: dict = {"ips": []}
        p = self._state_paths()[1]
        if p.exists():
            try:
                self._blocks = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self._blocks = {"ips": []}
