"""AI 智能建议引擎: 规则化“智能专家” + 可选大模型(LLM)增强建议。

两级建议:
    1) HeuristicAdvisor —— 本地规则引擎(不依赖外网): 根据实时统计、检测事件、
       防御状态、防火墙规则等, 输出“可解释的处置建议”(风险等级/依据/建议动作);
    2) LLMAdvisor    —— 可选在线增强: 当本机存在 DEEPSEEK_API_KEY(环境变量或
       Windows 凭据管理器 reasonix:DEEPSEEK_API_KEY)时, 将系统态势摘要交给
       大模型生成更综合的研判与对策; 未配置/失败时自动回退到规则引擎。
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from collections import Counter

DEEPSEEK_API = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"


# ------------------------------------------------------------------ 规则引擎
class HeuristicAdvisor:
    """依据态势上下文(context)输出处置建议(可解释、无需外网)。"""

    def __init__(self, default_threshold: float = 0.5) -> None:
        self.threshold = default_threshold

    def suggest(self, context: dict) -> list[dict]:
        ctx = context or {}
        stats = ctx.get("stats") or {}
        events = ctx.get("events") or []
        blocklist = ctx.get("blocklist") or []
        rules = ctx.get("fw_rules") or []
        out: list[dict] = []
        self._rate_threat(out, stats)
        self._probe_scan(out, events, blocklist)
        self._dos_burst(out, events, stats)
        self._accuracy_balance(out, ctx, stats)
        self._fw_sync(out, blocklist, rules)
        self._escalation(out, stats)
        return out

    @staticmethod
    def _mk(level: str, title: str, detail: str, action: str,
            confidence: float = 0.7, source: str = "rule-engine") -> dict:
        return {"level": level, "title": title, "detail": detail,
                "recommended_action": action,
                "confidence": round(min(max(confidence, 0), 1), 2),
                "source": source, "ts": time.time()}

    def _rate_threat(self, out: list, stats: dict) -> None:
        attack_rate = stats.get("attack_rate", 0.0)
        if attack_rate > 0.55:
            out.append(self._mk(
                "critical", "攻击流量占比过高",
                f"近窗口内 {stats.get('flows_window', 0)} 条流量中攻击占比 "
                f"{attack_rate:.0%}, 网络处于被持续攻击状态。",
                "立即复查封禁清单, 确认网关已启用 deny 规则, 必要时一键阻断全部攻击源。",
                confidence=0.9))
        elif attack_rate > 0.3:
            out.append(self._mk(
                "warn", "攻击流量占比上升",
                f"当前攻击占比 {attack_rate:.0%}, 存在小规模攻击或扫描。",
                "关注 Top 攻击源并在防火墙中新增 deny 规则(证据窗口默认 3 次/60s)。",
                confidence=0.7))

    def _probe_scan(self, out: list, events: list, blocklist: list) -> None:
        probes = [e for e in events if e.get("verdict") == "probe"]
        if len(probes) >= 3:
            srcs = Counter(e["src"] for e in probes)
            top = srcs.most_common(1)[0]
            blocked = {b for b in blocklist}
            if top[0] not in blocked:
                out.append(self._mk(
                    "warn", "疑似端口/主机扫描(Probe)",
                    f"最近 {len(probes)} 条探测告警, 高频源 {top[0]} 尚未被自动封禁。",
                    f"建议为 {top[0]} 添加 deny 规则或调低 block_hits 以加快响应。",
                    confidence=0.85))

    def _dos_burst(self, out: list, events: list, stats: dict) -> None:
        dos = [e for e in events if e.get("verdict") == "dos"]
        if len(dos) >= 5 and len(dos) >= 0.5 * len(events):
            out.append(self._mk(
                "critical", "疑似 DoS 洪泛",
                "短时间内大量连接被判为 DoS(如 SYN 洪泛特征), 业务可用性受威胁。",
                "建议启用流量限速/黑洞路由, 并核对服务器并发连接与带宽水位。",
                confidence=0.88))

    def _accuracy_balance(self, out: list, ctx: dict, stats: dict) -> None:
        fp = stats.get("fp", 0)
        fn = stats.get("fn", 0)
        tp = stats.get("tp", 0)
        hits = fp + fn + tp + stats.get("tn", 0)
        if hits >= 50:
            fp_ratio = fp / max(hits, 1)
            recall = tp / max(tp + fn, 1)
            if fp_ratio > 0.05:
                out.append(self._mk(
                    "warn", "误报率偏高",
                    f"近 {hits} 条已标注样本中误报 {fp} 条({fp_ratio:.1%})。",
                    f"建议将检测阈值从 {self.threshold:.2f} 提高(如 0.6), 减少误封风险。",
                    confidence=0.8))
            if recall < 0.85 and fp_ratio < 0.02:
                out.append(self._mk(
                    "info", "漏检占比上升",
                    f"已标注样本检出率 {recall:.1%}, 漏检多为隐蔽攻击(R2L/U2R 型)。",
                    "可补充流量侧特征(如会话时长、载荷统计)或部署针对性模型后再调低阈值。",
                    confidence=0.75))

    def _fw_sync(self, out: list, blocklist: list, rules: list) -> None:
        deny_srcs = {r.get("src_ip") for r in rules
                     if r.get("action") == "deny" and r.get("enabled")}
        unsynced = [ip for ip in blocklist if ip not in deny_srcs]
        if unsynced:
            out.append(self._mk(
                "info", "封禁清单与防火墙规则未同步",
                f"{len(unsynced)} 个已封禁源 IP 未生成对应 deny 规则。",
                "在防火墙编辑器中为这些 IP 添加 deny 规则: " + ", ".join(unsynced),
                confidence=0.95))

    def _escalation(self, out: list, stats: dict) -> None:
        blocked = stats.get("blocked", 0)
        active = stats.get("active_srcs", 0)
        if blocked >= 3 and active >= blocked * 2:
            out.append(self._mk(
                "critical", "攻击源多样化、封禁仍持续新增",
                f"已封禁 {blocked} 个源, 仍有 {active} 个活跃源在触发告警, 疑似分布式/自动化攻击。",
                "建议升级为分布式防御策略: 限速+验证码/CDN 清洗, 并上报态势。",
                confidence=0.85))


# ------------------------------------------------------------------ LLM 增强
def _cred_read(target: str) -> str | None:
    """读取 Windows 凭据管理器中的通用凭据(密码) —— 纯 ctypes 实现。"""
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME),
                    ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                    ("Persist", wintypes.DWORD),
                    ("AttributeCount", wintypes.DWORD),
                    ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]

    try:
        advapi = ctypes.windll.advapi32
        p = ctypes.c_void_p()
        if not advapi.CredReadW(target, 1, 0, ctypes.byref(p)):
            return None
        cred = ctypes.cast(p, ctypes.POINTER(CREDENTIAL)).contents
        size = cred.CredentialBlobSize
        blob = b"".join(
            bytes([cred.CredentialBlob[i]]) for i in range(size)) if size else b""
        advapi.CredFree(p)
        return blob.decode("utf-8", errors="ignore").rstrip("\x00") or None
    except Exception:
        return None


def resolve_api_key() -> str | None:
    """依次从 环境变量 / Windows 凭据管理器 获取 DeepSeek API Key。"""
    key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if key:
        return key
    try:
        return _cred_read("reasonix:DEEPSEEK_API_KEY")
    except Exception:
        return None


class LLMAdvisor:
    def __init__(self, api_key: str | None = None, model: str = DEEPSEEK_MODEL) -> None:
        # api_key 为 None 时才回退到环境变量/凭据管理器; 显式传空串表示“禁用”
        self.api_key = api_key if api_key is not None else resolve_api_key()
        self.model = model
        self.base_url = os.environ.get("ARKIDS_LLM_API", DEEPSEEK_API)

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def advise(self, situation: dict, question: str = "请给出网络攻防处置建议") -> str:
        if not self.available:
            raise RuntimeError("未配置 DEEPSEEK_API_KEY")
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system",
                 "content": "你是资深网络安全分析专家。请基于给定的实时攻防态势JSON，"
                            "用中文给出简明、可执行的研判与处置建议(检测/防御/调优)，"
                            "不要编造态势中不存在的数据。"},
                {"role": "user",
                 "content": "当前态势(JSON):\n" + json.dumps(situation, ensure_ascii=False)[:6000]
                            + "\n\n" + question},
            ],
            "temperature": 0.3,
            "max_tokens": 900,
        }
        req = urllib.request.Request(
            self.base_url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + self.api_key},
            method="POST")
        # 受限内网/TLS 拦截环境下允许关闭校验(ARKIDS_LLM_INSECURE=1)
        ctx = None
        if os.environ.get("ARKIDS_LLM_INSECURE") == "1":
            import ssl
            ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()


class AIAdvisor:
    """统一出口: 规则建议 + (可选)LLM 建议。"""

    def __init__(self, threshold: float = 0.5, api_key: str | None = None) -> None:
        self.heuristic = HeuristicAdvisor(default_threshold=threshold)
        self.llm = LLMAdvisor(api_key=api_key)

    @property
    def llm_available(self) -> bool:
        return self.llm.available

    def rules(self, context: dict) -> list[dict]:
        return self.heuristic.suggest(context)

    def llm_advice(self, context: dict, question: str = "") -> dict:
        if not self.llm.available:
            return {"ok": False, "error": "未配置 API Key(设置 DEEPSEEK_API_KEY 后可用)"}
        try:
            text = self.llm.advise(context, question or "请给出网络攻防处置建议")
            return {"ok": True, "text": text}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"LLM 调用失败, 已回退规则引擎: {exc}"}
