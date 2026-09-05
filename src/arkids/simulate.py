"""实时流量回放与攻击仿真: 让“检测 + 防御”闭环可离线演示。

思路:
    1. 读取带标签的流量文件(演示/NSL-KDD 皆可), 在“仿真网络”中为每条流分配
       源/目的 IP: 攻击源收敛到少数“攻击者”IP(体现多阶段/持续性攻击行为),
       正常流量均匀分布在内部主机 —— 从而使证据累积机制(滑动窗口封禁)生效;
    2. 逐条(可按速率)送入 FlowDetector, 命中攻击则由 DefenseEngine 处理;
    3. 结束时输出: 检测指标(与真实标签比对) + 防御动作统计 + 封禁清单。
"""
from __future__ import annotations

import time
from pathlib import Path

import numpy as np
import pandas as pd

from .config import KDD_FEATURES, LABEL_COL, is_attack
from .dataset import load_any
from .defense import DefenseEngine, DefenseEvent
from .detector import FlowDetector


def _hash_ip(x: int) -> str:
    return f"10.10.{int(x) % 255}.{int(x * 7) % 255}"


def assign_endpoints(df: pd.DataFrame, seed: int = 7, attacker_pool: int = 4) -> pd.DataFrame:
    """为流量指派源/目的地址(演示用途, 非真实五元组)。"""
    rng = np.random.default_rng(seed)
    srcs, dsts = [], []
    attacker_ips = [f"203.0.113.{i + 10}" for i in range(attacker_pool)]  # 文档网段
    for _, row in df.iterrows():
        attack = is_attack(row.get(LABEL_COL, "normal"))
        if attack:
            src = attacker_ips[int(rng.integers(0, attacker_pool))]
            dst = _hash_ip(int(rng.integers(0, 1000)))
        else:
            src = _hash_ip(int(rng.integers(0, 40000)))
            dst = "192.168.1.10"
        srcs.append(src)
        dsts.append(dst)
    out = df.copy()
    out.insert(0, "src_ip", srcs)
    out.insert(1, "dst_ip", dsts)
    return out


def run_simulation(
    data_path: str,
    model_path: str,
    threshold: float = 0.5,
    limit: int | None = None,
    attacker_pool: int = 4,
    block_hits: int = 3,
    window_sec: float = 60.0,
    speed: float = 0.0,            # 每秒回放条数, 0 表示尽快
    dry_run: bool = False,
    state_dir: str | Path | None = None,
    seed: int = 7,
) -> dict:
    df = load_any(data_path)
    if limit:
        df = df.head(limit)
    df = assign_endpoints(df, seed=seed, attacker_pool=attacker_pool)
    detector = FlowDetector.load(model_path, threshold=threshold)
    engine = DefenseEngine(
        state_dir=state_dir or Path("run"),
        block_hits=block_hits, window_sec=window_sec, dry_run=dry_run,
    )

    true_labels = df.get(LABEL_COL)
    hits = tp = fp = tn = fn = 0
    start = time.time()
    for idx, (_, row) in enumerate(df.iterrows(), start=1):
        flow = {c: row[c] for c in KDD_FEATURES}
        det = detector.detect_one(flow)
        ev = DefenseEvent(
            src_ip=row["src_ip"], dst_ip=row["dst_ip"],
            verdict=det.verdict, score=det.score, attack=det.attack,
        )
        engine.handle(ev)
        truth = None
        if true_labels is not None:
            truth = is_attack(row[LABEL_COL])
            hits += 1
            if det.attack and truth:
                tp += 1
            elif det.attack and not truth:
                fp += 1
            elif not det.attack and truth:
                fn += 1
            else:
                tn += 1
        if speed > 0 and idx % max(1, int(speed)) == 0:
            time.sleep(1.0 / speed)
        if idx <= 12 or det.attack or idx % 500 == 0:
            mark = "!!!" if det.attack else "   "
            print(f"[{idx:>5d}] {mark} {row['src_ip']:<16s} -> {row['dst_ip']:<15s} "
                  f"verdict={det.verdict:<6s} score={det.score:.3f}")

    elapsed = time.time() - start
    summary = {
        "flows": len(df),
        "elapsed_s": round(elapsed, 3),
        "throughput_fps": round(len(df) / max(elapsed, 1e-6), 1),
        "defense": engine.stats(),
        "blocked_ips": engine.blocked_ips(),
    }
    if true_labels is not None and hits:
        summary["metrics"] = {
            "true_attack": tp + fn, "true_normal": tn + fp,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "recall(攻击检出率)": round(tp / max(tp + fn, 1), 4),
            "precision": round(tp / max(tp + fp, 1), 4),
            "accuracy": round((tp + tn) / max(hits, 1), 4),
        }
    print("\n===== 仿真结束摘要 =====")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    return summary
