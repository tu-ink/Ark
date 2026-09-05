"""流式检测引擎: 对单条/批量网络流进行在线判决。

与训练器解耦: FlowDetector 加载训练产物后, 对每条流输出:
    - verdict : 判决类别(normal / dos / probe / r2l / u2r / other)
    - score   : “是攻击”的置信概率 [0,1]
    - attack  : 是否攻击(score >= threshold)
阈值可由使用者按“误报/漏报”偏好调整(threshold 降低 → 更敏感、漏报更少)。
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from .config import KDD_FEATURES, LABEL_COL
from .models import Trainer


@dataclass
class Detection:
    verdict: str
    score: float
    attack: bool
    probs: dict

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": round(float(self.score), 4),
            "attack": bool(self.attack),
            "probs": {k: round(float(v), 4) for k, v in self.probs.items()},
        }


class FlowDetector:
    def __init__(self, trainer: Trainer, threshold: float = 0.5) -> None:
        self.trainer = trainer
        self.threshold = float(threshold)
        self.classes = list(trainer.class_names_)

    # -- 单流判决 ----------------------------------------------------------
    def detect_one(self, flow: dict | pd.Series) -> Detection:
        row = self._to_frame(flow)
        proba = self.trainer.predict_proba(row).iloc[0]
        probs = {c: float(proba.get(c, 0.0)) for c in self.classes}
        # 若训练类集合不含某攻击家族, 相应概率计 0 并由 1-P(normal) 兜底
        attack_prob = max(1.0 - probs.get("normal", 0.0), 0.0)
        attack_prob = max(attack_prob, float(sum(v for k, v in probs.items() if k != "normal")))
        attack = attack_prob >= self.threshold
        if attack:
            cands = {k: v for k, v in probs.items() if k != "normal"}
            verdict = max(cands, key=cands.get) if cands else "other"
        else:
            verdict = "normal"
        return Detection(verdict=verdict, score=attack_prob, attack=attack, probs=probs)

    def detect_batch(self, df: pd.DataFrame) -> list[Detection]:
        return [self.detect_one(row) for _, row in df.iterrows()]

    @staticmethod
    def _to_frame(flow: dict | pd.Series) -> pd.DataFrame:
        if isinstance(flow, pd.Series):
            data = flow.to_dict()
        else:
            data = dict(flow)
        missing = [c for c in KDD_FEATURES if c not in data]
        if missing:
            raise KeyError(f"输入流缺少特征列: {missing[:6]} ...")
        return pd.DataFrame([data], columns=KDD_FEATURES)

    @staticmethod
    def load(model_path: str, threshold: float = 0.5) -> "FlowDetector":
        return FlowDetector(Trainer.load(model_path), threshold=threshold)


def attach_predictions(df: pd.DataFrame, detector: FlowDetector) -> pd.DataFrame:
    """批量推理: 给数据框追加 verdict/score/attack 三列。"""
    out = df.copy()
    rows = []
    for _, r in df.iterrows():
        d = detector.detect_one(r.drop(columns=[LABEL_COL], errors="ignore"))
        rows.append((d.verdict, d.score, d.attack))
    out["pred_verdict"], out["pred_score"], out["pred_attack"] = zip(*rows)
    return out
