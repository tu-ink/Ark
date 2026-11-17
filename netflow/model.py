# -*- coding: utf-8 -*-
"""检测层（model）：加载 Isolation Forest 模型并对每个时间窗口打分。

关于分数方向
------------
scikit-learn 的 ``IsolationForest.decision_function`` 返回值**越低越异常**：

* 大于 0：模型认为该样本属于正常分布；
* 小于 0：模型认为该样本是异常点（``offset_`` 由训练集分数的
  ``100 * contamination`` 分位数确定）。

判定规则为 ``score < threshold`` 即告警。默认阈值来自训练产物
（``train_model`` 默认写入 sklearn 自带校准点，含义是「约 contamination 比例的
正常窗口会被判为异常」）；若模型产物中没有阈值，则回退到 :data:`DEFAULT_THRESHOLD`。
保守场景可显式使用 ``--threshold -0.1``（实测约相当于正常分数分布的 P0.1）。

孤立森林的两个固有局限（实测数据见 README「检测效果说明」）：

* **分数饱和**：样本再怎么超出训练范围，分数也不会无限降低；
* **特征稀释**：只有少数几个特征异常时，其余正常特征会显著抬高路径长度。

模型产物格式
------------
``model.joblib`` 支持两种内容，加载时自动识别：

1. **推荐（训练脚本输出）**：字典包::

       {"model": IsolationForest, "scaler": StandardScaler | None,
        "feature_names": [...], "threshold": float, "meta": {...}}

2. 裸的 ``IsolationForest`` 估计器（兼容手工保存的模型，此时不做标准化）。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import joblib
import numpy as np

from .stats import FEATURE_NAMES

logger = logging.getLogger(__name__)

#: 阈值回退值：仅当模型产物里没有保存阈值时使用。
#: ``decision_function`` 的零点由训练时的 ``contamination`` 决定，
#: 因此 0.0 是 sklearn 自带的校准点。
DEFAULT_THRESHOLD = 0.0


#: 默认模型文件名
DEFAULT_MODEL_PATH = "model.joblib"


@dataclass
class ScoreResult:
    """一次评分的结果。"""

    score: Optional[float]           # decision_function 原始分数；None 表示未启用检测
    is_anomaly: bool                 # 是否判定为异常
    threshold: Optional[float]       # 本次使用的阈值
    enabled: bool                    # 检测是否处于启用状态

    def format_score(self) -> str:
        """用于界面展示的分数文本。"""
        if self.score is None:
            return "N/A"
        return "{0:.4f}".format(self.score)


class AnomalyDetector:
    """Isolation Forest 异常评分器。

    Parameters
    ----------
    model_path:
        ``model.joblib`` 路径。
    threshold:
        判定阈值。``None`` 表示优先使用模型产物中保存的阈值，
        否则回退到 :data:`DEFAULT_THRESHOLD`。
    feature_names:
        特征顺序，默认使用 :data:`netflow.stats.FEATURE_NAMES`，必须与训练时一致。
    strict:
        ``True`` 时模型缺失/加载失败直接抛异常；``False``（默认）时打印告警
        并降级为「只统计、不检测」模式，保证监测流程不中断。
    """

    def __init__(
        self,
        model_path: str = DEFAULT_MODEL_PATH,
        threshold: Optional[float] = None,
        feature_names: Sequence[str] = FEATURE_NAMES,
        strict: bool = False,
    ) -> None:
        self.model_path = model_path
        self.feature_names: List[str] = list(feature_names)
        self.threshold: Optional[float] = (
            float(threshold) if threshold is not None else None
        )
        self.strict = bool(strict)

        self.model = None
        self.scaler = None
        self.meta: Dict[str, Any] = {}
        self.enabled = False
        self.alert_count = 0
        self.score_count = 0

        self.load()

    # ------------------------------------------------------------------ #
    # 加载
    # ------------------------------------------------------------------ #
    def load(self) -> None:
        """加载模型产物；失败时按 ``strict`` 决定抛异常还是降级。"""
        if not os.path.isfile(self.model_path):
            self._degrade(
                "未找到模型文件 {0}，异常检测已禁用。"
                "请先运行:  python -m netflow.train_model --csv <CIC-IDS2017 CSV 路径>".format(
                    self.model_path
                )
            )
            return

        try:
            bundle = joblib.load(self.model_path)
        except Exception as exc:
            self._degrade("加载模型 {0} 失败: {1}".format(self.model_path, exc))
            return

        if isinstance(bundle, dict):
            self.model = bundle.get("model")
            self.scaler = bundle.get("scaler")
            self.meta = bundle.get("meta") or {}
            names = bundle.get("feature_names")
            if names:
                if list(names) != self.feature_names:
                    logger.warning(
                        "模型特征顺序与当前统计层不一致，已采用模型中的顺序:\n"
                        "  模型: %s\n  当前: %s", list(names), self.feature_names)
                self.feature_names = list(names)
            if self.threshold is None and bundle.get("threshold") is not None:
                self.threshold = float(bundle["threshold"])
        else:
            # 兼容：直接保存的裸估计器
            self.model = bundle
            self.scaler = None
            self.meta = {"format": "bare-estimator"}

        if self.model is None or not hasattr(self.model, "decision_function"):
            self._degrade("模型文件中未找到可用的 IsolationForest 估计器")
            return

        if self.threshold is None:
            self.threshold = DEFAULT_THRESHOLD
            logger.info("模型产物未包含阈值，使用默认阈值 %.4f", self.threshold)

        self.enabled = True
        logger.info("模型加载成功: %s | 特征数=%d | 阈值=%.4f | 训练信息=%s",
                    os.path.basename(self.model_path), len(self.feature_names),
                    self.threshold, self.meta.get("trained_at", "未知"))

    def _degrade(self, message: str) -> None:
        """进入降级模式（只统计不检测）或按 ``strict`` 直接失败。"""
        if self.strict:
            raise RuntimeError(message)
        logger.warning(message)
        self.enabled = False

    # ------------------------------------------------------------------ #
    # 评分
    # ------------------------------------------------------------------ #
    def _prepare(self, features: Sequence[float]) -> "np.ndarray":
        """把特征向量整理成 (1, n_features) 的浮点数组并按需标准化。"""
        vector = np.asarray(features, dtype=np.float64).reshape(1, -1)
        if vector.shape[1] != len(self.feature_names):
            raise ValueError("特征维度不匹配: 输入 {0} 维, 期望 {1} 维 ({2})".format(
                vector.shape[1], len(self.feature_names), self.feature_names))
        if not np.all(np.isfinite(vector)):
            # 极端情况下可能出现 inf（例如窗口时长极短导致 bps 溢出）
            vector = np.nan_to_num(vector, nan=0.0, posinf=0.0, neginf=0.0)
        if self.scaler is not None:
            vector = self.scaler.transform(vector)
        return vector

    def score(self, features: Sequence[float]) -> ScoreResult:
        """对单个特征向量评分，返回 :class:`ScoreResult`。"""
        if not self.enabled:
            return ScoreResult(score=None, is_anomaly=False,
                               threshold=self.threshold, enabled=False)
        try:
            vector = self._prepare(features)
            raw = float(self.model.decision_function(vector)[0])
        except Exception:
            logger.exception("模型评分失败，本窗口跳过异常判定")
            return ScoreResult(score=None, is_anomaly=False,
                               threshold=self.threshold, enabled=False)

        self.score_count += 1
        is_anomaly = raw < (self.threshold if self.threshold is not None else DEFAULT_THRESHOLD)
        if is_anomaly:
            self.alert_count += 1
        return ScoreResult(score=raw, is_anomaly=bool(is_anomaly),
                           threshold=self.threshold, enabled=True)

    def score_window(self, window) -> ScoreResult:
        """对 :class:`netflow.stats.WindowStats` 对象评分（语法糖）。"""
        return self.score(window.to_vector())

    # ------------------------------------------------------------------ #
    def describe(self) -> str:
        """返回模型简介，用于启动横幅与日志。"""
        if not self.enabled:
            return "异常检测: 未启用（缺少模型）"
        params = getattr(self.model, "get_params", lambda: {})()
        return ("异常检测: 已启用 | 阈值={0:.4f} | n_estimators={1} | "
                "max_samples={2} | contamination={3}".format(
                    self.threshold if self.threshold is not None else DEFAULT_THRESHOLD,
                    params.get("n_estimators", "?"),
                    params.get("max_samples", "?"),
                    params.get("contamination", "?"),
                ))

    def calibration(self) -> Dict[str, float]:
        """返回训练产物中保存的阈值标定表（可能为空字典）。"""
        table = self.meta.get("calibration")
        return dict(table) if isinstance(table, dict) else {}


def load_detector(
    model_path: str = DEFAULT_MODEL_PATH,
    threshold: Optional[float] = None,
    strict: bool = False,
) -> AnomalyDetector:
    """构造检测器的便捷函数。"""
    return AnomalyDetector(model_path=model_path, threshold=threshold, strict=strict)


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.model`` 自检：现场训练最小模型并评分。"""
    from sklearn.ensemble import IsolationForest

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    rng = np.random.default_rng(42)
    normal = rng.normal(loc=[1000, 800000, 0.7, 0.25, 0.05, 40, 0.1, 700, 200, 160000],
                        scale=[200, 100000, 0.05, 0.05, 0.01, 5, 0.02, 50, 40, 20000],
                        size=(2000, len(FEATURE_NAMES)))
    model = IsolationForest(n_estimators=100, contamination=0.01,
                            random_state=42, n_jobs=1).fit(normal)
    path = "model_selftest.joblib"
    joblib.dump({"model": model, "scaler": None, "feature_names": list(FEATURE_NAMES),
                 "threshold": DEFAULT_THRESHOLD, "meta": {"trained_at": "selftest"}}, path)

    detector = AnomalyDetector(path)
    print(detector.describe())
    print("正常样本:", detector.score(
        [1000, 800000, 0.7, 0.25, 0.05, 40, 0.1, 700, 200, 160000]))
    print("异常样本:", detector.score(
        [50000, 4000000, 0.0, 0.0, 1.0, 3000, 0.9, 80, 10000, 800000]))
    os.remove(path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
