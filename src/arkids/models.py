"""模型: 训练、持久化与加载(随机森林 / 梯度提升 / 多层感知机可选)。

约定:
    - 对外的标签一律为攻击家族字符串(normal/dos/probe/r2l/u2r);
    - 内部使用 sklearn LabelEncoder 将字符串编码为整数再训练/推理,
      避免部分 sklearn 版本在字符串标签 + early_stopping 等路径下的兼容问题。
"""
from __future__ import annotations

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

from .config import CLASSES, is_attack
from .features import FeaturePreparer

ALGOS = ("rf", "gb", "mlp")


def _n_jobs() -> int:
    """并行度: 默认 1(兼容受限运行环境), 可通过 ARKIDS_N_JOBS 环境变量调大。"""
    return int(__import__("os").environ.get("ARKIDS_N_JOBS", "1"))


def build_model(algo: str = "rf", random_state: int = 42):
    """按名称构建基学习器; 超参为面向 41 维流量特征的轻量默认值。"""
    algo = algo.lower()
    if algo == "rf":
        return RandomForestClassifier(
            n_estimators=200, max_depth=20, min_samples_leaf=2,
            n_jobs=_n_jobs(), random_state=random_state, class_weight="balanced_subsample",
        )
    if algo == "gb":
        return GradientBoostingClassifier(
            n_estimators=180, max_depth=5, learning_rate=0.08, random_state=random_state,
        )
    if algo == "mlp":
        return MLPClassifier(
            hidden_layer_sizes=(128, 64), max_iter=400, early_stopping=True,
            random_state=random_state, n_iter_no_change=15,
        )
    raise ValueError(f"未知算法: {algo}, 可选 {ALGOS}")


class Trainer:
    """封装“标签编码 + 特征变换 + 模型训练 + 评估 + 打包持久化”。

    检测任务为 5 分类(normal/dos/probe/r2l/u2r), 同时派生二元“是否攻击”
    标签用于计算 ROC-AUC 等指标。
    """

    def __init__(self, algo: str = "rf", random_state: int = 42) -> None:
        self.algo = algo
        self.random_state = random_state
        self.preparer = FeaturePreparer()
        self.model = build_model(algo, random_state)
        self.pipe: Pipeline | None = None
        self.le: LabelEncoder | None = None       # 家族标签 <-> 整数编码
        self.class_names_: list[str] = list(CLASSES)  # 模型输出类别(字符串)

    # -- 训练与评估 -------------------------------------------------------
    def fit(self, X_train: pd.DataFrame, y_train: pd.Series) -> "Trainer":
        known = set(CLASSES)
        unknown = sorted(set(y_train) - known)
        if unknown:
            raise ValueError(f"训练标签含未定义类别: {unknown}")
        Xf = self.preparer.fit_transform(X_train)
        le = LabelEncoder()
        y_int = le.fit_transform(y_train)          # 字符串 -> 0..k-1
        self.le = le
        self.class_names_ = [str(c) for c in le.classes_]
        self.pipe = Pipeline([("clf", self.model)])
        self.pipe.fit(Xf, y_int)
        self._n_train = int(len(X_train))
        return self

    def _decode(self, code: int) -> str:
        if self.le is None:
            raise RuntimeError("模型未训练")
        return str(self.le.inverse_transform([int(code)])[0])

    def predict(self, X: pd.DataFrame) -> pd.Series:
        if self.pipe is None:
            raise RuntimeError("模型未训练")
        pred_int = self.pipe.predict(self.preparer.transform(X))
        return pd.Series([self._decode(c) for c in pred_int])

    def predict_proba(self, X: pd.DataFrame) -> pd.DataFrame:
        if self.pipe is None:
            raise RuntimeError("模型未训练")
        proba = self.pipe.predict_proba(self.preparer.transform(X))
        names = [self._decode(c) for c in self.pipe.classes_]
        return pd.DataFrame(proba, columns=names)

    def attack_probability(self, X: pd.DataFrame) -> pd.Series:
        """任一类攻击的总概率 = 1 - P(normal)。"""
        proba = self.predict_proba(X)
        normal = proba["normal"] if "normal" in proba else 0.0
        return (1.0 - normal).clip(lower=0.0, upper=1.0)

    # -- 持久化 -----------------------------------------------------------
    def save(self, path: str) -> str:
        if self.pipe is None:
            raise RuntimeError("模型未训练, 无法保存")
        bundle = {
            "algo": self.algo,
            "class_names": self.class_names_,
            "label_encoder": self.le,
            "preparer": self.preparer,
            "model": self.pipe,
        }
        joblib.dump(bundle, str(path), compress=3)
        return str(path)

    @staticmethod
    def load(path: str) -> "Trainer":
        bundle = joblib.load(str(path))
        t = Trainer(algo=bundle["algo"])
        t.preparer = bundle["preparer"]
        t.pipe = bundle["model"]
        t.le = bundle.get("label_encoder")
        t.class_names_ = bundle.get("class_names") or list(CLASSES)
        return t

    # -- 便捷评估 ---------------------------------------------------------
    def evaluate(self, X: pd.DataFrame, y_true: pd.Series) -> dict:
        """返回 sklearn classification_report 文本与关键指标 dict。"""
        y_pred = self.predict(X)
        y_true_bin = y_true.map(lambda s: "attack" if is_attack(s) else "normal")
        y_pred_bin = y_pred.map(lambda s: "attack" if is_attack(s) else "normal")

        from sklearn.metrics import (accuracy_score, f1_score,
                                     precision_score, recall_score, roc_auc_score)

        attack_prob = self.attack_probability(X)
        auc = roc_auc_score((y_true_bin == "attack").astype(int), attack_prob)
        report_txt = classification_report(y_true, y_pred, digits=4, zero_division=0)
        macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
        weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
        return {
            "accuracy": accuracy_score(y_true, y_pred),
            "attack_auc": auc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "attack_precision": precision_score(y_true_bin, y_pred_bin, pos_label="attack", zero_division=0),
            "attack_recall": recall_score(y_true_bin, y_pred_bin, pos_label="attack", zero_division=0),
            "report_txt": report_txt,
            "n_train": int(getattr(self, "_n_train", 0)),
        }
