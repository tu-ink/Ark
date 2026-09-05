"""特征工程: 类别特征 One-Hot 编码 + 数值特征标准化, 构建统一特征变换器。"""
from __future__ import annotations

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .config import CATEGORICAL_FEATURES, KDD_FEATURES

NUMERIC_FEATURES = [c for c in KDD_FEATURES if c not in CATEGORICAL_FEATURES]


class FeaturePreparer:
    """封装训练/推理共用的特征变换逻辑。

    fit(X)     : 依据训练数据学习编码与标准化参数
    transform(X): 输出可直接送入模型的数值特征矩阵
    """

    def __init__(self) -> None:
        self._transformer: ColumnTransformer | None = None

    def _build(self) -> ColumnTransformer:
        return ColumnTransformer(
            transformers=[
                (
                    "cat",
                    OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                    CATEGORICAL_FEATURES,
                ),
                ("num", StandardScaler(), NUMERIC_FEATURES),
            ],
            remainder="drop",
        )

    def fit(self, X: pd.DataFrame) -> "FeaturePreparer":
        self._transformer = self._build()
        self._transformer.fit(X[KDD_FEATURES])
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if self._transformer is None:
            raise RuntimeError("FeaturePreparer 尚未 fit, 请先调用 fit()")
        cols = self._transformer.get_feature_names_out()
        arr = self._transformer.transform(X[KDD_FEATURES])
        return pd.DataFrame(arr, columns=cols)

    def fit_transform(self, X: pd.DataFrame) -> pd.DataFrame:
        return self.fit(X).transform(X)
