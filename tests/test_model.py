# -*- coding: utf-8 -*-
"""检测层单元测试：评分方向、阈值判定、缺失降级。"""

from __future__ import annotations

import os
import shutil
import sys
import unittest

import numpy as np

from tests import helpers
from tests.helpers import make_temp_dir

from netflow.model import AnomalyDetector
from netflow.stats import FEATURE_NAMES

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

def setUpModule() -> None:
    helpers.silence_logging()

def tearDownModule() -> None:
    helpers.restore_logging()
    helpers.cleanup()
# ====================================================================== #
# 检测层
# ====================================================================== #
class TestModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from sklearn.ensemble import IsolationForest

        cls.tmp = make_temp_dir("model-")
        cls.model_path = os.path.join(cls.tmp, "model.joblib")

        rng = np.random.default_rng(0)
        center = np.array([1000, 800000, 0.7, 0.25, 0.05, 40, 0.1, 700, 200, 160000],
                          dtype=float)
        scale = np.array([100, 50000, 0.05, 0.05, 0.01, 5, 0.02, 50, 30, 20000], dtype=float)
        normal = rng.normal(loc=center, scale=scale, size=(600, len(FEATURE_NAMES)))
        cls.center = center
        cls.scale = scale

        import joblib

        model = IsolationForest(n_estimators=100, contamination=0.05,
                                random_state=0, n_jobs=1).fit(normal)
        joblib.dump({"model": model, "scaler": None,
                     "feature_names": list(FEATURE_NAMES),
                     "threshold": -0.1, "meta": {"trained_at": "unittest"}},
                    cls.model_path)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_normal_scores_higher_than_anomaly(self) -> None:
        detector = AnomalyDetector(self.model_path)
        self.assertTrue(detector.enabled)
        normal_result = detector.score(self.center)
        anomaly_result = detector.score(self.center + 40 * self.scale)
        self.assertIsNotNone(normal_result.score)
        self.assertIsNotNone(anomaly_result.score)
        self.assertGreater(normal_result.score, anomaly_result.score,
                           "异常样本的 decision_function 分数应更低")

    def test_threshold_decision(self) -> None:
        """阈值判定的方向必须正确：分数低于阈值即异常。"""
        extreme = self.center + 40 * self.scale
        reference = AnomalyDetector(self.model_path)
        raw = reference.score(extreme).score
        self.assertIsNotNone(raw)

        # 阈值略高于该样本分数 → 必须判为异常
        above = AnomalyDetector(self.model_path, threshold=raw + 1e-6)
        self.assertTrue(above.score(extreme).is_anomaly)
        self.assertEqual(above.alert_count, 1)

        # 阈值略低于该样本分数 → 必须判为正常
        below = AnomalyDetector(self.model_path, threshold=raw - 1e-6)
        self.assertFalse(below.score(extreme).is_anomaly)
        self.assertEqual(below.alert_count, 0)

    def test_missing_model_degrades(self) -> None:
        detector = AnomalyDetector(os.path.join(self.tmp, "missing.joblib"))
        self.assertFalse(detector.enabled)
        result = detector.score(self.center)
        self.assertFalse(result.enabled)
        self.assertIsNone(result.score)
        self.assertFalse(result.is_anomaly)

    def test_missing_model_strict_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            AnomalyDetector(os.path.join(self.tmp, "missing.joblib"), strict=True)

    def test_dimension_mismatch(self) -> None:
        detector = AnomalyDetector(self.model_path)
        result = detector.score([1.0, 2.0])  # 维度错误：应安全返回
        self.assertIsNone(result.score)


if __name__ == "__main__":
    unittest.main(verbosity=2)
