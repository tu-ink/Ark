import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pandas as pd  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from arkids.config import CLASSES, LABEL_COL  # noqa: E402
from arkids.dataset import generate_demo_flows  # noqa: E402
from arkids.models import Trainer  # noqa: E402


def _fit_tiny_trainer(seed: int = 5):
    df = generate_demo_flows(n=800, seed=seed)
    X = df.drop(columns=[LABEL_COL])
    y = df[LABEL_COL]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=0)
    trainer = Trainer(algo="rf", random_state=0)
    trainer.fit(Xtr, ytr)
    return trainer, Xte, yte


class TestModels(unittest.TestCase):
    def test_train_predict_roundtrip(self):
        trainer, Xte, yte = _fit_tiny_trainer()
        pred = trainer.predict(Xte)
        self.assertEqual(len(pred), len(yte))
        self.assertTrue(set(pred).issubset(set(CLASSES)))
        proba = trainer.predict_proba(Xte)
        self.assertAlmostEqual(float(proba.sum(axis=1).mean()), 1.0, places=4)

    def test_evaluate_metrics(self):
        trainer, Xte, yte = _fit_tiny_trainer()
        m = trainer.evaluate(Xte, yte)
        for key in ("accuracy", "attack_auc", "macro_f1", "weighted_f1"):
            self.assertIn(key, m)
            self.assertGreaterEqual(m[key], 0.0)
            self.assertLessEqual(m[key], 1.0)
        # 演示数据规律清晰, 测试集 F1 应明显优于随机
        self.assertGreater(m["accuracy"], 0.7)

    def test_save_load(self):
        trainer, Xte, yte = _fit_tiny_trainer()
        path = os.path.join(os.path.dirname(__file__), "_tmp_model.joblib")
        try:
            trainer.save(path)
            loaded = Trainer.load(path)
            pred_orig = trainer.predict(Xte)
            pred_load = loaded.predict(Xte)
            self.assertTrue((pred_orig == pred_load).all())
        finally:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main()
