import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pandas as pd  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from arkids.config import LABEL_COL  # noqa: E402
from arkids.dataset import generate_demo_flows  # noqa: E402
from arkids.defense import DefenseEngine, DefenseEvent  # noqa: E402
from arkids.detector import FlowDetector  # noqa: E402
from arkids.models import Trainer  # noqa: E402
from arkids.simulate import run_simulation  # noqa: E402

from _util import cleanup_tmp, make_tmp


def _tiny_detector():
    df = generate_demo_flows(n=600, seed=9)
    X = df.drop(columns=[LABEL_COL])
    y = df[LABEL_COL]
    Xtr, _, ytr, _ = train_test_split(X, y, test_size=0.3, stratify=y, random_state=0)
    trainer = Trainer(algo="rf", random_state=0)
    trainer.fit(Xtr, ytr)
    return FlowDetector(trainer, threshold=0.5)


class TestDetector(unittest.TestCase):
    def test_detect_one_shape(self):
        det = _tiny_detector()
        df = generate_demo_flows(n=1, seed=1)
        row = df.drop(columns=[LABEL_COL]).iloc[0].to_dict()
        out = det.detect_one(row)
        self.assertIn(out.verdict, {"normal", "dos", "probe", "r2l", "u2r"})
        self.assertTrue(0.0 <= out.score <= 1.0)
        self.assertEqual(out.attack, out.verdict != "normal")


class TestDefenseEngine(unittest.TestCase):
    def tearDown(self):
        cleanup_tmp("defense")

    def test_escalation_to_block_after_hits(self):
        td = make_tmp("defense")
        eng = DefenseEngine(state_dir=td, block_hits=3, window_sec=60, dry_run=True)
        base = time.time()
        for i in range(3):
            eng.handle(DefenseEvent(
                src_ip="1.2.3.4", verdict="dos", score=0.99,
                attack=True, ts=base + i * 5,
            ))
        self.assertIn("1.2.3.4", eng.blocked_ips())
        self.assertEqual(eng.alert_count(), 3)

    def test_window_prune_prevents_escalation(self):
        td = make_tmp("defense")
        eng = DefenseEngine(state_dir=td, block_hits=3, window_sec=10, dry_run=True)
        base = time.time() - 100  # 所有告警早已超出窗口
        for _ in range(5):
            eng.handle(DefenseEvent(
                src_ip="5.6.7.8", verdict="probe", score=0.9, attack=True, ts=base,
            ))
        self.assertNotIn("5.6.7.8", eng.blocked_ips())


class TestSimulation(unittest.TestCase):
    def tearDown(self):
        cleanup_tmp("simulation")

    def test_run_simulation_end_to_end(self):
        td = make_tmp("simulation")
        data_path = os.path.join(td, "demo.csv")
        model_path = os.path.join(td, "model.joblib")
        df = generate_demo_flows(n=400, seed=3)
        df.to_csv(data_path, index=False)
        X, y = df.drop(columns=[LABEL_COL]), df[LABEL_COL]
        Xtr, _, ytr, _ = train_test_split(X, y, test_size=0.3, stratify=y, random_state=0)
        Trainer(algo="rf", random_state=0).fit(Xtr, ytr).save(model_path)

        summary = run_simulation(
            data_path=data_path, model_path=model_path, limit=200,
            block_hits=3, attacker_pool=2, state_dir=td,
        )
        self.assertEqual(summary["flows"], 200)
        self.assertGreaterEqual(summary["metrics"]["accuracy"], 0.7)
        self.assertGreaterEqual(summary["defense"]["blocked"], 0)


if __name__ == "__main__":
    unittest.main()
