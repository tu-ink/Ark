# -*- coding: utf-8 -*-
"""存储层单元测试：建表、写入、查询、导出。"""

from __future__ import annotations

import os
import shutil
import sys
import unittest

from tests import helpers
from tests.helpers import make_temp_dir, make_window

from netflow.database import TrafficDB
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
# 存储层
# ====================================================================== #
class TestDatabase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = make_temp_dir("db-")
        self.db_path = os.path.join(self.tmp, "test.db")
        self.db = TrafficDB(self.db_path)

    def tearDown(self) -> None:
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_insert_and_query_roundtrip(self) -> None:
        window = make_window(1200)
        stats_id, alert_id = self.db.insert_window(
            window, anomaly_score=-0.25, is_anomaly=True, threshold=-0.1, message="测试告警")
        self.assertGreater(stats_id, 0)
        self.assertIsNotNone(alert_id)

        rows = self.db.query_stats(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["packet_count"], window.packet_count)
        self.assertEqual(rows[0]["is_anomaly"], 1)

        alerts = self.db.query_alerts(limit=5)
        self.assertEqual(len(alerts), 1)
        self.assertAlmostEqual(alerts[0]["anomaly_score"], -0.25)
        self.assertIn("packet_count", alerts[0]["feature_snapshot"])

    def test_normal_window_creates_no_alert(self) -> None:
        _sid, alert_id = self.db.insert_window(make_window(), anomaly_score=0.2,
                                               is_anomaly=False)
        self.assertIsNone(alert_id)
        self.assertEqual(self.db.summary()["alerts"], 0)
        self.assertEqual(self.db.summary()["anomaly_windows"], 0)

    def test_summary_and_export(self) -> None:
        self.db.insert_window(make_window(100), anomaly_score=0.1)
        self.db.insert_window(make_window(200), anomaly_score=-0.3, is_anomaly=True,
                              threshold=-0.1)
        summary = self.db.summary()
        self.assertEqual(summary["windows"], 2)
        self.assertEqual(summary["anomaly_windows"], 1)
        self.assertEqual(summary["total_packets"], 300)

        csv_path = os.path.join(self.tmp, "stats.csv")
        self.assertEqual(self.db.export_stats_csv(csv_path), 2)
        self.assertTrue(os.path.isfile(csv_path))

    def test_feature_matrix_shape(self) -> None:
        self.db.insert_window(make_window(), anomaly_score=0.0)
        names, matrix = self.db.fetch_feature_matrix(limit=10)
        self.assertEqual(list(names), list(FEATURE_NAMES))
        self.assertEqual(len(matrix), 1)
        self.assertEqual(len(matrix[0]), len(FEATURE_NAMES))


if __name__ == "__main__":
    unittest.main(verbosity=2)
