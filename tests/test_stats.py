# -*- coding: utf-8 -*-
"""统计层单元测试：窗口聚合、特征向量、空窗口处理。"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime

from tests import helpers
from tests.helpers import SCAPY_AVAILABLE, StubPacket

from netflow.stats import FEATURE_NAMES, StatsCollector, _WindowAccumulator

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

def setUpModule() -> None:
    helpers.silence_logging()

def tearDownModule() -> None:
    helpers.restore_logging()
    helpers.cleanup()
# ====================================================================== #
# 统计层
# ====================================================================== #
@unittest.skipUnless(SCAPY_AVAILABLE, "需要 Scapy 的层类型")
class TestStats(unittest.TestCase):
    def test_feature_names_order(self) -> None:
        self.assertEqual(len(FEATURE_NAMES), 10)
        self.assertEqual(FEATURE_NAMES[0], "packet_count")
        self.assertEqual(FEATURE_NAMES[-1], "bps")
        self.assertEqual(len(set(FEATURE_NAMES)), 10)

    def test_window_aggregation(self) -> None:
        acc = _WindowAccumulator(top_n=5)
        acc.add(StubPacket(100, "10.0.0.1", "tcp", 80, syn=True))
        acc.add(StubPacket(200, "10.0.0.2", "tcp", 443, syn=False))
        acc.add(StubPacket(300, "10.0.0.1", "udp", 53))
        acc.add(StubPacket(400, "10.0.0.3", "icmp"))

        now = datetime.now()
        stats = acc.finalize(now, now, 4.0)

        self.assertEqual(stats.packet_count, 4)
        self.assertEqual(stats.byte_count, 1000)
        self.assertEqual(stats.tcp_count, 2)
        self.assertEqual(stats.udp_count, 1)
        self.assertEqual(stats.icmp_count, 1)
        self.assertEqual(stats.syn_count, 1)
        self.assertEqual(stats.unique_src_ips, 3)
        self.assertAlmostEqual(stats.tcp_ratio, 0.5)
        self.assertAlmostEqual(stats.syn_ratio, 0.25)
        self.assertAlmostEqual(stats.avg_pkt_len, 250.0)
        self.assertAlmostEqual(stats.pps, 1.0)
        self.assertAlmostEqual(stats.bps, 250.0)

    def test_feature_vector_matches_names(self) -> None:
        acc = _WindowAccumulator()
        acc.add(StubPacket(120))
        now = datetime.now()
        stats = acc.finalize(now, now, 5.0)
        vector = stats.to_vector()
        self.assertEqual(len(vector), len(FEATURE_NAMES))
        self.assertEqual(stats.to_dict()["packet_count"], float(stats.packet_count))
        self.assertIn("packet_count", stats.to_json())

    def test_empty_window_is_skipped_by_default(self) -> None:
        collector = StatsCollector(packet_queue=__import__("queue").Queue(),
                                   window_seconds=1.0, record_empty=False)
        seen = []
        collector._emit(_WindowAccumulator(), datetime.now(), 1.0, seen.append)
        self.assertEqual(seen, [], "空窗口默认不应上报")
        self.assertEqual(collector.window_count, 0)

    def test_empty_window_can_be_recorded(self) -> None:
        collector = StatsCollector(packet_queue=__import__("queue").Queue(),
                                   window_seconds=1.0, record_empty=True)
        seen = []
        collector._emit(_WindowAccumulator(), datetime.now(), 1.0, seen.append)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].packet_count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
