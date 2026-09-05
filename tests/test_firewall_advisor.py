import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from arkids.advisor import AIAdvisor, HeuristicAdvisor  # noqa: E402
from arkids.firewall import FirewallRule, FirewallStore  # noqa: E402

from _util import cleanup_tmp, make_tmp  # noqa: E402


class TestFirewallStore(unittest.TestCase):
    def tearDown(self):
        cleanup_tmp("fw")

    def test_add_query_export_delete(self):
        td = make_tmp("fw")
        store = FirewallStore(state_dir=td)
        r1 = store.add(FirewallRule(src_ip="203.0.113.66", action="deny",
                                    protocol="tcp", dport="80", note="测试规则"))
        self.assertTrue(store.is_src_blocked("203.0.113.66"))
        self.assertEqual(len(store.rules()), 1)

        # 重复 deny 同 IP -> 幂等
        store.add(FirewallRule(src_ip="203.0.113.66", action="deny"))
        self.assertEqual(len(store.rules()), 1)

        # 停用后不再视为封禁
        store.update(r1.id, enabled=False)
        self.assertFalse(store.is_src_blocked("203.0.113.66"))

        # 删除
        self.assertTrue(store.delete(r1.id))
        self.assertEqual(store.rules(), [])

    def test_export_script_contains_rule(self):
        td = make_tmp("fw")
        store = FirewallStore(state_dir=td)
        store.add(FirewallRule(src_ip="203.0.113.77", action="deny",
                               protocol="any", note="auto"))
        text = store.script_text()
        self.assertIn("203.0.113.77", text)

    def test_reload_from_disk(self):
        td = make_tmp("fw")
        store = FirewallStore(state_dir=td)
        store.add(FirewallRule(src_ip="203.0.113.88", action="deny", note="持久"))
        store2 = FirewallStore(state_dir=td)
        self.assertTrue(store2.is_src_blocked("203.0.113.88"))


class TestAdvisor(unittest.TestCase):
    def _ctx(self, **over) -> dict:
        base = {
            "stats": {"flows": 1000, "alerts": 100, "blocks": 2, "tp": 90, "fp": 5,
                      "tn": 850, "fn": 55, "flows_window": 300,
                      "attacks_window": 200, "attack_rate": 0.66,
                      "blocked": 2, "active_srcs": 8},
            "events": [], "blocklist": ["203.0.113.10", "203.0.113.11"],
            "fw_rules": [], "threshold": 0.5,
        }
        base.update(over)
        return base

    def test_high_attack_rate_gives_critical(self):
        out = HeuristicAdvisor().suggest(self._ctx())
        levels = {s["level"] for s in out}
        self.assertIn("critical", levels)

    def test_fw_sync_warns_unmatched_blocks(self):
        # 封禁清单存在但防火墙规则为空 -> 同步提示
        out = HeuristicAdvisor().suggest(self._ctx())
        self.assertTrue(any("未同步" in s["title"] for s in out))

    def test_fp_high_suggests_threshold(self):
        ctx = self._ctx()
        ctx["stats"]["fp"] = 120
        ctx["stats"]["tp"] = 500
        ctx["stats"]["tn"] = 300
        ctx["stats"]["fn"] = 20
        ctx["stats"]["attack_rate"] = 0.1
        out = HeuristicAdvisor().suggest(ctx)
        self.assertTrue(any("误报率偏高" in s["title"] for s in out))

    def test_ai_advisor_disabled_when_key_blank(self):
        advisor = AIAdvisor(api_key="")   # 显式空串 = 关闭 LLM(不读取凭据库)
        self.assertFalse(advisor.llm_available)
        res = advisor.llm_advice(self._ctx())
        self.assertFalse(res["ok"])


if __name__ == "__main__":
    unittest.main()
