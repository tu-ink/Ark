# -*- coding: utf-8 -*-
"""配置层单元测试：三级合并优先级、布尔开关、参数校验。"""

from __future__ import annotations

import os
import shutil
import sys
import unittest

from tests import helpers
from tests.helpers import make_temp_dir

from netflow.config import AppConfig

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

def setUpModule() -> None:
    helpers.silence_logging()

def tearDownModule() -> None:
    helpers.restore_logging()
    helpers.cleanup()
# ====================================================================== #
# 配置层
# ====================================================================== #
class TestConfig(unittest.TestCase):
    def test_priority_cli_over_file_over_default(self) -> None:
        tmp = make_temp_dir("config-")
        try:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"window": 9.0, "top_n": 7, "log_level": "WARNING"}')

            from_file = AppConfig.from_sources(["--config", path])
            self.assertEqual(from_file.window, 9.0)
            self.assertEqual(from_file.top_n, 7)
            self.assertEqual(from_file.log_level, "WARNING")
            self.assertEqual(from_file.db, AppConfig().db)  # 未指定则用默认值

            overridden = AppConfig.from_sources(["--config", path, "-w", "2.5"])
            self.assertEqual(overridden.window, 2.5)
            self.assertEqual(overridden.top_n, 7)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_boolean_flags(self) -> None:
        self.assertTrue(AppConfig.from_sources([]).promisc)
        self.assertFalse(AppConfig.from_sources(["--no-promisc"]).promisc)
        self.assertTrue(AppConfig.from_sources([]).auto_train)
        self.assertFalse(AppConfig.from_sources(["--no-auto-train"]).auto_train)

    def test_validation_rejects_bad_values(self) -> None:
        with self.assertRaises(ValueError):
            AppConfig.from_sources(["-w", "0"])
        with self.assertRaises(ValueError):
            AppConfig.from_sources(["--queue-size", "-5"])
        with self.assertRaises(ValueError):
            AppConfig.from_sources(["--ui", "plain", "--refresh", "0"])

    def test_missing_config_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            AppConfig.from_sources(["--config", "no-such-file.json"])

    def test_describe_returns_pairs(self) -> None:
        rows = AppConfig.from_sources([]).describe()
        self.assertTrue(rows)
        for label, value in rows:
            self.assertIsInstance(label, str)
            self.assertIsInstance(value, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
