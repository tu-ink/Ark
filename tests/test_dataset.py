import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pandas as pd  # noqa: E402

from arkids.config import KDD_FEATURES, LABEL_COL, CLASSES, to_family  # noqa: E402
from arkids.dataset import generate_demo_flows, load_kdd_file  # noqa: E402


class TestDataset(unittest.TestCase):
    def test_demo_flows_schema_and_coverage(self):
        df = generate_demo_flows(n=2000, seed=1)
        self.assertEqual(list(df.columns), KDD_FEATURES + [LABEL_COL])
        self.assertEqual(len(df), 2000)
        counts = df[LABEL_COL].value_counts()
        # 五大类(含攻击家族)均应出现
        self.assertTrue(set(counts.index) == set(CLASSES), counts.to_dict())

    def test_family_mapping(self):
        self.assertEqual(to_family("normal"), "normal")
        self.assertEqual(to_family("Neptune"), "dos")
        self.assertEqual(to_family("satan"), "probe")
        self.assertEqual(to_family("guess_passwd"), "r2l")
        self.assertEqual(to_family("rootkit"), "u2r")
        self.assertEqual(to_family("unknown_attack"), "other")

    def test_load_kdd_file(self):
        # 构造一个极小的 NSL-KDD 风格临时文件(空白分隔、无表头)
        demo = generate_demo_flows(n=20, seed=3)
        path = os.path.join(os.path.dirname(__file__), "_tmp_kdd.txt")
        demo.iloc[0, -1] = "neptune"  # 保留一个原始攻击名格式
        demo.to_csv(path, sep=" ", header=False, index=False)
        try:
            loaded = load_kdd_file(path)
            self.assertEqual(loaded.shape[1], 42)
            self.assertIn("normal", set(loaded[LABEL_COL]))
            self.assertIn("dos", set(loaded[LABEL_COL]))
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
