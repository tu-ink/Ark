import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pandas as pd  # noqa: E402

from arkids.dataset import generate_demo_flows  # noqa: E402
from arkids.features import FeaturePreparer  # noqa: E402


class TestFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = generate_demo_flows(n=600, seed=11)

    def test_fit_transform_dimensions_and_no_nan(self):
        prep = FeaturePreparer()
        X = prep.fit_transform(self.df.drop(columns=["label"]))
        self.assertEqual(X.shape[0], len(self.df))
        # 编码后维度应大于原始 41
        self.assertGreater(X.shape[1], 41)
        self.assertFalse(X.isna().any().any())

    def test_transform_single_row_consistent(self):
        prep = FeaturePreparer()
        prep.fit(self.df.drop(columns=["label"]))
        X1 = prep.transform(self.df.drop(columns=["label"]))
        X2 = prep.transform(self.df.drop(columns=["label"]).iloc[[0]])
        self.assertEqual(len(X2), 1)
        pd.testing.assert_series_equal(X2.iloc[0], X1.iloc[0])

    def test_unknown_category_tolerated(self):
        # One-Hot 需容忍训练时未出现的 service/flag 值
        prep = FeaturePreparer()
        prep.fit(self.df.drop(columns=["label"]))
        row = self.df.drop(columns=["label"]).iloc[[0]].copy()
        row["service"] = "brand_new_service"
        out = prep.transform(row)
        self.assertEqual(out.shape[0], 1)


if __name__ == "__main__":
    unittest.main()
