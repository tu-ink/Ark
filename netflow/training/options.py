# -*- coding: utf-8 -*-
"""训练参数与命令行解析。

``TrainOptions`` 是一个纯数据类，既可以由命令行构造，也可以由
:func:`netflow.training.trainer.bootstrap_model` 直接构造。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..model import DEFAULT_MODEL_PATH

@dataclass
class TrainOptions:
    """一次训练的全部参数（由命令行或 :func:`bootstrap_model` 构造）。"""

    # 数据来源
    csv: Optional[List[str]] = None
    synthetic: bool = False
    synthetic_hours: float = 1.0
    synthetic_flows_per_sec: float = 60.0
    synthetic_out: Optional[str] = None
    synthetic_seed: int = 42
    # 特征构建
    window: float = 5.0
    chunksize: int = 200000
    max_rows: Optional[int] = None
    clip_quantile: Optional[float] = None
    keep_csv: Optional[str] = None
    # 模型参数
    out: str = DEFAULT_MODEL_PATH
    n_estimators: int = 200
    contamination: float = 0.01
    max_samples: object = "auto"
    random_state: int = 42
    n_jobs: int = 1
    threshold: object = "auto"
    scale: bool = False
    log_level: str = "INFO"
    extra: Dict[str, object] = field(default_factory=dict, repr=False)


# ---------------------------------------------------------------------- #
# 命令行
# ---------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """构造训练脚本的命令行解析器。"""
    parser = argparse.ArgumentParser(
        prog="netflow.train_model",
        description="使用 CIC-IDS2017 正常流量训练 Isolation Forest 模型",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("示例:\n"
                "  python -m netflow.train_model --csv data/MachineLearningCVE/*.csv\n"
                "  python -m netflow.train_model --synthetic --synthetic-hours 1\n"),
    )
    src = parser.add_argument_group("数据来源（二选一）")
    src.add_argument("--csv", nargs="+", default=None,
                     help="一个或多个 CIC-IDS2017 CSV 路径，支持通配符")
    src.add_argument("--synthetic", action="store_true",
                     help="无数据集时生成合成的 BENIGN 流量并据此训练（仅用于打通流程）")
    src.add_argument("--synthetic-hours", type=float, default=1.0,
                     help="合成数据的时间跨度（小时），默认 1")
    src.add_argument("--synthetic-flows-per-sec", type=float, default=60.0,
                     help="合成数据的平均流速率（flow/s），默认 60")
    src.add_argument("--synthetic-out", default=None,
                     help="把合成数据同时保存为 CSV（便于检查列格式）")
    src.add_argument("--synthetic-seed", type=int, default=42, help="合成数据随机种子")

    feat = parser.add_argument_group("特征构建")
    feat.add_argument("--window", type=float, default=5.0,
                      help="窗口聚合长度（秒），必须与实时监测的 -w/--window 一致，默认 5")
    feat.add_argument("--chunksize", type=int, default=200000,
                      help="分块读取 CSV 的行数，默认 20 万行")
    feat.add_argument("--max-rows", type=int, default=None,
                      help="最多读取多少行 BENIGN 数据（用于快速试跑）")
    feat.add_argument("--clip-quantile", type=float, default=None,
                      help="如 0.999，则把每个特征裁剪到该分位数，抑制极端值影响")
    feat.add_argument("--keep-csv", default=None,
                      help="把构建好的特征矩阵保存为 CSV，便于检查与论文作图")

    mdl = parser.add_argument_group("模型参数")
    mdl.add_argument("--out", default=DEFAULT_MODEL_PATH,
                     help="模型输出路径，默认 %s" % DEFAULT_MODEL_PATH)
    mdl.add_argument("--n-estimators", type=int, default=200, help="树的数量，默认 200")
    mdl.add_argument("--contamination", type=float, default=0.01,
                     help="预期异常比例，默认 0.01")
    mdl.add_argument("--max-samples", default="auto",
                     help="每棵树的采样数，默认 auto（min(256, n_samples)）")
    mdl.add_argument("--random-state", type=int, default=42, help="随机种子，默认 42")
    mdl.add_argument("--n-jobs", type=int, default=1,
                     help="训练并行度，默认 1（单进程）。本项目训练集通常只有几千个窗口，"
                          "单进程已足够快；-1 表示用满所有 CPU，但在禁止创建命名管道的"
                          "受限环境（容器/沙箱）中会失败")
    mdl.add_argument("--threshold", default="auto",
                     help="判定阈值。'auto'（默认）采用 sklearn 自带校准点："
                          "decision_function 的零点正好是训练分数的 contamination 分位数，"
                          "含义是「约 contamination 比例的正常窗口会被判异常」；"
                          "也可直接给数值，如 -0.1 表示更保守的阈值")
    mdl.add_argument("--scale", action="store_true",
                     help="同时保存 StandardScaler。注意：孤立森林对单特征的单调变换不敏感，"
                          "标准化不改变树结构与分数，默认关闭")
    mdl.add_argument("--log-level", default="INFO",
                     choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="日志级别")
    return parser


def options_from_argv(argv: Optional[Sequence[str]] = None) -> TrainOptions:
    """解析命令行并转换为 :class:`TrainOptions`。"""
    ns = build_parser().parse_args(argv)
    return TrainOptions(
        csv=ns.csv, synthetic=ns.synthetic,
        synthetic_hours=ns.synthetic_hours,
        synthetic_flows_per_sec=ns.synthetic_flows_per_sec,
        synthetic_out=ns.synthetic_out, synthetic_seed=ns.synthetic_seed,
        window=ns.window, chunksize=ns.chunksize, max_rows=ns.max_rows,
        clip_quantile=ns.clip_quantile, keep_csv=ns.keep_csv,
        out=ns.out, n_estimators=ns.n_estimators, contamination=ns.contamination,
        max_samples=ns.max_samples, random_state=ns.random_state, n_jobs=ns.n_jobs,
        threshold=ns.threshold, scale=ns.scale, log_level=ns.log_level,
    )
