# -*- coding: utf-8 -*-
"""训练层：把 CIC-IDS2017 / 合成流量训练成 Isolation Forest 模型。

本包由原 ``netflow/train_model.py`` 拆分而来，按职责划分为：

===================  ================================================
模块                  职责
===================  ================================================
``schema``           CIC-IDS2017 的列名常量与必需列定义
``dataset``          CSV 读取、表头清洗、时间戳解析、BENIGN 分块迭代
``features``         窗口聚合 / 逐流近似两种特征构建模式
``synthetic``        合成正常流量生成（无数据集时的兜底与演示数据源）
``options``          训练参数与命令行解析
``trainer``          训练主流程与开箱即用的引导模型训练
===================  ================================================

对外只需要使用本包的导出：去 ``netflow/train_model.py`` 只是一层向后兼容的薄壳。
"""

from __future__ import annotations

from .options import TrainOptions, build_parser, options_from_argv
from .dataset import iter_benign_chunks
from .features import (
    build_feature_frame_flow_mode,
    build_feature_frame_window_mode,
    build_feature_matrix,
)
from .synthetic import generate_synthetic_benign
from .trainer import bootstrap_model, train
from .cli import main

__all__ = [
    "TrainOptions", "build_parser", "options_from_argv", "iter_benign_chunks",
    "build_feature_frame_flow_mode", "build_feature_frame_window_mode",
    "build_feature_matrix", "generate_synthetic_benign",
    "bootstrap_model", "train", "main",
]
