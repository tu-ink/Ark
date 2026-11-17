# -*- coding: utf-8 -*-
"""向后兼容层：旧代码里的 ``from .train_model import ...`` 仍然可用。

训练逻辑已拆分到 :mod:`netflow.training` 包，本模块只做转发，
避免外部调用点（以及 ``python -m netflow.train_model``）失效。
"""

from __future__ import annotations

import sys

from .training import (                                    # noqa: F401
    TrainOptions,
    bootstrap_model,
    build_feature_frame_flow_mode,
    build_feature_frame_window_mode,
    build_feature_matrix,
    build_parser,
    generate_synthetic_benign,
    iter_benign_chunks,
    main,
    options_from_argv,
    train,
)

__all__ = [
    "TrainOptions", "build_parser", "options_from_argv", "iter_benign_chunks",
    "build_feature_frame_flow_mode", "build_feature_frame_window_mode",
    "build_feature_matrix", "generate_synthetic_benign",
    "bootstrap_model", "train", "main",
]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
