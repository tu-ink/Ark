# -*- coding: utf-8 -*-
"""训练脚本的命令行入口。

用法::

    python -m netflow.training --csv data/MachineLearningCVE/*.csv
    python -m netflow.training --synthetic --out model.joblib

`python -m netflow.train_model` 依然可用（向后兼容薄壳）。
"""

from __future__ import annotations

import logging
from typing import Optional, Sequence

from .options import options_from_argv
from .trainer import train

logger = logging.getLogger(__name__)

__all__ = ["main"]

def main(argv: Optional[Sequence[str]] = None) -> int:
    """训练脚本入口。"""
    import logging as _logging

    options = options_from_argv(argv)
    _logging.basicConfig(
        level=getattr(_logging, str(options.log_level).upper(), _logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        return train(options)
    except KeyboardInterrupt:
        logger.warning("训练被用户中断")
        return 130
    except Exception:
        logger.exception("训练失败")
        return 1
