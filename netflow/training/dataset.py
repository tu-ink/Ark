# -*- coding: utf-8 -*-
"""数据集读取：CSV 分块、表头清洗、时间戳解析、BENIGN 过滤。

注意 :func:`_clean_numeric` 会处理 CIC-IDS2017 里出现的字面量 ``Infinity``
（``Flow Duration`` 为 0 时出现），统一转成 NaN，由上层填 0。
"""

from __future__ import annotations

import glob
import logging
import os
from typing import Iterator, List, Optional, Sequence

import numpy as np
import pandas as pd

from .schema import (
    COL_LABEL,
    NUMERIC_COLUMNS,
    _TIMESTAMP_FORMATS,
)

logger = logging.getLogger(__name__)

# 数据读取
# ---------------------------------------------------------------------- #
def _resolve_csv_paths(patterns: Sequence[str]) -> List[str]:
    """展开通配符并去重，返回真实存在的 CSV 路径列表。"""
    paths: List[str] = []
    for pattern in patterns:
        matched = sorted(glob.glob(pattern))
        if not matched and os.path.isfile(pattern):
            matched = [pattern]
        if not matched:
            logger.warning("未匹配到文件: %s", pattern)
        for path in matched:
            if path not in paths:
                paths.append(path)
    return paths


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """清理 CIC-IDS2017 表头中常见的前后空格。"""
    df.columns = [str(c).strip() for c in df.columns]
    return df


def _parse_timestamps(series: pd.Series) -> pd.Series:
    """把时间戳列解析为 datetime，兼容多种常见格式。"""
    if pd.api.types.is_numeric_dtype(series):
        values = pd.to_numeric(series, errors="coerce")
        unit = "ms" if values.dropna().median() > 1e11 else "s"
        return pd.to_datetime(values, unit=unit, errors="coerce")

    text = series.astype(str).str.strip()
    for fmt in _TIMESTAMP_FORMATS:
        parsed = pd.to_datetime(text, format=fmt, errors="coerce")
        if parsed.notna().mean() > 0.9:
            logger.info("时间戳格式识别为: %s", fmt)
            return parsed
    try:  # pandas >= 2.0 支持混合格式推断
        parsed = pd.to_datetime(text, format="mixed", errors="coerce")
        if parsed.notna().mean() > 0.5:
            logger.info("时间戳使用混合格式推断")
            return parsed
    except (TypeError, ValueError):
        pass
    logger.warning("时间戳解析成功率低，无法按窗口聚合，将退化为逐流近似模式")
    return pd.Series(pd.NaT, index=series.index)


def _clean_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """把数值列统一为 float，处理 CIC-IDS2017 中常见的 Infinity / 空值。

    ``Flow Bytes/s``、``Flow Packets/s`` 在 ``Flow Duration`` 为 0 时会出现
    字面量 ``Infinity``，先转数值再把 ±inf 统一置为 NaN，后续由
    :func:`build_feature_matrix` 填 0。
    """
    for col in NUMERIC_COLUMNS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            df[col] = df[col].replace([np.inf, -np.inf], np.nan)
    return df


def _window_keys(ts: pd.Series, window_seconds: float) -> np.ndarray:
    """把 datetime 序列转换为 epoch 秒对齐的窗口编号（int64 数组）。

    使用 ``to_numpy(dtype="datetime64[ns]")`` 而不是 ``astype("int64")``，
    以兼容 pandas 1.x 与 2.x 的不同行为。
    """
    nanos = ts.to_numpy(dtype="datetime64[ns]").astype("int64")
    return np.floor(nanos / 1e9 / float(window_seconds)).astype("int64")


def iter_benign_chunks(
    paths: Sequence[str],
    chunksize: int,
    max_rows: Optional[int] = None,
) -> Iterator[pd.DataFrame]:
    """按块迭代读取 CSV，只保留 ``Label == BENIGN`` 的行。"""
    remaining = max_rows
    for path in paths:
        logger.info("读取 %s ...", path)
        try:
            reader = pd.read_csv(path, chunksize=chunksize, low_memory=False,
                                 skipinitialspace=True)
        except Exception:
            logger.exception("读取 %s 失败，已跳过", path)
            continue
        for chunk in reader:
            chunk = _normalize_columns(chunk)
            if COL_LABEL not in chunk.columns:
                logger.warning("%s 缺少 %s 列，已跳过", os.path.basename(path), COL_LABEL)
                break
            mask = chunk[COL_LABEL].astype(str).str.strip().str.upper() == "BENIGN"
            benign = chunk.loc[mask].copy()
            if benign.empty:
                continue
            benign = _clean_numeric(benign)
            if remaining is not None:
                if remaining <= 0:
                    return
                if len(benign) > remaining:
                    benign = benign.iloc[:remaining]
                remaining -= len(benign)
            yield benign
