# -*- coding: utf-8 -*-
"""特征构建：窗口聚合模式与逐流近似模式。

实时系统输出的是「窗口级」特征，而 CIC-IDS2017 的 CSV 是「流级」特征。
两种口径直接混用会造成严重域偏移，因此本模块提供两条路径：

* :func:`build_feature_frame_window_mode` —— 优先路径，先按窗口聚合流再算特征；
* :func:`build_feature_frame_flow_mode` —— 退化路径，把每条流当作一个窗口。

两条路径最终都输出与 :data:`netflow.stats.FEATURE_NAMES` 完全一致的 10 列。
"""

from __future__ import annotations

import logging
from typing import List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

from ..stats import FEATURE_NAMES
from .dataset import _parse_timestamps, _window_keys, iter_benign_chunks
from .schema import (
    COL_BWD_BYTES,
    COL_BWD_PKTS,
    COL_FLOW_BYTES_S,
    COL_FLOW_PKTS_S,
    COL_FWD_BYTES,
    COL_FWD_PKTS,
    COL_PROTOCOL,
    COL_SRC_IP,
    COL_SYN,
    COL_TIMESTAMP,
    REQUIRED_FLOW_COLUMNS,
    REQUIRED_WINDOW_COLUMNS,
)

logger = logging.getLogger(__name__)

# 特征构建
# ---------------------------------------------------------------------- #
def _ratio(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """安全除法：分母为 0 时返回 0。"""
    return (numerator / denominator.replace(0, np.nan)).fillna(0.0)


def build_feature_frame_window_mode(df: pd.DataFrame, window_seconds: float) -> pd.DataFrame:
    """**窗口聚合模式**：把流按固定时间窗口聚合为与实时层一致的特征。

    要求 ``df`` 含 ``Timestamp``、``Source IP``、``Protocol`` 等列。
    每次调用会丢弃最后一个可能不完整的窗口（由调用方负责跨块拼接）。
    """
    df = df.copy()
    df["_ts"] = _parse_timestamps(df[COL_TIMESTAMP])
    df = df.dropna(subset=["_ts"])
    if df.empty:
        return pd.DataFrame(columns=list(FEATURE_NAMES))

    df["_fwd"] = df.get(COL_FWD_PKTS, 0).fillna(0).clip(lower=0)
    df["_bwd"] = df.get(COL_BWD_PKTS, 0).fillna(0).clip(lower=0)
    df["_fbytes"] = df.get(COL_FWD_BYTES, 0).fillna(0).clip(lower=0)
    df["_bbytes"] = df.get(COL_BWD_BYTES, 0).fillna(0).clip(lower=0)
    df["_pkts"] = df["_fwd"] + df["_bwd"]
    df["_bytes"] = df["_fbytes"] + df["_bbytes"]
    df["_proto"] = df.get(COL_PROTOCOL, 0).fillna(0).astype("int64")
    df["_tcp"] = np.where(df["_proto"] == 6, df["_pkts"], 0.0)
    df["_udp"] = np.where(df["_proto"] == 17, df["_pkts"], 0.0)
    df["_icmp"] = np.where(df["_proto"] == 1, df["_pkts"], 0.0)
    df["_syn"] = df[COL_SYN].fillna(0).clip(lower=0) if COL_SYN in df.columns else 0.0

    # 以 epoch 秒对齐的固定窗口分组（同一数据集内分组口径一致）
    df["_wkey"] = _window_keys(df["_ts"], window_seconds)

    grouped = df.groupby("_wkey", sort=True)
    out = pd.DataFrame(index=grouped.size().index)
    out["packet_count"] = grouped["_pkts"].sum()
    out["byte_count"] = grouped["_bytes"].sum()
    out["tcp_ratio"] = _ratio(grouped["_tcp"].sum(), out["packet_count"])
    out["udp_ratio"] = _ratio(grouped["_udp"].sum(), out["packet_count"])
    out["icmp_ratio"] = _ratio(grouped["_icmp"].sum(), out["packet_count"])
    if COL_SRC_IP in df.columns:
        out["unique_src_ips"] = grouped[COL_SRC_IP].nunique()
    else:
        out["unique_src_ips"] = grouped.size()  # 无源 IP 时以窗口内流数近似
    out["syn_ratio"] = _ratio(grouped["_syn"].sum(), out["packet_count"])
    out["avg_pkt_len"] = _ratio(out["byte_count"], out["packet_count"])
    out["pps"] = out["packet_count"] / float(window_seconds)
    out["bps"] = out["byte_count"] / float(window_seconds)

    return out.reset_index(drop=True)[list(FEATURE_NAMES)]


def build_feature_frame_flow_mode(df: pd.DataFrame) -> pd.DataFrame:
    """**逐流近似模式**：把每条流当作一个窗口，映射到 10 维特征。

    近似之处（务必在论文中说明）：

    * ``tcp/udp/icmp_ratio`` 由单条流的 Protocol 二值化（0 或 1），
      而非窗口内多协议的加权占比；
    * ``unique_src_ips`` 恒为 1（每条流只有一个源 IP），该维**不携带信息**；
    * ``pps`` / ``bps`` 直接取 ``Flow Packets/s``、``Flow Bytes/s``，
      而不是「窗口内包数 ÷ 窗口长度」。
    """
    out = pd.DataFrame(index=df.index)
    zero = pd.Series(0.0, index=df.index)
    fwd = df.get(COL_FWD_PKTS, zero).fillna(0).clip(lower=0)
    bwd = df.get(COL_BWD_PKTS, zero).fillna(0).clip(lower=0)
    fbytes = df.get(COL_FWD_BYTES, zero).fillna(0).clip(lower=0)
    bbytes = df.get(COL_BWD_BYTES, zero).fillna(0).clip(lower=0)

    out["packet_count"] = fwd + bwd
    out["byte_count"] = fbytes + bbytes
    proto = df.get(COL_PROTOCOL, zero).fillna(0).astype("int64")
    out["tcp_ratio"] = (proto == 6).astype(float)
    out["udp_ratio"] = (proto == 17).astype(float)
    out["icmp_ratio"] = (proto == 1).astype(float)
    out["unique_src_ips"] = 1.0
    if COL_SYN in df.columns:
        out["syn_ratio"] = _ratio(df[COL_SYN].fillna(0).clip(lower=0), out["packet_count"])
    else:
        out["syn_ratio"] = 0.0
    out["avg_pkt_len"] = _ratio(out["byte_count"], out["packet_count"])
    out["pps"] = (df[COL_FLOW_PKTS_S].fillna(0).clip(lower=0)
                  if COL_FLOW_PKTS_S in df.columns else out["packet_count"])
    out["bps"] = (df[COL_FLOW_BYTES_S].fillna(0).clip(lower=0)
                  if COL_FLOW_BYTES_S in df.columns else out["byte_count"])
    return out[list(FEATURE_NAMES)].reset_index(drop=True)


def build_feature_matrix(
    paths: Sequence[str],
    window_seconds: float,
    chunksize: int,
    max_rows: Optional[int] = None,
) -> Tuple[pd.DataFrame, str]:
    """读取全部 BENIGN 数据并构建特征矩阵。

    Returns
    -------
    (features, mode)
        ``mode`` 为 ``"window"`` 或 ``"flow"``，用于日志与论文说明。
    """
    mode: Optional[str] = None
    frames: List[pd.DataFrame] = []
    total_rows = 0
    window_carry: Optional[pd.DataFrame] = None

    for chunk in iter_benign_chunks(paths, chunksize, max_rows):
        total_rows += len(chunk)
        if mode is None:
            missing = [c for c in REQUIRED_FLOW_COLUMNS if c not in chunk.columns]
            if missing:
                raise ValueError(
                    "CSV 缺少必要的列: {0}。请确认使用的是 CIC-IDS2017 的 "
                    "MachineLearningCVE CSV 文件。".format(", ".join(missing)))
            if all(c in chunk.columns for c in REQUIRED_WINDOW_COLUMNS):
                # 用前若干行探测时间戳是否可解析，能解析才走窗口聚合模式
                probe = _parse_timestamps(chunk[COL_TIMESTAMP].head(1000))
                mode = "window" if probe.notna().mean() > 0.5 else "flow"
            else:
                mode = "flow"
            logger.info("特征构建模式: %s", "窗口聚合" if mode == "window" else "逐流近似")

        if mode == "window":
            part = chunk
            if window_carry is not None and not window_carry.empty:
                part = pd.concat([window_carry, part], ignore_index=True, sort=False)
            features = build_feature_frame_window_mode(part, window_seconds)

            # 块边界处的最后一个窗口可能不完整：把它的原始行留到下一块一起聚合，
            # 同时从本块结果中丢掉这个尚未闭合的窗口。
            ts = _parse_timestamps(part[COL_TIMESTAMP])
            valid_idx = ts.index[ts.notna()]
            if len(valid_idx):
                keys = _window_keys(ts.loc[valid_idx], window_seconds)
                last_key = int(keys.max())
                carry_mask = pd.Series(False, index=part.index)
                carry_mask.loc[valid_idx] = keys == last_key
                window_carry = part.loc[carry_mask]
                features = features.iloc[:-1] if len(features) > 1 else features.iloc[0:0]
            else:
                window_carry = None
            if len(features):
                frames.append(features)
        else:
            frames.append(build_feature_frame_flow_mode(chunk))

    if mode == "window" and window_carry is not None and not window_carry.empty:
        frames.append(build_feature_frame_window_mode(window_carry, window_seconds))

    if not frames:
        raise ValueError("未能从输入数据中构建出任何特征，请检查 CSV 内容与 Label 列")

    matrix = pd.concat(frames, ignore_index=True)
    matrix = matrix.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    logger.info("共读取 BENIGN 行数: %d，构建特征样本: %d 条", total_rows, len(matrix))
    return matrix, mode
