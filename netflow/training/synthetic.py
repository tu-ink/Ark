# -*- coding: utf-8 -*-
"""合成正常流量生成。

仅用于：① 拿不到真实数据集时打通训练链路；② 生成演示用样本 pcap 的来源分布。
**不能**用于论文中的检测效果论证。
"""

from __future__ import annotations

import logging
from datetime import datetime

import numpy as np
import pandas as pd

from .schema import (
    COL_BWD_BYTES,
    COL_BWD_LEN_MEAN,
    COL_BWD_PKTS,
    COL_DST_IP,
    COL_DST_PORT,
    COL_FLOW_BYTES_S,
    COL_FLOW_DURATION,
    COL_FLOW_PKTS_S,
    COL_FWD_BYTES,
    COL_FWD_LEN_MEAN,
    COL_FWD_PKTS,
    COL_LABEL,
    COL_PROTOCOL,
    COL_SRC_IP,
    COL_SRC_PORT,
    COL_SYN,
    COL_TIMESTAMP,
)

logger = logging.getLogger(__name__)

# 合成数据（无数据集时的兜底）
# ---------------------------------------------------------------------- #
def generate_synthetic_benign(
    hours: float = 1.0,
    flows_per_sec: float = 60.0,
    seed: int = 42,
) -> pd.DataFrame:
    """生成列结构与 CIC-IDS2017 一致的**合成正常流量**。

    仅用于在拿不到真实数据集时打通「训练 → 推理 → 落库」全流程，
    以及作为回放演示的数据来源，**不能**用于论文中的效果论证。

    生成模型：主机在时间轴上的泊松到达 + 对数正态的包数/字节数 +
    负载起伏因子 + 偶发的正常大流量传输（拉开正常带宽）。
    """
    rng = np.random.default_rng(seed)
    duration = max(hours, 0.01) * 3600.0
    n_flows = int(duration * flows_per_sec)
    logger.info("生成合成 BENIGN 流量: %d 条流, 覆盖 %.2f 小时", n_flows, duration / 3600.0)

    t0 = datetime(2017, 7, 5, 9, 0, 0).timestamp()
    start = np.sort(rng.uniform(0.0, duration, size=n_flows))
    # 负载起伏因子，使不同窗口的包速率存在自然差异
    load = 0.65 + 0.35 * np.sin(start / duration * np.pi * 2.0)

    n_hosts = 40
    src_hosts = rng.integers(0, n_hosts, size=n_flows)
    src_ip = np.array(["192.168.10.{0}".format(h + 10) for h in range(n_hosts)])[src_hosts]
    pool = np.array(["10.0.{0}.{1}".format(rng.integers(0, 4), rng.integers(1, 250))
                     for _ in range(min(n_flows, 4000))])
    dst_ip = rng.choice(pool, size=n_flows)

    proto = rng.choice([6, 17, 1], size=n_flows, p=[0.72, 0.25, 0.03])
    fwd_pkts = np.maximum(1, rng.lognormal(np.log(6.0), 0.9, n_flows) * load * 4).round()
    bwd_pkts = np.maximum(0, rng.lognormal(np.log(7.0), 0.9, n_flows) * load * 4).round()
    # 偶发的正常大流量传输（备份、视频、软件分发），使正常带宽更宽
    bulk = rng.random(n_flows) < 0.02
    fwd_pkts[bulk] *= rng.uniform(20, 120, size=int(bulk.sum()))
    bwd_pkts[bulk] *= rng.uniform(20, 120, size=int(bulk.sum()))

    fwd_len_mean = rng.normal(320, 90, size=n_flows).clip(60, 1400)
    bwd_len_mean = rng.normal(420, 120, size=n_flows).clip(60, 1400)
    fwd_bytes = fwd_pkts * fwd_len_mean
    bwd_bytes = bwd_pkts * bwd_len_mean
    flow_duration = np.maximum(1.0, rng.lognormal(np.log(0.6), 1.0, size=n_flows) * 1e5)
    total_bytes = fwd_bytes + bwd_bytes
    total_pkts = fwd_pkts + bwd_pkts
    syn_count = np.where(proto == 6, np.minimum(2, fwd_pkts), 0)

    return pd.DataFrame({
        COL_TIMESTAMP: [datetime.fromtimestamp(t0 + s).strftime("%d/%m/%Y %H:%M:%S")
                        for s in start],
        COL_SRC_IP: src_ip,
        COL_DST_IP: dst_ip,
        COL_SRC_PORT: rng.integers(1024, 65000, size=n_flows),
        COL_DST_PORT: rng.choice([80, 443, 53, 22, 8080, 445], size=n_flows,
                                 p=[.3, .35, .1, .08, .1, .07]),
        COL_PROTOCOL: proto,
        COL_FLOW_DURATION: flow_duration.round(0),
        COL_FWD_PKTS: fwd_pkts,
        COL_BWD_PKTS: bwd_pkts,
        COL_FWD_BYTES: fwd_bytes.round(0),
        COL_BWD_BYTES: bwd_bytes.round(0),
        COL_FWD_LEN_MEAN: fwd_len_mean.round(2),
        COL_BWD_LEN_MEAN: bwd_len_mean.round(2),
        COL_FLOW_BYTES_S: (total_bytes / (flow_duration / 1e6)).round(2),
        COL_FLOW_PKTS_S: (total_pkts / (flow_duration / 1e6)).round(2),
        COL_SYN: syn_count,
        COL_LABEL: "BENIGN",
    })
