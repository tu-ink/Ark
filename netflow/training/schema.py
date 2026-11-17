# -*- coding: utf-8 -*-
"""CIC-IDS2017 数据集 Schema：列名常量与必需列定义。

单独成模块的好处：``dataset`` 与 ``features`` 都要用这些常量，
集中定义避免两处各自维护导致列名漂移。
"""

from __future__ import annotations

COL_LABEL = "Label"
COL_TIMESTAMP = "Timestamp"
COL_SRC_IP = "Source IP"
COL_DST_IP = "Destination IP"
COL_SRC_PORT = "Source Port"
COL_DST_PORT = "Destination Port"
COL_PROTOCOL = "Protocol"
COL_FWD_PKTS = "Total Fwd Packets"
COL_BWD_PKTS = "Total Backward Packets"
COL_FWD_BYTES = "Total Length of Fwd Packets"
COL_BWD_BYTES = "Total Length of Bwd Packets"
COL_FLOW_BYTES_S = "Flow Bytes/s"
COL_FLOW_PKTS_S = "Flow Packets/s"
COL_FLOW_DURATION = "Flow Duration"
COL_SYN = "SYN Flag Count"
COL_FWD_LEN_MEAN = "Fwd Packet Length Mean"
COL_BWD_LEN_MEAN = "Bwd Packet Length Mean"

#: 逐流近似模式下必须存在的列
REQUIRED_FLOW_COLUMNS = (COL_FWD_PKTS, COL_BWD_PKTS, COL_FWD_BYTES, COL_BWD_BYTES)

#: 窗口聚合模式额外需要的列
REQUIRED_WINDOW_COLUMNS = (COL_TIMESTAMP, COL_SRC_IP, COL_PROTOCOL)

#: 需要转成数值型的列
NUMERIC_COLUMNS = (
    COL_FWD_PKTS, COL_BWD_PKTS, COL_FWD_BYTES, COL_BWD_BYTES,
    COL_FLOW_BYTES_S, COL_FLOW_PKTS_S, COL_FLOW_DURATION, COL_SYN,
    COL_FWD_LEN_MEAN, COL_BWD_LEN_MEAN, COL_PROTOCOL,
)

_TIMESTAMP_FORMATS = (
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%d/%m/%Y %I:%M:%S %p",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
)
