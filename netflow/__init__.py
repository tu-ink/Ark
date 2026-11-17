# -*- coding: utf-8 -*-
"""基于 Isolation Forest 的网络流量监测系统。

包结构（分层设计）::

    netflow/
    ├── config.py      配置：默认值 → 配置文件 → 命令行 三级合并
    ├── logs.py        日志：控制台 / 文件 / 内存环形缓冲（供 UI 事件面板）
    ├── capture.py     采集层：Scapy AsyncSniffer + BPF + 有界队列（含 pcap 回放）
    ├── stats.py       统计层：消费者线程 + 时间窗口聚合 + 10 维特征
    ├── database.py    存储层：SQLite（stats / alerts 两表）
    ├── model.py       检测层：Isolation Forest 评分与阈值判定
    ├── train_model.py 训练层：CIC-IDS2017 / 合成数据 → model.joblib
    ├── pipeline.py    编排层：把上面各层串成一条监测流水线
    ├── cli.py         入口层：参数解析、信号处理、主循环
    └── ui/            表现层：ANSI 全屏 TUI 仪表盘 + 纯文本回退

依赖方向严格自上而下：``ui → pipeline → (capture, stats, model, database)``，
各层之间只通过数据对象交互，不做反向依赖，便于单独测试与替换。
"""

from __future__ import annotations

__version__ = "2.1.0"
__all__ = ["__version__"]
