# -*- coding: utf-8 -*-
"""配置层：把「默认值 → 配置文件 → 命令行参数」三级来源合并成一个不可变配置对象。

优先级（后者覆盖前者）::

    内置默认值  <  --config 指定的 JSON 配置文件  <  命令行参数

这样既可以直接 ``python main.py --demo`` 零配置运行，也可以在部署时把常用参数
固化到配置文件里（见 ``config.example.json``），最后用命令行做临时覆盖。
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass, fields
from typing import Any, Dict, List, Optional, Sequence

from . import __version__

PROGRAM_NAME = "netflow-monitor"

#: 默认 BPF 过滤器。``icmp`` 只匹配 IPv4，如需 IPv6 请追加 ``or icmp6``
DEFAULT_BPF_FILTER = "tcp or udp or icmp"

#: 默认文件名
DEFAULT_DB_PATH = "traffic_monitor.db"
DEFAULT_MODEL_PATH = "model.joblib"
DEFAULT_SAMPLE_PCAP = "sample.pcap"

#: UI 模式
UI_MODES = ("auto", "tui", "plain")
#: UI 绘制风格：ascii 兼容性最好；unicode 使用制表符与方块字符，更好看
UI_STYLES = ("ascii", "unicode")


@dataclass
class AppConfig:
    """监测系统的全部可配置项。"""

    # ---------------- 采集层 ----------------
    iface: Optional[str] = None
    """监听的网卡名，``None`` 表示 Scapy 默认网卡。"""
    bpf: str = DEFAULT_BPF_FILTER
    """BPF 过滤表达式。"""
    queue_size: int = 10000
    """有界队列容量，队满丢弃新包并计数。"""
    promisc: bool = True
    """是否开启网卡混杂模式。"""
    replay: Optional[str] = None
    """回放 pcap 文件（设置了就不再抓网卡，无需管理员权限）。"""
    replay_speed: float = 1.0
    """回放倍速：1.0 为实时，0 为不限速（仅压力测试）。"""
    packet_limit: Optional[int] = None
    """采集到指定包数后自动停止。"""
    demo: bool = False
    """演示模式：自动准备示例 pcap 并回放。"""

    # ---------------- 统计层 ----------------
    window: float = 5.0
    """时间窗口长度（秒）。"""
    top_n: int = 5
    """记录 Top-N 源 IP / 目的端口。"""
    record_empty: bool = False
    """是否把无报文的空窗口也写入数据库。"""

    # ---------------- 存储层 ----------------
    db: str = DEFAULT_DB_PATH
    """SQLite 数据库路径。"""

    # ---------------- 检测层 ----------------
    model: str = DEFAULT_MODEL_PATH
    """Isolation Forest 模型路径。"""
    threshold: Optional[float] = None
    """判定阈值；``None`` 表示使用模型产物中保存的阈值。"""
    strict_model: bool = False
    """模型缺失时直接退出，而不是降级为「只统计不检测」。"""
    auto_train: bool = True
    """模型缺失时自动用合成数据训练引导模型，保证开箱可用。"""

    # ---------------- 表现层 ----------------
    ui: str = "auto"
    """UI 模式：auto（有终端就用 TUI）/ tui / plain。"""
    ui_style: str = "ascii"
    """绘制风格：ascii（默认，兼容性最好）/ unicode。"""
    refresh: float = 0.5
    """TUI 刷新间隔（秒）。"""
    history: int = 60
    """TUI 保留的窗口历史条数（用于趋势图）。"""

    # ---------------- 运行 ----------------
    duration: Optional[float] = None
    """运行指定秒数后自动停止。"""
    log_level: str = "INFO"
    log_file: Optional[str] = None
    """日志文件路径（UTF-8）；TUI 模式下建议设置，便于事后排查。"""
    config_file: Optional[str] = None
    """本次实际加载的配置文件路径（只读，由 :meth:`from_sources` 填充）。"""

    # ------------------------------------------------------------------ #
    # 命令行
    # ------------------------------------------------------------------ #
    @staticmethod
    def build_parser() -> argparse.ArgumentParser:
        """构造命令行解析器。

        所有可配置项默认值均为 ``None``，以便区分「用户显式指定」与「未指定」，
        从而实现配置文件与命令行的正确覆盖关系。
        """
        parser = argparse.ArgumentParser(
            prog=PROGRAM_NAME,
            description="基于 Isolation Forest 的网络流量监测系统（控制台 / 全屏 TUI）",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                "示例:\n"
                "  python main.py --demo                      # 零配置演示（推荐先跑这个）\n"
                "  python main.py --list-ifaces               # 查看可用网卡\n"
                "  python main.py -i eth0 -w 5                # 实时监测（需管理员/root）\n"
                "  python main.py --ui plain -i eth0          # 纯文本输出（便于重定向到文件）\n"
                "  python main.py --show-alerts 20            # 查询历史告警\n"
                "  python main.py --config config.json -i eth0\n"
            ),
        )
        parser.add_argument("-V", "--version", action="version",
                            version="{0} {1}".format(PROGRAM_NAME, __version__))

        grp = parser.add_argument_group("数据来源")
        grp.add_argument("-i", "--iface", default=None, help="监听的网卡名")
        grp.add_argument("--bpf", default=None, help="BPF 过滤表达式，默认 %r" % DEFAULT_BPF_FILTER)
        grp.add_argument("--queue-size", type=int, default=None, help="有界队列容量，默认 10000")
        grp.add_argument("--promisc", dest="promisc", action="store_true", default=None,
                         help="开启网卡混杂模式（默认开启）")
        grp.add_argument("--no-promisc", dest="promisc", action="store_false", default=None,
                         help="关闭网卡混杂模式")
        grp.add_argument("--replay", default=None, help="回放 pcap 文件而不是实时抓包")
        grp.add_argument("--replay-speed", type=float, default=None,
                         help="回放倍速：1.0 实时（默认），0 不限速")
        grp.add_argument("--packet-limit", type=int, default=None, help="采集指定包数后停止")
        grp.add_argument("--demo", dest="demo", action="store_true", default=None,
                         help="演示模式：自动准备示例 pcap 并回放（无需管理员权限）")

        grp = parser.add_argument_group("统计")
        grp.add_argument("-w", "--window", type=float, default=None, help="时间窗口长度（秒），默认 5")
        grp.add_argument("--top-n", type=int, default=None, help="Top-N 源 IP / 目的端口，默认 5")
        grp.add_argument("--record-empty", dest="record_empty", action="store_true", default=None,
                         help="记录没有报文的空窗口（默认跳过）")
        grp.add_argument("--no-record-empty", dest="record_empty", action="store_false", default=None,
                         help="不记录空窗口（默认）")

        grp = parser.add_argument_group("存储与模型")
        grp.add_argument("-d", "--db", default=None, help="SQLite 数据库路径，默认 %s" % DEFAULT_DB_PATH)
        grp.add_argument("-m", "--model", default=None, help="模型路径，默认 %s" % DEFAULT_MODEL_PATH)
        grp.add_argument("--threshold", type=float, default=None,
                         help="异常判定阈值；不指定时使用模型内保存的阈值")
        grp.add_argument("--strict-model", dest="strict_model", action="store_true", default=None,
                         help="模型缺失时直接退出")
        grp.add_argument("--no-strict-model", dest="strict_model", action="store_false", default=None,
                         help="模型缺失时降级为「只统计不检测」（默认）")
        grp.add_argument("--auto-train", dest="auto_train", action="store_true", default=None,
                         help="模型缺失时自动训练引导模型（默认开启）")
        grp.add_argument("--no-auto-train", dest="auto_train", action="store_false", default=None,
                         help="关闭模型缺失时的自动引导训练")

        grp = parser.add_argument_group("界面")
        grp.add_argument("--ui", choices=UI_MODES, default=None,
                         help="UI 模式：auto（默认）/ tui（全屏仪表盘）/ plain（纯文本）")
        grp.add_argument("--ui-style", choices=UI_STYLES, default=None,
                         help="绘制风格：ascii（默认，兼容性最好）/ unicode")
        grp.add_argument("--refresh", type=float, default=None, help="TUI 刷新间隔（秒），默认 0.5")
        grp.add_argument("--history", type=int, default=None, help="TUI 趋势保留窗口数，默认 60")

        grp = parser.add_argument_group("运行与日志")
        grp.add_argument("--duration", type=float, default=None, help="运行指定秒数后自动停止")
        grp.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default=None,
                         help="日志级别，默认 INFO")
        grp.add_argument("--log-file", default=None, help="同时写入 UTF-8 日志文件")
        grp.add_argument("-c", "--config", default=None, help="加载 JSON 配置文件")

        grp = parser.add_argument_group("查询与辅助（执行后立即退出）")
        grp.add_argument("--list-ifaces", action="store_true", help="列出可用网卡")
        grp.add_argument("--show-stats", type=int, default=None, metavar="N",
                         help="打印最近 N 条统计记录")
        grp.add_argument("--show-alerts", type=int, default=None, metavar="N",
                         help="打印最近 N 条告警记录")
        grp.add_argument("--export-csv", default=None, metavar="PATH", help="把 stats 表导出为 CSV")
        grp.add_argument("--make-sample", default=None, metavar="PATH",
                         help="生成示例 pcap（正常流量 + SYN 洪泛）后退出")
        return parser

    # ------------------------------------------------------------------ #
    # 构造
    # ------------------------------------------------------------------ #
    @classmethod
    def from_sources(cls, argv: Optional[Sequence[str]] = None,
                     namespace: Optional[argparse.Namespace] = None) -> "AppConfig":
        """按「默认值 → 配置文件 → 命令行」合并出最终配置。

        Parameters
        ----------
        argv:
            命令行参数列表；``None`` 表示使用 ``sys.argv[1:]``。
        namespace:
            已经解析好的命令行结果，传入可避免重复解析（cli 层会用到）。
        """
        args = namespace if namespace is not None else cls.build_parser().parse_args(argv)
        config = cls()

        config_path = getattr(args, "config", None)
        if config_path:
            config.apply_file(config_path)
            config.config_file = os.path.abspath(config_path)

        config.apply_namespace(args)
        config.validate()
        return config

    def apply_file(self, path: str) -> None:
        """从 JSON 配置文件读取覆盖项（未知键会被忽略并给出提示）。"""
        if not os.path.isfile(path):
            raise FileNotFoundError("配置文件不存在: {0}".format(path))
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("配置文件根节点必须是 JSON 对象")

        known = {f.name for f in fields(self)}
        unknown: List[str] = []
        for key, value in data.items():
            if key in known:
                setattr(self, key, value)
            else:
                unknown.append(key)
        if unknown:
            import logging

            logging.getLogger(__name__).warning("配置文件中存在未知配置项，已忽略: %s",
                                                ", ".join(sorted(unknown)))

    def apply_namespace(self, args: argparse.Namespace) -> None:
        """用命令行参数覆盖配置（仅覆盖用户显式给出的项）。"""
        for spec in fields(self):
            if not hasattr(args, spec.name):
                continue
            value = getattr(args, spec.name)
            if value is not None:
                setattr(self, spec.name, value)

    def validate(self) -> None:
        """参数合法性校验，失败时抛出带说明的 ``ValueError``。"""
        if self.window <= 0:
            raise ValueError("--window 必须为正数，当前为 {0}".format(self.window))
        if self.queue_size <= 0:
            raise ValueError("--queue-size 必须为正数，当前为 {0}".format(self.queue_size))
        if self.top_n < 1:
            raise ValueError("--top-n 必须 >= 1")
        if self.refresh <= 0:
            raise ValueError("--refresh 必须为正数")
        if self.history < 5:
            raise ValueError("--history 至少为 5")
        if self.replay_speed < 0:
            raise ValueError("--replay-speed 不能为负数")
        if self.duration is not None and self.duration <= 0:
            raise ValueError("--duration 必须为正数")
        if self.ui not in UI_MODES:
            raise ValueError("--ui 只能是 {0}".format("/".join(UI_MODES)))
        if self.ui_style not in UI_STYLES:
            raise ValueError("--ui-style 只能是 {0}".format("/".join(UI_STYLES)))

    # ------------------------------------------------------------------ #
    # 输出
    # ------------------------------------------------------------------ #
    def as_dict(self) -> Dict[str, Any]:
        """转为字典（用于日志与 ``--show-config`` 之类的诊断输出）。"""
        return asdict(self)

    def describe(self) -> List[str]:
        """返回启动横幅用的键值对列表。"""
        source = ("pcap 回放 {0}".format(self.replay) if self.replay
                  else "网卡 {0}".format(self.iface or "<默认网卡>"))
        return [
            ("数据源", source),
            ("BPF 过滤器", self.bpf if not self.replay else "（回放模式不生效）"),
            ("统计窗口", "{0} 秒".format(self.window)),
            ("数据库", os.path.abspath(self.db)),
            ("模型", os.path.abspath(self.model)),
            ("队列容量", "{0}（队满丢弃新包并计数）".format(self.queue_size)),
            ("界面", "{0} / {1}".format(self.ui, self.ui_style)),
        ]
