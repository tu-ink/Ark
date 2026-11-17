# -*- coding: utf-8 -*-
"""入口层（cli）：命令行解析、辅助子命令与主流程调度。

只做三件事：

1. 把命令行/配置文件合并成 :class:`~netflow.config.AppConfig`；
2. 处理不需要进入监测循环的辅助命令（列网卡、查历史、导出 CSV、生成示例数据）；
3. 初始化日志与界面，然后交给 :class:`~netflow.pipeline.MonitorApp` 运行。
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Optional, Sequence

from . import __version__
from .config import PROGRAM_NAME, AppConfig
from .database import TrafficDB, print_recent
from .logs import setup_logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------- #
# 辅助命令
# ---------------------------------------------------------------------- #
def cmd_list_ifaces() -> int:
    """打印可用网卡列表。"""
    from .capture import SCAPY_AVAILABLE, SCAPY_IMPORT_ERROR, list_interfaces

    if not SCAPY_AVAILABLE:
        print("未检测到 Scapy：{0}".format(SCAPY_IMPORT_ERROR))
        print("请先执行:  python -m pip install -r requirements.txt")
        return 1
    interfaces = list_interfaces()
    if not interfaces:
        print("未枚举到网卡。Windows 下请确认已安装 Npcap（https://npcap.com/）")
        return 1
    print("可用网卡:")
    for name in interfaces:
        print("  -", name)
    return 0


def cmd_make_sample(path: str) -> int:
    """生成示例 pcap。"""
    from .sample import generate_sample_pcap

    try:
        target = generate_sample_pcap(path, quiet=False)
    except Exception:
        logger.exception("生成示例数据失败（请确认已安装 Scapy）")
        return 1
    print("已生成: {0}".format(target))
    print("下一步:  python main.py --demo")
    return 0


def cmd_query(config: AppConfig, show_stats: Optional[int] = None,
              show_alerts: Optional[int] = None,
              export_csv: Optional[str] = None) -> int:
    """查询 / 导出数据库内容后退出。"""
    db = TrafficDB(config.db)
    try:
        if show_stats is not None:
            print_recent(db, limit=show_stats)
        if show_alerts is not None:
            if show_stats is not None:
                print()
            print_recent(db, limit=show_alerts, alerts=True)
        if export_csv:
            count = db.export_stats_csv(export_csv)
            print("已导出 {0} 行统计记录到 {1}".format(count, export_csv))
        summary = db.summary()
        print()
        print("数据库 {0}: 窗口 {1} 个（异常 {2} 个）, 告警 {3} 条, 时间范围 {4} ~ {5}, "
              "累计包数 {6}, 累计字节 {7}".format(
                  config.db, summary.get("windows", 0), summary.get("anomaly_windows", 0),
                  summary.get("alerts", 0), summary.get("first_ts") or "-",
                  summary.get("last_ts") or "-", summary.get("total_packets", 0),
                  summary.get("total_bytes", 0)))
    finally:
        db.close()
    return 0


# ---------------------------------------------------------------------- #
# 主入口
# ---------------------------------------------------------------------- #
def main(argv: Optional[Sequence[str]] = None) -> int:
    """程序入口，返回进程退出码。"""
    # ---------- 1. 解析配置（命令行 + 配置文件，三级合并） ----------
    parser = AppConfig.build_parser()
    args = parser.parse_args(argv)
    try:
        config = AppConfig.from_sources(namespace=args)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print("配置错误: {0}".format(exc), file=sys.stderr)
        return 2

    # ---------- 2. 决定界面模式，据此决定日志是否输出到控制台 ----------
    from .ui.base import resolve_ui_mode

    ui_mode = resolve_ui_mode(config)
    setup_logging(config.log_level, config.log_file, console=(ui_mode != "tui"))

    # ---------- 3. 辅助命令（执行后立即退出） ----------
    if args.list_ifaces:
        return cmd_list_ifaces()
    if args.make_sample:
        return cmd_make_sample(args.make_sample)
    if args.show_stats is not None or args.show_alerts is not None or args.export_csv:
        return cmd_query(config, args.show_stats, args.show_alerts, args.export_csv)

    # ---------- 4. 正常监测流程 ----------
    logger.info("%s v%s 启动", PROGRAM_NAME, __version__)
    if config.config_file:
        logger.info("已加载配置文件: %s", config.config_file)

    from .pipeline import MonitorApp

    app = MonitorApp(config)
    try:
        return app.run()
    except KeyboardInterrupt:
        logger.warning("收到 Ctrl+C，进程退出")
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
