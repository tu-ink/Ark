# -*- coding: utf-8 -*-
"""命令行工具：生成示例 pcap（正常流量 + SYN 洪泛）。

真正的实现在 :mod:`netflow.sample` 中，本脚本只是薄封装，
方便把它当作独立工具使用::

    python tools/make_sample_pcap.py
    python tools/make_sample_pcap.py --out demo.pcap --flood-rate 3000

等价的包内命令::

    python -m netflow.sample
    python main.py --make-sample sample.pcap
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional, Sequence

# 允许在未安装的情况下直接运行本脚本
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from netflow.sample import DEFAULT_SAMPLE_NAME, generate_sample_pcap  # noqa: E402


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="生成用于演示与链路验证的示例 pcap（正常流量 + SYN 洪泛）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("示例:\n"
                "  python tools/make_sample_pcap.py\n"
                "  python tools/make_sample_pcap.py --out demo.pcap --flood-rate 3000\n"),
    )
    parser.add_argument("--out", default=DEFAULT_SAMPLE_NAME,
                        help="输出文件名，默认 %s" % DEFAULT_SAMPLE_NAME)
    parser.add_argument("--duration", type=float, default=16.0, help="正常段时长（秒），默认 16")
    parser.add_argument("--rate", type=float, default=400.0, help="正常段包速率，默认 400 pps")
    parser.add_argument("--flood-duration", type=float, default=5.0, help="洪泛段时长，默认 5 秒")
    parser.add_argument("--flood-rate", type=float, default=1600.0, help="洪泛段包速率，默认 1600 pps")
    parser.add_argument("--seed", type=int, default=7, help="随机种子，默认 7")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        path = generate_sample_pcap(
            args.out, args.duration, args.rate,
            args.flood_duration, args.flood_rate, args.seed, quiet=False)
    except Exception as exc:
        print("生成失败: {0}".format(exc), file=sys.stderr)
        print("请先安装依赖: python -m pip install -r requirements.txt", file=sys.stderr)
        return 1
    print("已生成:", path)
    print("\n下一步:  python main.py --demo")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
