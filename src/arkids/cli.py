"""命令行入口: python -m arkids <子命令> [选项]

子命令:
    init-demo-data   生成与 NSL-KDD 同构的离线演示数据集
    fetch-nslkdd     从公开镜像尽力下载 NSL-KDD 评测集(网络可用时)
    train            训练检测模型并输出评估报告
    simulate         实时流量回放 + 攻击仿真(检测与防御闭环演示)
    serve            启动极简 REST 检测服务
    demo             init-demo-data + train + simulate 一键演示
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from . import __version__
from .config import (DATA_DIR, LABEL_COL, MODELS_DIR, PROJECT_ROOT,
                     ensure_dirs)
from .dataset import (fetch_nslkdd, generate_demo_flows, load_any,
                      save_demo_csv)
from .models import ALGOS, Trainer
from .simulate import run_simulation

DEFAULT_MODEL = MODELS_DIR / "arkids_rf.joblib"
DEMO_CSV = DATA_DIR / "demo_flows.csv"


def _cmd_init_demo(args: argparse.Namespace) -> None:
    ensure_dirs()
    path = save_demo_csv(str(args.out), n=args.n, seed=args.seed)
    df = pd.read_csv(path)
    print(f"[ok] 演示数据已生成: {path}  (共 {len(df)} 行)")
    print(df[LABEL_COL].value_counts().to_string())


def _cmd_fetch(args: argparse.Namespace) -> None:
    ensure_dirs()
    got = fetch_nslkdd(str(args.dir))
    if got:
        for p in got:
            print(f"[ok] 已就绪: {p}")
    else:
        print("[warn] 下载失败(网络不可达或镜像变更)。可手动放置 KDDTrain+.txt 后使用 "
              "--data 指定; 或先运行 init-demo-data 使用合成演示数据。")


def _load_training_data(path: str | None) -> tuple[pd.DataFrame, pd.Series]:
    ensure_dirs()
    if path is None:
        if not DEMO_CSV.exists():
            save_demo_csv(str(DEMO_CSV), n=4000)
            print(f"[info] 未指定数据, 已自动生成演示集 {DEMO_CSV}")
        path = str(DEMO_CSV)
    df = load_any(path)
    if LABEL_COL not in df.columns:
        sys.exit(f"[error] 数据缺少标签列 '{LABEL_COL}': {path}")
    y = df[LABEL_COL].astype(str).str.lower()
    X = df.drop(columns=[LABEL_COL])
    return X, y


def _cmd_train(args: argparse.Namespace) -> None:
    ensure_dirs()
    t0 = time.time()
    X, y = _load_training_data(args.data)
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=args.seed,
    )
    trainer = Trainer(algo=args.algo, random_state=args.seed)
    trainer.fit(Xtr, ytr)
    eval_train = trainer.evaluate(Xtr, ytr)
    eval_test = trainer.evaluate(Xte, yte)
    trainer.save(str(args.out))
    lines = [
        f"ArkIDS 训练报告(algo={args.algo}, seed={args.seed})",
        f"数据: {args.data or '自动生成演示集'}  样本: 训练={len(Xtr)} 测试={len(Xte)}",
        f"耗时: {time.time() - t0:.2f}s   模型产物: {args.out}",
        "",
        "== 测试集整体指标 ==",
        f"  Accuracy     = {eval_test['accuracy']:.4f}",
        f"  Attack AUC   = {eval_test['attack_auc']:.4f}",
        f"  Macro F1     = {eval_test['macro_f1']:.4f}",
        f"  Weighted F1  = {eval_test['weighted_f1']:.4f}",
        f"  攻击 Precision= {eval_test['attack_precision']:.4f}",
        f"  攻击 Recall  = {eval_test['attack_recall']:.4f}",
        "",
        "== 测试集逐类报告 ==",
        eval_test["report_txt"],
        "== 训练集(拟合参考) ==",
        f"  Accuracy={eval_train['accuracy']:.4f}  MacroF1={eval_train['macro_f1']:.4f}",
    ]
    text = "\n".join(lines)
    print(text)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        with open(str(args.report) + ".json", "w", encoding="utf-8") as fh:
            json.dump({"test": {k: v for k, v in eval_test.items() if k != "report_txt"},
                       "train": {k: v for k, v in eval_train.items() if k != "report_txt"}},
                      fh, ensure_ascii=False, indent=2)
        print(f"[ok] 报告已保存: {args.report}")


def _cmd_simulate(args: argparse.Namespace) -> None:
    ensure_dirs()
    run_simulation(
        data_path=args.data or str(DEMO_CSV),
        model_path=args.model,
        threshold=args.threshold,
        limit=args.limit,
        attacker_pool=args.attacker_pool,
        block_hits=args.block_hits,
        window_sec=args.window,
        speed=args.speed,
        dry_run=args.dry_run,
        state_dir=args.state_dir,
        seed=args.seed,
    )


def _cmd_serve(args: argparse.Namespace) -> None:
    ensure_dirs()
    from .server import DetectionService
    DetectionService(model_path=args.model, threshold=args.threshold,
                     state_dir=args.state_dir).serve(args.host, args.port)


def _cmd_dashboard(args: argparse.Namespace) -> None:
    """启动可视化控制台(实时攻防网络/防火墙/日志/AI 建议)。"""
    ensure_dirs()
    if not Path(args.model).exists():
        print(f"[error] 未找到模型 {args.model}, 请先运行: python -m arkids train")
        raise SystemExit(2)
    # 控制台使用独立状态目录并默认“干净启动”, 避免与 simulate 的历史封禁状态混叠
    import shutil
    state_dir = Path(args.state_dir)
    if not getattr(args, "no_reset", False):
        shutil.rmtree(state_dir, ignore_errors=True)
        state_dir.mkdir(parents=True, exist_ok=True)
    from .dashboard import DashboardService
    DashboardService(
        model_path=args.model, data_path=args.data, threshold=args.threshold,
        attacker_pool=args.attacker_pool, block_hits=args.block_hits,
        window_sec=args.window, state_dir=str(state_dir),
        seed=args.seed, speed=args.speed,
    ).serve(args.host, args.port)


def _cmd_demo(args: argparse.Namespace) -> None:
    """一键演示: 造数据 -> 训练 -> 仿真闭环。"""
    ensure_dirs()
    save_demo_csv(str(DEMO_CSV), n=args.n, seed=args.seed)
    train_ns = argparse.Namespace(
        data=str(DEMO_CSV), algo="rf", out=str(DEFAULT_MODEL),
        test_size=0.3, seed=args.seed, report=str(PROJECT_ROOT / "run" / "train_report.txt"),
    )
    _cmd_train(train_ns)
    print("\n" + "=" * 60 + "\n开始仿真演示(检测→防御联动):\n")
    run_simulation(data_path=str(DEMO_CSV), model_path=str(DEFAULT_MODEL),
                   limit=args.simulate_limit, attacker_pool=5,
                   block_hits=args.block_hits, window_sec=60.0)


# ---------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="arkids", description="基于人工智能的网络攻击智能检测与防御系统")
    p.add_argument("--version", action="version", version=f"arkids {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init-demo-data", help="生成离线演示数据集")
    sp.add_argument("--out", default=str(DEMO_CSV))
    sp.add_argument("--n", type=int, default=4000)
    sp.add_argument("--seed", type=int, default=42)
    sp.set_defaults(func=_cmd_init_demo)

    sp = sub.add_parser("fetch-nslkdd", help="下载 NSL-KDD 评测集")
    sp.add_argument("--dir", default=str(DATA_DIR / "nslkdd"))
    sp.set_defaults(func=_cmd_fetch)

    sp = sub.add_parser("train", help="训练检测模型")
    tp = sp.add_argument_group()
    tp.add_argument("--data", default=None)
    tp.add_argument("--algo", default="rf", choices=ALGOS)
    tp.add_argument("--out", default=str(DEFAULT_MODEL))
    tp.add_argument("--test-size", type=float, default=0.3)
    tp.add_argument("--seed", type=int, default=42)
    tp.add_argument("--report", default=None)
    sp.set_defaults(func=_cmd_train)

    sp = sub.add_parser("simulate", help="攻击仿真与防御联动演示")
    sp.add_argument("--data", default=None)
    sp.add_argument("--model", default=str(DEFAULT_MODEL))
    sp.add_argument("--threshold", type=float, default=0.5)
    sp.add_argument("--limit", type=int, default=None)
    sp.add_argument("--attacker-pool", type=int, default=4)
    sp.add_argument("--block-hits", type=int, default=3)
    sp.add_argument("--window", type=float, default=60.0)
    sp.add_argument("--speed", type=float, default=0.0)
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--state-dir", default="run")
    sp.add_argument("--seed", type=int, default=7)
    sp.set_defaults(func=_cmd_simulate)

    sp = sub.add_parser("serve", help="启动 REST 检测服务")
    sp.add_argument("--model", default=str(DEFAULT_MODEL))
    sp.add_argument("--threshold", type=float, default=0.5)
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8735)
    sp.add_argument("--state-dir", default="run")
    sp.set_defaults(func=_cmd_serve)

    sp = sub.add_parser("dashboard", help="启动可视化控制台(实时攻防网络/防火墙/日志/AI 建议)")
    sp.add_argument("--model", default=str(DEFAULT_MODEL))
    sp.add_argument("--data", default=None, help="回放流量文件(缺省使用演示集)")
    sp.add_argument("--threshold", type=float, default=0.5)
    sp.add_argument("--attacker-pool", type=int, default=5)
    sp.add_argument("--block-hits", type=int, default=3)
    sp.add_argument("--window", type=float, default=60.0)
    sp.add_argument("--speed", type=float, default=40.0, help="每秒回放事件数")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8642)
    sp.add_argument("--state-dir", default="run/dashboard",
                    help="运行状态目录(默认每次启动自动清空)")
    sp.add_argument("--no-reset", action="store_true",
                    help="不清空状态目录(跨启动保留封禁/规则)")
    sp.add_argument("--seed", type=int, default=7)
    sp.set_defaults(func=_cmd_dashboard)

    sp = sub.add_parser("demo", help="一键演示(造数据+训练+仿真)")
    sp.add_argument("--n", type=int, default=4000)
    sp.add_argument("--simulate-limit", type=int, default=1500)
    sp.add_argument("--block-hits", type=int, default=3)
    sp.add_argument("--seed", type=int, default=42)
    sp.set_defaults(func=_cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
