# -*- coding: utf-8 -*-
"""训练主流程：拟合隔离森林、标定阈值、保存模型产物。

同时提供 :func:`bootstrap_model`：模型缺失时用合成数据快速训练一个引导模型，
保证程序开箱即可运行（正式使用必须换成真实数据集训练的模型）。
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ..model import DEFAULT_MODEL_PATH
from ..stats import FEATURE_NAMES
from .dataset import _resolve_csv_paths
from .features import build_feature_frame_window_mode, build_feature_matrix
from .options import TrainOptions
from .synthetic import generate_synthetic_benign

logger = logging.getLogger(__name__)

# ---------------- 引导模型（开箱即用）的默认参数 ----------------
#: 合成数据时长与流速率，与示例 pcap 的包速率大致匹配
BOOTSTRAP_HOURS = 0.5
BOOTSTRAP_FLOWS_PER_SEC = 6.0
#: 引导模型声明的异常比例。取 0.03 使 auto 阈值落在正常分数分布的 P3 附近，
#: 从而既能检出示例中的 SYN 洪泛，又不会对正常窗口误报。
BOOTSTRAP_CONTAMINATION = 0.03

# 训练主流程
# ---------------------------------------------------------------------- #
def train(options: TrainOptions) -> int:
    """执行完整的训练流程，返回进程退出码（0 表示成功）。"""
    if options.synthetic:
        synthetic = generate_synthetic_benign(
            hours=options.synthetic_hours,
            flows_per_sec=options.synthetic_flows_per_sec,
            seed=options.synthetic_seed,
        )
        if options.synthetic_out:
            directory = os.path.dirname(os.path.abspath(options.synthetic_out))
            if directory:
                os.makedirs(directory, exist_ok=True)
            synthetic.to_csv(options.synthetic_out, index=False)
            logger.info("合成数据已保存: %s", options.synthetic_out)
        matrix = build_feature_frame_window_mode(synthetic, options.window)
        matrix = matrix.replace([np.inf, -np.inf], np.nan).fillna(0.0)
        mode = "window(synthetic)"
        logger.info("合成数据构建特征样本: %d 条", len(matrix))
    else:
        if not options.csv:
            logger.error("请通过 --csv 指定 CIC-IDS2017 CSV，或使用 --synthetic 生成兜底数据")
            return 2
        paths = _resolve_csv_paths(options.csv)
        if not paths:
            logger.error("未找到任何可读取的 CSV 文件")
            return 2
        logger.info("待处理文件 %d 个", len(paths))
        matrix, mode = build_feature_matrix(
            paths, options.window, options.chunksize, options.max_rows)

    if len(matrix) < 10:
        logger.error("有效样本仅 %d 条，不足以训练模型", len(matrix))
        return 2

    if options.clip_quantile is not None:
        upper = matrix.quantile(options.clip_quantile)
        lower = matrix.quantile(1.0 - options.clip_quantile)
        matrix = matrix.clip(lower=lower, upper=upper, axis=1)
        logger.info("已按分位数 %.4f 裁剪极端值", options.clip_quantile)

    if options.keep_csv:
        matrix.to_csv(options.keep_csv, index=False, encoding="utf-8-sig")
        logger.info("特征矩阵已保存: %s", options.keep_csv)

    logger.info("特征统计（用于与实时特征比对，检查是否存在域偏移）:")
    desc = matrix.describe().T[["min", "50%", "max"]]
    for name, row in desc.iterrows():
        logger.info("  %-16s min=%-14.4g median=%-14.4g max=%-14.4g",
                    name, row["min"], row["50%"], row["max"])

    scaler = None
    x_train = matrix.values.astype(np.float64)
    if options.scale:
        from sklearn.preprocessing import StandardScaler

        scaler = StandardScaler().fit(x_train)
        x_train = scaler.transform(x_train)
        logger.info("已启用 StandardScaler 标准化")

    max_samples = options.max_samples
    if isinstance(max_samples, str) and max_samples.isdigit():
        max_samples = int(max_samples)

    logger.info("开始训练 Isolation Forest: n_estimators=%d, contamination=%s, "
                "max_samples=%s, n_jobs=%d",
                options.n_estimators, options.contamination, max_samples, options.n_jobs)
    model = IsolationForest(
        n_estimators=options.n_estimators,
        contamination=options.contamination,
        max_samples=max_samples,
        random_state=options.random_state,
        n_jobs=options.n_jobs,
    )
    model.fit(x_train)

    scores = model.decision_function(x_train)
    empirical = float(np.percentile(scores, options.contamination * 100.0))

    # 阈值来源：auto 使用 sklearn 自带的校准点；否则使用用户给定的固定值
    if str(options.threshold).strip().lower() in ("auto", "none", ""):
        threshold = empirical
        threshold_mode = "auto: P{0:g}(正常训练分数) = {1:.4f}".format(
            options.contamination * 100.0, empirical)
    else:
        threshold = float(options.threshold)
        threshold_mode = "fixed: {0:.4f}".format(threshold)

    below_threshold = float((scores < threshold).mean())
    logger.info("训练完成 | 分数分布: min=%.4f, P1=%.4f, median=%.4f, max=%.4f",
                scores.min(), np.percentile(scores, 1), np.median(scores), scores.max())
    logger.info("判定阈值 = %.4f（%s），正常训练样本告警比例 = %.2f%%",
                threshold, threshold_mode, below_threshold * 100.0)

    logger.info("阈值标定参考（均为正常训练样本上的统计）:")
    for q in (0.1, 0.5, 1.0, 2.0, 5.0):
        logger.info("  目标误报率 P%-5g 对应阈值 %-12.4f %s",
                    q, np.percentile(scores, q),
                    "极保守，几乎不告警" if q <= 0.5 else
                    ("与 contamination 一致" if abs(q - options.contamination * 100) < 1e-9
                     else "较灵敏，误报偏多"))
    logger.info("说明: 孤立森林的分数存在「饱和」特性——样本再怎么超出训练范围，"
                "分数也不会无限降低；且当只有少数特征异常时，其余正常特征会稀释异常信号。"
                "因此阈值应按可接受的误报率标定，而不是固定取某个经验值。")
    if below_threshold > 0.1:
        logger.warning("按当前阈值有 %.1f%% 的正常训练样本会被判为异常，误报率偏高。"
                       "可考虑调低阈值（更负）或增大 --contamination。",
                       below_threshold * 100.0)

    bundle = {
        "model": model,
        "scaler": scaler,
        "feature_names": list(FEATURE_NAMES),
        "threshold": float(threshold),
        "meta": {
            "trained_at": datetime.now().isoformat(timespec="seconds"),
            "mode": mode,
            "window_seconds": options.window,
            "samples": int(len(matrix)),
            "n_estimators": options.n_estimators,
            "contamination": options.contamination,
            "max_samples": str(max_samples),
            "random_state": options.random_state,
            "scaled": bool(options.scale),
            "threshold_mode": threshold_mode,
            "empirical_threshold": empirical,
            "calibration": {"P{0:g}".format(q): float(np.percentile(scores, q))
                            for q in (0.1, 0.5, 1.0, 2.0, 5.0)},
            "score_min": float(scores.min()),
            "score_median": float(np.median(scores)),
            "alarm_ratio_on_train": below_threshold,
            "source": "synthetic" if options.synthetic else list(options.csv or []),
            "note": "SYNTHETIC DATA - 仅用于流程验证，不可用于效果论证"
            if options.synthetic else "CIC-IDS2017 BENIGN only",
        },
    }
    out_path = os.path.abspath(options.out)
    directory = os.path.dirname(out_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    joblib.dump(bundle, out_path)
    logger.info("模型已保存: %s (%.1f KB)", out_path, os.path.getsize(out_path) / 1024.0)

    if options.synthetic:
        logger.warning("本次训练使用的是**合成数据**，仅用于验证程序链路是否打通；"
                       "论文中的实验结论请使用真实 CIC-IDS2017 数据重新训练。")
    logger.info("下一步:  python main.py -i <网卡名> -m %s", options.out)
    return 0


def bootstrap_model(
    model_path: str = DEFAULT_MODEL_PATH,
    window_seconds: float = 5.0,
) -> bool:
    """模型缺失时用合成 BENIGN 流量训练一个**引导模型**，保证程序开箱可用。

    Returns
    -------
    bool
        是否成功产出模型文件。
    """
    logger.warning("=" * 74)
    logger.warning("未找到模型文件 %s，正在用合成 BENIGN 流量训练引导模型 ...", model_path)
    logger.warning("引导模型只用于跑通链路与演示，其正常基线来自**合成流量**；")
    logger.warning("正式使用请用真实数据集重新训练：")
    logger.warning("  python -m netflow.train_model --csv data/MachineLearningCVE/*.csv "
                   "--out %s", model_path)
    logger.warning("=" * 74)
    try:
        options = TrainOptions(
            synthetic=True,
            synthetic_hours=BOOTSTRAP_HOURS,
            synthetic_flows_per_sec=BOOTSTRAP_FLOWS_PER_SEC,
            window=window_seconds,
            out=model_path,
            contamination=BOOTSTRAP_CONTAMINATION,
        )
        ok = train(options) == 0 and os.path.isfile(model_path)
        if ok:
            logger.info("引导模型已就绪: %s", model_path)
        return ok
    except Exception:
        logger.exception("引导模型训练失败，异常检测将保持禁用"
                         "（可用 --no-auto-train 关闭该自动行为）")
        return False
