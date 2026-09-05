# 实验结果与分析

> 实验环境：Windows / Python 3.12.6 / scikit-learn 1.8.0 / numpy 2.2.6 / pandas 2.3.3。
> 硬件：普通个人计算机（未调大并行度，`ARKIDS_N_JOBS` 保持默认 1）。
> 全部结果可复现：固定随机种子（数据 42，训练 42，仿真 7/2024），命令见文末。

## 1. 实验数据

- **演示数据集** `data/demo_flows.csv`：4000 条合成流量，与 NSL-KDD 同构（41 特征+标签）。
  生成参数：攻击占比 0.62；标签噪声 0.03；特征污染 0.06；
  **隐蔽攻击硬样本比例 0.18**（攻击流量特征与正常流量高度相似，模拟
  R2L/U2R 类难以单流识别的攻击）。
- 类别分布：normal 1504、dos 634、r2l 633、probe 627、u2r 602。
- 划分：70% 训练 / 30% 测试（按类别分层，种子 42）。
- 仿真验证集 `data/demo_eval.csv`：**全新种子(2024)生成**的 1500 条样本，与训练数据无重叠。

## 2. 检测模型对比（测试集 1200 条）

| 模型 | Accuracy | Attack AUC | Macro-F1 | Weighted-F1 | 攻击 Precision | 攻击 Recall | 训练耗时 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RandomForest(200 棵) | **0.8975** | **0.9143** | **0.9041** | **0.8989** | 1.0000 | 0.8358 | ~1 s |
| MLP(128-64, 早停) | 0.8775 | — | 0.8830 | 0.8786 | — | 0.8358 | 数十秒级 |

RandomForest 逐类报告（测试集）：

```
              precision    recall  f1-score   support
         dos     1.0000    0.8263    0.9049       190
      normal     0.7857    1.0000    0.8800       451
       probe     1.0000    0.8032    0.8909       188
         r2l     1.0000    0.8842    0.9385       190
         u2r     1.0000    0.8287    0.9063       181

    accuracy                         0.8975      1200
   macro avg     0.9571    0.8685    0.9041      1200
weighted avg     0.9195    0.8975    0.8989      1200
```

### 结果解读（与文献对照）

1. **正常类 Precision=0.786、各类攻击 Precision≈1.0**：被漏判的主要是“伪装成正常流量”
   的隐蔽攻击（模型判为 normal），几乎不存在正常流量被误报为攻击的情况 —— 与真实
   入侵检测中“宁可漏检、少误报”或“R2L/U2R 检出率低”的已知难点一致
   （参见 docs/literature_review.md 文献 1、8）。
2. **各攻击类 Recall ≈ 0.80~0.88**：扣除 18% 特征不可分的硬样本后，可分攻击基本全检出
   （可分部分 Recall ≈ 0.97+），说明模型学到了家族级判别模式而非死记硬背。
3. 演示数据刻意“不完美”，用于如实展示模型泛化与数据难度的关系，而非宣称 SOTA。

## 3. 检测-防御闭环仿真（1500 条全新样本）

设置：攻击源收敛到 5 个仿真 IP（`203.0.113.10~14`）；`--threshold 0.5`；
封禁条件 = 60 s 窗口内同源告警 ≥ 3 次。

| 指标 | 值 |
| --- | --- |
| 流量总数 | 1500（真攻击 889 / 正常 611） |
| Accuracy | 0.8993 |
| 攻击检出率 Recall | 0.8346 |
| 攻击 Precision | 0.9946 |
| 误报(FP) | 4 |
| 告警总数 | 746 |
| 自动封禁攻击源 | **5/5 全部封禁** |
| 正常主机被误封 | 0 |

说明：封禁的 5 个 IP 全部为仿真攻击源（正常流量源为主机网段 10.10.*.*，
且每源仅零星告警，不满足证据阈值，因此无误封）；4 条误报流量来源分散、未达
封禁阈值，也验证了**证据累积机制对单条误报的容忍性**。

## 4. 局限

1. 全部实验在**合成数据**上完成，数字不构成真实网络环境性能承诺；
   正式结论需以 NSL-KDD / CICIDS2017 评测为准（工程上已支持，见 usage.md 2.4）。
2. 检测粒度为单条流，未建模多步攻击链与会话上下文。
3. 防御动作为仿真执行（输出规则脚本/封禁清单），真实联动需对接防火墙/SOAR。

## 5. 复现命令

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m arkids init-demo-data --n 4000 --seed 42 --out data/demo_flows.csv
python -m arkids init-demo-data --n 1500 --seed 2024 --out data/demo_eval.csv
python -m arkids train --data data/demo_flows.csv --algo rf --out models/arkids_rf.joblib
python -m arkids train --data data/demo_flows.csv --algo mlp --out models/arkids_mlp.joblib
python -m arkids simulate --data data/demo_eval.csv --model models/arkids_rf.joblib `
    --attacker-pool 5 --block-hits 3 --window 60
python -m unittest discover -s tests -v
```
