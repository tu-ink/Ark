# 系统设计说明

## 1. 设计目标

面向“基于人工智能智能检测防御网络攻击”主题，交付一个**可运行、可扩展**的
网络攻击检测与防御原型，核心诉求：

1. **检测**：对单条网络流给出类别判决（正常/DoS/Probe/R2L/U2R）与攻击置信度；
2. **防御**：把检测结果转化为可执行的安全动作，并尽量降低误封风险；
3. **工程性**：数据/模型/接口解耦，命令行与 REST 双入口，离线可复现。

## 2. 总体架构

```
                    ┌──────────────────────────────────────────────┐
                    │                   输入层                     │
                    │  流量文件(NSL-KDD 格式 / 演示 CSV)  或 REST  │
                    └──────────────────┬───────────────────────────┘
                                       ▼
   ┌────────────────────────────────────────────────────────────────┐
   │                      特征工程(FeaturePreparer)                 │
   │   协议/服务/标志: One-Hot;  数值特征: 标准化(StandardScaler)   │
   └────────────────────────────────┬───────────────────────────────┘
                                    ▼
   ┌────────────────────────────────────────────────────────────────┐
   │                  AI 检测引擎(FlowDetector + Trainer)           │
   │   模型: RandomForest / GradientBoosting / MLP(神经网络)         │
   │   输出: 五分类判决 + P(攻击) 置信度, 阈值可调                  │
   └────────────────────────────────┬───────────────────────────────┘
                                    ▼
   ┌────────────────────────────────────────────────────────────────┐
   │                 智能防御引擎(DefenseEngine)                    │
   │   证据累积: 同源 IP 在时间窗口内告警 ≥ k 次 → 封禁            │
   │   动作: 告警日志/封禁清单JSON/防火墙规则/Webhook 扩展点        │
   └────────────────────────────────────────────────────────────────┘
```

### 闭环逻辑（对应主题“检测 + 防御”）

1. 每条网络流 → 特征变换 → 模型推理 → 若 `P(攻击) ≥ 阈值` 判定为攻击并告警；
2. 防御引擎把“源 IP”作为最小证据单元，在滑动时间窗口内累积告警；
3. 累积告警数达到阈值（默认 3 次/60s）→ 自动封禁该 IP：
   - 写入 `run/blocklist.json`（封禁清单，可被外部安全设备消费）；
   - 追加 `run/firewall_rules.sh`（生成 nftables/iptables 规则，供真实环境执行）；
4. 证据窗口过期自动清理，支持误报后的“衰减”恢复（降低长期误杀）。

> 设计理由（文献 1、2 提示的工程约束）：单条样本误报率高时若直接封禁会误伤正常用户，
> 故采用**证据累积式决策**；这与真实 WAF/IPS 的“多次触发再阻断”策略一致。

## 3. 数据设计

- **统一模式**：41 个 KDD 风格流量特征 + `label`（`docs/` 与代码注释均给出列名）；
- **标准评测集**：支持直接读取 NSL-KDD（无表头、空白分隔的 KDDTrain+/KDDTest+），
  原始攻击名自动映射为 `normal/dos/probe/r2l/u2r/other` 家族（`config.ATTACK_FAMILY`）；
- **演示数据**（离线兜底）：合成器按家族设计统计规律，并包含三种可控噪声：
  - 标签噪声（标注误差）、特征污染（观测噪声）、**隐蔽攻击样本**（特征同正常流量的
    攻击，占攻击样本 ~18%，用于复现 R2L/U2R 难检测现象）；
- 演示数据刻意保留难度，避免“合成数据 100% 精度”的假象（见 docs/experiment.md）。

## 4. 模型与评估

| 模型 | 说明 |
| --- | --- |
| RandomForest(rf) | 默认模型，200 棵树，`balanced_subsample` 缓解类不平衡 |
| GradientBoosting(gb) | 深度提升树，非线性特征交互 |
| MLP(mlp) | 128-64 两层全连接神经网络(演示“深度学习”路线) |

统一流程：类别特征 One-Hot（容忍未见类别）→ 数值标准化 → 训练 → 测试集评估。

指标：Accuracy、Attack AUC（二元攻击概率 ROC）、逐类 Precision/Recall/F1
（`classification_report`），支持导出文本与 JSON。

## 5. 检测阈值与在线判决

- `detector.FlowDetector`：单条流 → `Detection{verdict, score, attack}`；
- `score = 1 - P(normal)`，`attack = score ≥ threshold`（默认 0.5，可调）：
  - 调低阈值 → 更敏感（漏报↓ 误报↑），适合“宁可多报、由防御层去重”场景；
  - 调高阈值 → 更保守，适合误封代价高的场景。
- 逐类概率保留在响应中，便于上层做更细粒度的策略。

## 6. 防御动作与扩展点

现有动作：告警(`alerts.jsonl` 内存+控制台)、封禁(`blocklist.json`)、
规则导出(`firewall_rules.sh`)、REST 手动封禁。扩展点：

- `defense.DefenseEngine.handle()` 为单一入口，可在其内部插入邮件/Webhook/工单；
- 封禁动作与检测解耦，可替换为真实防火墙/交换机 API 调用；
- 状态均为 JSON 文件，便于与外部 SOAR/SIEM 集成。

## 7. 接口

- **CLI**：`init-demo-data / fetch-nslkdd / train / simulate / serve / dashboard / demo`
- **REST**(stdlib)：`GET /health`、`GET /defense/status`、
  `POST /detect`（41 特征 JSON）、`POST /defense/block`（强制封禁）
- **可视化控制台**(stdlib + 原生前端)：`python -m arkids dashboard`，见 7.1

### 7.1 可视化控制台(Web Dashboard)

控制台在检测/防御内核之上提供一层“实时态势可视化 + 交互管理”，由三个新模块支撑：

- `firewall.FirewallStore`：防火墙规则库(增删/启停/幂等去重)，与自动封禁联动写入，
  统一导出 nftables/iptables 脚本；REST: `GET/POST /api/firewall`、`POST /api/firewall/toggle|delete`、
  `GET /api/firewall/script`；
- `advisor.AIAdvisor`：智能建议两级结构 —— ① `HeuristicAdvisor` 本地可解释规则引擎
  (威胁等级评估/扫描探测/洪泛/误报-漏报平衡/规则同步检查, 输入当前态势快照, 离线可用)；
  ② `LLMAdvisor` 可选在线增强(DeepSeek Chat API, 密钥仅从环境变量/系统凭据库读取, 不入库;
  失败自动回退)。REST: `GET /api/advisor`、`POST /api/advisor/llm`；
- `dashboard.LiveEngine` + `webui/`：后台线程持续回放流量(检测→证据累积→自动封禁→
  防火墙同步), 聚合为“图节点/边 + 事件流 + KPI/趋势 + 威胁等级”快照;
  `webui/` 为纯 HTML/CSS/JS 单页(Canvas 网络动画、攻击日志表、防火墙编辑器、AI 建议面板)。

控制台每 1s 轮询 `/api/snapshot` 渲染, 支持暂停/调速(`POST /api/control`);
默认使用独立状态目录 `run/dashboard` 并干净启动(`--no-reset` 保留跨启动状态),
避免与 `simulate` 的历史封禁状态相互干扰。

## 8. 局限与后续工作

1. 演示数据为合成数据；建议接入 NSL-KDD/CICIDS2017 做正式实验；
2. 特征粒度到“流”，未做会话/图级关联与多步攻击链推理；
3. 未加入对抗样本鲁棒性(文献 2)与模型在线更新；
4. 单机原型，生产化需 Kafka/Spark 流式处理与分布式模型服务。
