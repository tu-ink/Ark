# 基于人工智能的网络攻击智能检测与防御系统（ArkIDS）

> 主题：**基于人工智能智能检测防御网络攻击**
> 本项目为基于该主题的课程/研究原型项目：使用机器学习对网络流量进行**在线检测与分类**，
> 并联动**智能防御模块**自动完成告警、封禁、防火墙规则生成等闭环动作。

ArkIDS（`arkids`）以标准评测集 **NSL-KDD** 的数据模式（41 维流量特征 + 标签）为输入格式，
训练 **随机森林 / 多层感知机** 等分类模型，把每条网络流判定为 `normal / dos / probe / r2l / u2r`
五类之一，并输出"是攻击"的置信概率；防御引擎依据**置信度阈值 + 滑动时间窗口证据累积**，
对持续发起攻击的源 IP 自动封禁（nftables/iptables 规则、封禁清单、Webhook 通知均可导出/扩展）。

- 全部核心依赖仅 `numpy / pandas / scikit-learn / joblib`，REST 服务与仿真仅用 Python 标准库；
- 内置 **可离线复现的合成演示数据集**（与 NSL-KDD 同构），无网也可一键跑通全流程；
- 提供 `demo` 一键命令：造数据 → 训练 → 攻击仿真 → 防御联动演示。

## 快速开始

```bash
# 1) 安装依赖(Python >= 3.9)
pip install -r requirements.txt

# 2) 一键演示: 生成演示数据 + 训练 + 仿真闭环
python -m arkids demo            # 需要 PYTHONPATH=src (或安装为包后直接运行)

# 3) 分步执行
python -m arkids init-demo-data                          # 生成演示数据
python -m arkids train --data data/demo_flows.csv        # 训练 RF 模型
python -m arkids simulate --model models/arkids_rf.joblib # 检测+防御仿真
python -m arkids serve --port 8735                       # REST 检测服务
python -m arkids dashboard --port 8642                   # 可视化控制台(Web)
```

> 提示：从仓库根目录运行时先设置 `PYTHONPATH=src`（Windows PowerShell：
> `$env:PYTHONPATH="$PWD\src"`）；或 `pip install -e .`（需在仓库根添加 pyproject/setup，
> 详见 docs/usage.md）。

## 目录结构

```
Ark/
├── src/arkids/            # 核心包
│   ├── config.py          #   特征模式/攻击家族映射/路径
│   ├── dataset.py         #   NSL-KDD 加载器 + 演示数据合成器
│   ├── features.py        #   特征工程(OneHot + 标准化)
│   ├── models.py          #   模型训练/评估/持久化(RF/GB/MLP)
│   ├── detector.py        #   流式检测引擎(置信度决策)
│   ├── defense.py         #   智能防御引擎(证据累积/封禁/规则)
│   ├── firewall.py        #   防火墙规则库(在线编辑/脚本导出)
│   ├── advisor.py         #   AI 智能建议(规则引擎 + 可选 LLM)
│   ├── dashboard.py       #   可视化控制台服务(实时攻防仿真 + API)
│   ├── webui/             #   前端静态资源(HTML/CSS/JS, 原生无框架)
│   ├── simulate.py        #   攻击仿真与检测-防御回放
│   ├── server.py          #   极简 REST 服务(stdlib)
│   └── cli.py             #   命令行入口
├── tests/                 # 单元测试(unittest, 20 项全部通过)
├── docs/                  # 文献调研/设计/使用/实验文档
├── data/                  # 数据(自动生成或下载, 已 gitignore)
├── models/                # 训练产物(已 gitignore)
└── run/                   # 运行产物: 告警/封禁/规则(已 gitignore)
```

## 可视化控制台（Web）

```bash
python -m arkids dashboard --model models/arkids_rf.joblib --port 8642
# 浏览器打开 http://127.0.0.1:8642
```

控制台以深色安防风格单页呈现，包含：

- **🌐 实时攻防网络**：Canvas 动画绘制“攻击源(203.0.113.x) → 业务服务器”与
  “内网用户 → 服务器”的实时流量关系，攻击边红色脉冲、自动封禁源红色叉号闪烁，
  下方为每秒流量/封禁趋势小图，顶栏实时威胁等级与 KPI；
- **📋 攻击日志**：检测事件流水(时间/源/目标/判决/置信度/动作)，支持按攻击类型过滤；
- **🧱 防火墙规则编辑器**：在线新增/启停/删除 deny·allow 规则，实时导出
  nftables/iptables 脚本预览；
- **🤖 AI 智能建议**：内置离线规则引擎持续给出可解释处置建议（依据/置信度/建议动作）；
  若本机配置 `DEEPSEEK_API_KEY`（或 Windows 凭据库中 `reasonix:DEEPSEEK_API_KEY`），
  可一键调用在线大模型生成综合研判（失败自动回退规则引擎，密钥绝不入库）。

控制台默认使用独立的 `run/dashboard` 状态目录并“干净启动”（`--no-reset` 可保留跨启动
封禁/规则）；顶部按钮可暂停回放或调节事件速率（20~160/s）。

## 核心结果（合成演示数据集，4000 条，70/30 划分）

| 模型 | Accuracy | Attack AUC | Macro-F1 | 攻击 Precision | 攻击 Recall |
| --- | --- | --- | --- | --- | --- |
| RandomForest | 0.8975 | 0.9143 | 0.9041 | 1.0000 | 0.8358 |
| MLP(128-64)  | 0.8775 | — | 0.8830 | — | 0.8358 |

**检测-防御闭环仿真**（全新 1500 条样本、5 个攻击源）：
攻击检出率 0.835、精确率 0.995、Accuracy 0.899；仿真期间产生 746 条告警，
5 个攻击源全部在滑动窗口证据累积后被自动封禁，正常主机误封为 0。

> ⚠️ 演示数据为**合成数据**，指标仅用于演示流水线，不代表真实网络环境性能；
> 复现真实评测请使用 NSL-KDD（`python -m arkids fetch-nslkdd` 或手动放置
> `KDDTrain+.txt`/`KDDTest+.txt` 后以 `--data` 指定，详见 docs/usage.md）。
> 合成数据中刻意保留了约 18% 与正常流量高度相似的"隐蔽攻击"样本，用于模拟
> 文献中 R2L/U2R 类攻击检出率偏低的真实难点（可解释性见 docs/experiment.md）。

## REST 接口示例

```bash
curl -s localhost:8735/health
# {"status": "ok", "service": "arkids"}

curl -s -X POST localhost:8735/detect -H "Content-Type: application/json" \
  -d '{"features": {"duration": 0, "protocol_type": "tcp", "service": "private",
       "flag": "S0", "src_bytes": 0, "dst_bytes": 0, "count": 120, ...41 个特征...}}'
# {"verdict":"dos","score":0.97,"attack":true,"probs":{...}}

curl -s -X POST localhost:8735/defense/block -H "Content-Type: application/json" \
  -d '{"src_ip": "203.0.113.66"}'          # 管理台强制封禁
```

## 快速入门文档

- [文献调研与选题报告（知网检索）](docs/literature_review.md)
- [系统设计说明](docs/design.md)
- [使用指南](docs/usage.md)
- [实验结果与分析](docs/experiment.md)

## 技术要点（对应主题关键词"智能检测 + 智能防御"）

1. **AI 检测**：特征工程（类别 One-Hot + 数值标准化）→ 监督分类（RF/GB/MLP）→
   输出**类别 + 攻击概率**，支持按业务调节置信度阈值权衡误报/漏报；
2. **智能防御**：单条告警不立即封禁，而是统计同源 IP 在时间窗口内的告警证据，
   达到阈值后联动封禁并导出防火墙规则（nftables/iptables），降低误杀；
3. **AI 智能建议**：内置可解释规则引擎持续输出处置建议（离线可用），可选接入
   大模型生成综合研判，辅助运维决策；
4. **可落地接口**：REST 检测服务、Web 可视化控制台（实时攻防网络/防火墙在线编辑/
   攻击日志/AI 建议面板）、封禁清单 JSON、规则脚本输出，便于对接 SIEM/防火墙。

## 项目背景与致谢

选题与设计参考了知网收录及公开期刊的多篇相关论文（详见
[docs/literature_review.md](docs/literature_review.md)），如
肖建平等《基于深度学习的网络入侵检测研究综述》（数据与计算发展前沿, 2021）、
余正飞等《面向网络空间防御的对抗机器学习研究综述》（自动化学报, 2022）等；
评测数据模式基于 NSL-KDD 标准格式。

## License

MIT（详见 LICENSE）。
