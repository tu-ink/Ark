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
- 提供 `demo` 一键命令：造数据 → 训练 → 攻击仿真 → 防御联动演示；
- **工程化**：版本单一来源、标准 pyproject 元数据、console 入口 `arkids`、
  wheel / PyInstaller exe 打包、应用图标与 favicon（详见 docs/packaging.md）。

**当前版本：v0.11.2** · License: MIT · [CHANGELOG](CHANGELOG.md)

## 快速开始

### A. 直接使用（免装 Python）—— 打包版

发布产物在 `dist/`（或 GitHub Releases），当前版本 **0.11.2**：
- `ArkIDS-0.11.2-win64-portable.zip`（**唯一推荐形态**）：目录版，解压后双击
  `ArkIDS\ArkIDS.exe` 即打开原生桌面 GUI（tkinter，无需浏览器）；
- `arkids-0.11.2-py3-none-any.whl`：pip 安装包（`pip install arkids-0.11.2-py3-none-any.whl`）；
- `VERSION.txt`：发布包版本标定（版本号/构建时间/Git 提交/内嵌抓包库）。

> **不再提供单文件 exe**：单文件版运行时要把内置组件自解压到临时目录，在受限权限
> 或杀软拦截环境下会“双击无反应/闪退”（实测 `Failed to extract MSVCP140.dll`）。
> 目录版直接把依赖放在同目录，稳定可用；发布脚本会自动清理历史单文件产物。

### B. 源码 / 开发者模式（Python ≥ 3.9）

```bash
# 1) 安装依赖或直接安装 wheel
pip install -r requirements.txt
# 或: pip install dist/arkids-0.11.2-py3-none-any.whl   (安装后可直接用 arkids 命令)

# 2) 一键演示: 生成演示数据 + 训练 + 仿真闭环
python -m arkids demo            # 需要 PYTHONPATH=src (或安装为包后直接运行)

# 3) 分步执行
python -m arkids init-demo-data                          # 生成演示数据
python -m arkids train --data data/demo_flows.csv        # 训练 RF 模型
python -m arkids simulate --model models/arkids_rf.joblib # 检测+防御仿真
python -m arkids gui                                     # 桌面 GUI(主界面)
python -m arkids selftest                                # 运行/核心功能自检(9 项)
python -m arkids serve --port 8735                       # REST 检测服务
python -m arkids dashboard --port 8642                   # 可视化控制台(Web, 可选)
```

> 提示：从仓库根目录运行时先设置 `PYTHONPATH=src`（Windows PowerShell：
> `$env:PYTHONPATH="$PWD\src"`），或安装为包后直接用 `arkids` 命令（见 docs/packaging.md）。

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
│   ├── capture.py         #   真实流量采集: tshark 引擎 + pcap/pcapng 解析 + 启发式检测
│   ├── scapylib.py        #   Python 抓包库引擎(scapy + Npcap, 默认首选)
│   ├── sniffer.py         #   自研抓包引擎: 原始套接字抓包 + pcap 落盘(免第三方工具)
│   ├── firewall.py        #   防火墙规则库(在线编辑/脚本导出)
│   ├── advisor.py         #   AI 智能建议(规则引擎 + 可选 LLM)
│   ├── exttools.py        #   工具箱: 外部工具探测/按需调用(Wireshark、010、CyberChef)
│   ├── selftest.py        #   运行/核心功能自检(打包后可直接 selftest)
│   ├── gui.py             #   原生桌面 GUI(tkinter, 主界面)
│   ├── dashboard.py       #   可视化控制台服务(可选, Web)
│   ├── webui/             #   前端静态资源(HTML/CSS/JS, 原生无框架)
│   ├── simulate.py        #   离线攻击仿真(仅算法实验/评测用)
│   ├── server.py          #   极简 REST 服务(stdlib)
│   ├── cli.py             #   命令行入口
│   ├── _vendor/           #   内嵌 scapy(不入库, 由 scripts/fetch_scapy.py 获取)
│   └── version.py         #   版本号单一来源
├── assets/                # 应用图标(.ico/.png/favicon)与 exe 版本资源
├── scripts/               # 图标/打包/发布门禁(release_check|_make_release_zips|fetch_scapy)
├── tests/                 # 单元测试(unittest, 37 项全部通过)
├── docs/                  # 文献调研/设计/使用/实验/打包文档
├── data/                  # 数据(自动生成或下载, 已 gitignore)
├── models/                # 训练产物(已 gitignore)
├── run/                   # 运行产物: 告警/封禁/规则(已 gitignore)
├── dist/                  # 打包产物: wheel / ArkIDS.exe / win64 zip(已 gitignore)
├── pyproject.toml         # PEP 621 工程元数据 + 入口 + 包数据
├── arkids.spec            # PyInstaller 单文件版打包配置
├── arkids_onedir.spec     # PyInstaller 目录版打包配置
├── CHANGELOG.md           # 版本历史
└── LICENSE                # MIT
```

## 真实流量监控（桌面 GUI 为主界面，Web 控制台为可选）

> 主界面是**原生桌面 GUI**（`arkids gui`，打包版双击 `ArkIDS.exe`）：实时总览（真实攻防
> 拓扑与速率趋势）、封包浏览、威胁与处置、防火墙规则在线编辑、工具箱·排错，共 5 个页签。
> 下面这段 Web 控制台为兼容保留（`arkids dashboard`），能力与 GUI 一致。

> 数据真实性原则：**不生成、不播放任何仿真/构造流量**。只消费两种真实来源：
> ① 本机网卡实时抓包；② 用户提供的真实抓包文件(.pcap/.pcapng)。未选择数据源时显示
> “等待真实流量”，而不是演示假数据。

```bash
python -m arkids dashboard --port 8642                  # 打开 http://127.0.0.1:8642
python -m arkids dashboard --pcap capture.pcap          # 直接回放真实抓包文件
python -m arkids dashboard --interface "以太网"          # 直接对指定网卡抓包
```

- **抓包引擎（默认 Python 抓包库）**：`--engine auto` 按 **scapy → tshark → 自研原始套接字**
  顺序自动择优：
  1. **scapy**（内嵌 2.7.0，经 Npcap 的 `wpcap.dll`）——默认首选，跨网卡/跨链路类型最稳；
  2. **tshark**（装了 Wireshark 时可用，兼容 4.x 的纳秒精度 pcap）；
  3. **自研 `SnifferCapture`**（Windows `SIO_RCVALL` / Linux `AF_PACKET`，免第三方工具兜底）。
  Windows 实时抓包需要 Npcap（随 Wireshark 安装）；若安装时勾选“限制为管理员”，
  需右键以管理员身份运行（GUI 工具箱提供“以管理员运行 (UAC)”按钮）。
  抓不到包时用**工具箱 → 深度抓包排错**，会明确区分 `denied`(权限) / `no_device`(驱动) /
  `no_traffic`(接口无流量) / `ok`，而不是笼统报错。原始报文可同步落盘 .pcap 并用本机
  Wireshark/010 复核（工具箱按需调用，见 `docs/third_party_tools.md`）。
- **🌐 实时网络拓扑**：从真实数据包聚合的“内网主机(私网) ↔ 外网主机(公网)”连线图，
  线宽按真实包量、红色连线表示命中威胁的主机，附包速率/告警速率趋势；
- **封包浏览**：实时数据包表(时间/源/目标/协议/端口/TCP标志/长度)，支持搜索与 CSV 导出；
- **威胁与处置**：基于 60s 流统计的启发式检测(SYN 洪泛/端口扫描/高连接速率)给出可解释证据，
  支持“阻断源 IP”一键加入 deny 规则(默认**不**自动封禁，误伤可控)；
- **🤖 AI 研判**：离线规则引擎给出处置建议；配置 `DEEPSEEK_API_KEY` 后可调用大模型对
  真实态势做综合研判（密钥不入库、失败自动回退）。

> 内置实时抓包只需【管理员身份运行】(Windows 原始套接字/Linux root), **无需安装任何
> 抓包软件**；非管理员时仍可用“回放抓包文件”模式加载真实 .pcap/.pcapng(内置解析器)。
> 离线算法实验(NSL-KDD/合成演示 + 训练/评估)属于另一条研究链路，请使用
> `arkids train|simulate` 命令，与本监控模式分离。

## 工程化与发布（版本标定 / 发布门禁）

- **版本号单一来源**：`src/arkids/version.py`（`__version__`），`pyproject.toml` 动态读取，
  exe 版本资源（`assets/version_info.txt`）由发布脚本自动生成，避免多份版本号漂移；
- **发布门禁（一条命令跑完）**：

  ```bash
  python scripts/release_check.py     # 版本资源 → 单元测试 → 打包 → exe 自检 → GUI 冒烟 → 便携包
  ```

  门禁按顺序执行 6 步，任一步失败即中止：① 生成版本资源；② `tests/` 单元测试（37 项）；
  ③ PyInstaller 目录版打包；④ **打包产物核心功能自检**（`ArkIDS.exe selftest`，9 项：
  版本/环境、scapy 抓包库、pcap 解析、pcapng 解析、防火墙、启发式检测、抓包权限排错、
  REST 接口、GUI 构建）；⑤ GUI 启动冒烟（`ArkIDS.exe gui` 自动开关）；⑥ 生成
  `dist/ArkIDS-<版本>-win64-portable.zip` + wheel + `VERSION.txt`，并清理历史版本产物。
  日志落在 `dist/release_logs/`。
- **内嵌库不入库**：`src/arkids/_vendor/scapy/`（GPL-2.0，约 9 MB）不提交到 Git，
  克隆后执行 `python scripts/fetch_scapy.py` 从 PyPI 拉取（发布门禁会在缺失时自动获取）；
- **仅发布目录版**：`ArkIDS-<版本>-win64-portable.zip`；
- **推送说明**：本机到 `github.com:443` 不稳定时，可用 `run/_push_all.py`（GitHub Git Data
  API 通道，令牌取自 Windows 凭据管理器）完成推送，效果与 `git push` 一致。

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
- [打包与发布说明（icon / wheel / exe）](docs/packaging.md)
- [外部工具调研与来源核验（GitHub）](docs/third_party_tools.md)

## 技术要点（对应主题关键词"智能检测 + 智能防御"）

1. **AI 检测**：特征工程（类别 One-Hot + 数值标准化）→ 监督分类（RF/GB/MLP）→
   输出**类别 + 攻击概率**，支持按业务调节置信度阈值权衡误报/漏报；
2. **智能防御**：单条告警不立即封禁，而是统计同源 IP 在时间窗口内的告警证据，
   达到阈值后联动封禁并导出防火墙规则（nftables/iptables），降低误杀；
3. **AI 智能建议**：内置可解释规则引擎持续输出处置建议（离线可用），可选接入
   大模型生成综合研判，辅助运维决策；
4. **可落地接口**：原生桌面 GUI（实时攻防网络/封包浏览/威胁处置/防火墙在线编辑/AI 建议）
   与可选 Web 控制台、REST 检测服务、封禁清单 JSON、规则脚本输出，便于对接 SIEM/防火墙。

## 项目背景与致谢

选题与设计参考了知网收录及公开期刊的多篇相关论文（详见
[docs/literature_review.md](docs/literature_review.md)），如
肖建平等《基于深度学习的网络入侵检测研究综述》（数据与计算发展前沿, 2021）、
余正飞等《面向网络空间防御的对抗机器学习研究综述》（自动化学报, 2022）等；
评测数据模式基于 NSL-KDD 标准格式。

## License

MIT（详见 LICENSE）。
