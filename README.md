# 基于 Isolation Forest 的网络流量监测系统

一个**纯 Python、无 Web 依赖**的网络流量监测应用：实时抓包 → 固定窗口多维统计 →
Isolation Forest 异常评分 → SQLite 持久化 → **全屏 TUI 仪表盘 / 纯文本**双形态输出。

界面使用标准库自研的 ANSI 全屏终端界面，**不使用** Flask / Django / ECharts /
Bootstrap 等任何 Web 技术，也不依赖第三方 TUI 库（Windows 的 CPython 不带 curses）。

---

## 1. 快速开始

```bash
python -m pip install -r requirements.txt   # ① 安装依赖（只需一次）
python main.py --demo                       # ② 跑起来，其余全部自动完成
```

Windows 也可以直接双击 **`run.bat`**（无参数即进入演示模式）。

`--demo` 会自动完成三件事，**不需要管理员权限、不需要 Npcap、不需要数据集**：

1. 找不到 `sample.pcap` 时自动生成示例流量（16 秒正常 + 5 秒 SYN 洪泛）；
2. 找不到 `model.joblib` 时自动用合成 BENIGN 流量训练**引导模型**；
3. 以 1 倍速回放示例 pcap，并在界面上实时展示统计与告警。

实测输出（可复现，随机种子固定）：5 个窗口里 3 个正常窗口零告警、2 个 SYN 洪泛窗口
全部告警。

> 引导模型由**合成流量**训练，只用于跑通链路与演示。正式使用请按 1.3 用真实
> CIC-IDS2017 数据重新训练；加 `--no-auto-train` 可关闭自动训练。

### 1.2 实时监测

```bash
python main.py --list-ifaces                 # 先看有哪些网卡

# Linux / macOS（需要 root 或 CAP_NET_RAW）
sudo python main.py -i eth0 -w 5

# Windows：以管理员身份打开终端，或右键 run.bat「以管理员身份运行」
python main.py -i "以太网" -w 5
```

`Ctrl+C` 优雅退出：先排空队列、输出最后一个窗口，再打印运行统计
（总包数、丢包数、异常次数等）。

### 1.3 用真实数据集训练

```bash
python -m netflow.train_model --csv data/MachineLearningCVE/*.csv --out model.joblib
```

---

## 2. 界面说明

### 2.1 全屏 TUI 仪表盘（默认）

启动后自动进入全屏仪表盘（终端不支持 ANSI 或输出被重定向时自动降级为纯文本）：

```
+ NetFlow Monitor · Isolation Forest ---------------------------------------- 网卡 eth0 · 21:48:30 +
| 状态: * 采集中   运行 00:00:00   队列 0/0   丢包 0 (0.00%)   窗口 12   告警 3                    |
+- 窗口统计（最近 5 秒） ------------------------++- 异常评分 -------------------------------------+
| 包数              2,077 包速率        415.4 pps|| 当前分数        -0.2000 判定阈值        +0.0000|
| 字节           625.0 KB 字节速率     125.0 KB/s|| 判定结果           异常 距阈值          -0.2000|
| 唯一源 IP            40 平均包长          308 B|| 趋势     @@@@@@@@@                             |
| SYN 比例          0.000 采样时刻       21:48:30|| 累计告警           3 次                        |
+------------------------------------------------++------------------------------------------------+
+- 协议与标志位分布 -------------------------------------------------------------------------------+
| TCP        69% ######################################################------------------------    |
| UDP        23% ##################------------------------------------------------------------    |
| ICMP        3% ##----------------------------------------------------------------------------    |
| SYN      0.000 ------------------------------------------------------------------------------    |
+--------------------------------------------------------------------------------------------------+
+- Top 源 IP ------------------------------------++- Top 目的端口 ---------------------------------+
| 192.168.10.21                             75   || 443                                      535   |
+------------------------------------------------++------------------------------------------------+
+- 最近告警（共 3 条） ----------------------------------------------------------------------------+
| 21:48:30    -0.2000  包    2,077  唯一源IP      40  SYN 0.00                                     |
+--------------------------------------------------------------------------------------------------+
| q 退出   p 暂停/继续   r 清空历史   ? 帮助                                                        |
+--------------------------------------------------------------------------------------------------+
```

**快捷键**

| 按键 | 作用 |
| --- | --- |
| `q` / `Ctrl+C` | 优雅退出（先排空队列，再输出最后一个窗口） |
| `p` | 暂停 / 继续界面刷新 |
| `r` | 清空趋势与告警历史（不影响数据库） |
| `?` / `h` | 显示 / 隐藏帮助页 |

**绘制风格**：`--ui-style ascii`（默认，兼容性最好）或 `--ui-style unicode`
（使用制表符与方块字符，需终端字体支持）。

### 2.2 纯文本模式

`--ui plain`，或在输出被重定向 / 终端不支持 ANSI 时自动启用。每完成一个窗口打印一行：

```
[2026-09-22 21:47:18] 包数: 1997, 字节: 579691, TCP: 70%, UDP: 26%, ICMP: 4%, 唯一源IP: 40, SYN比例: 0.00, 异常分数: 0.0989
    Top源IP: 192.168.10.37(75), ... | Top目的端口: 80(535), 443(525), ...
[ALERT] 异常流量 detected! 分数: -0.0349 (阈值: -0.0000)
```

界面模式由 `--ui auto|tui|plain` 控制，默认 `auto`。

---

## 3. 环境要求

### 3.1 Python 依赖

| 依赖 | 版本 | 用途 |
| --- | --- | --- |
| Python | 3.8+ | 运行环境（开发验证于 3.12） |
| scapy | >= 2.5.0 | 报文捕获（AsyncSniffer）与 pcap 读写 |
| pandas / numpy | >= 1.3 / 1.21 | 流聚合、窗口统计、特征计算 |
| scikit-learn | >= 1.0 | Isolation Forest |
| joblib | >= 1.1 | 模型序列化 |

`sqlite3`、`threading`、`queue`、`argparse`、`logging`、`ctypes`、`msvcrt`/`termios`
等全部来自标准库，界面不需要任何额外依赖。

### 3.2 抓包权限

* **Windows**：安装 [Npcap](https://npcap.com/)（勾选 "WinPcap API-compatible Mode"），
  并以**管理员身份**运行；否则 `AsyncSniffer` 会因权限不足失败。
* **Linux**：`sudo` 运行，或授予能力：
  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
  ```
* **拿不到权限时**：用 `python main.py --demo` 回放示例 pcap，功能完全一致。

### 3.3 中文输出

程序输出为 UTF-8。若在 Windows 上重定向到文件出现乱码：

```bash
set PYTHONIOENCODING=utf-8      # CMD
$env:PYTHONIOENCODING="utf-8"   # PowerShell
```

---

## 4. 项目结构（分层设计）

```
netflow_monitor/
├── main.py                     # 程序入口（转发到 netflow.cli）
├── requirements.txt            # 依赖清单
├── pyproject.toml              # 打包元数据 + netflow-monitor 控制台命令
├── config.example.json         # 示例配置文件
├── run.bat                     # Windows 一键启动（无参数 = 演示模式）
├── README.md
├── 重构说明.md                  # 本次重构的改动清单与优化数据
│
├── netflow/                    # ★ 主包
│   ├── __init__.py             # 包说明与版本号
│   ├── config.py               # 配置层：默认值 → 配置文件 → 命令行 三级合并
│   ├── logs.py                 # 日志层：控制台 / 文件 / 内存环形缓冲
│   ├── capture.py              # 采集层：AsyncSniffer + BPF + 有界队列（含 pcap 回放）
│   ├── stats.py                # 统计层：消费者线程 + 时间窗口聚合 + 10 维特征
│   ├── database.py             # 存储层：SQLite（stats / alerts 两张表）
│   ├── model.py                # 检测层：Isolation Forest 评分与阈值判定
│   ├── sample.py               # 示例流量生成（正常 + SYN 洪泛）
│   ├── pipeline.py             # 编排层：把各层串成一条监测流水线
│   ├── cli.py                  # 入口层：参数解析、辅助命令、主流程调度
│   ├── train_model.py          # 向后兼容薄壳（训练逻辑已移入 training/）
│   ├── training/               # ★ 训练层（由原 train_model.py 拆分）
│   │   ├── __init__.py         # 包导出
│   │   ├── __main__.py         # python -m netflow.training 入口
│   │   ├── schema.py           # CIC-IDS2017 列名常量与必需列
│   │   ├── dataset.py          # CSV 分块读取、表头清洗、时间戳解析
│   │   ├── features.py         # 窗口聚合 / 逐流近似两种特征构建模式
│   │   ├── synthetic.py        # 合成正常流量生成
│   │   ├── options.py          # 训练参数与命令行
│   │   └── trainer.py          # 训练主流程 + 引导模型
│   └── ui/                     # 表现层
│       ├── __init__.py         # 包导出
│       ├── base.py             # 界面基类 + 工厂（auto/tui/plain 自动选择）
│       ├── ansi.py             # ANSI 控制、显示宽度计算（中文按 2 列）
│       ├── keys.py             # 跨平台非阻塞按键读取（msvcrt / termios）
│       ├── state.py            # 线程安全的界面状态容器
│       ├── widgets.py          # 控件库：面板、条形图、迷你趋势图、各分区
│       ├── dashboard.py        # ★ 全屏 TUI 仪表盘（布局编排与交互）
│       └── plain.py            # 纯文本逐行输出
│
├── tools/
│   └── make_sample_pcap.py     # 命令行工具：生成示例 pcap
└── tests/                      # 单元测试（按被测层次分文件，共 29 项）
    ├── __init__.py
    ├── helpers.py              # 报文桩、窗口构造、临时目录、日志静默
    ├── test_stats.py
    ├── test_database.py
    ├── test_model.py
    ├── test_config.py
    └── test_ui.py
```

### 依赖方向

```
ui  →  pipeline  →  { capture, stats, model, database }
                          ↑
                       config / logs
```

严格单向，不允许反向依赖：

* **采集层**只负责把包搬进队列，不解析、不落库、不打印；
* **统计层**只负责把包聚合成窗口；
* **检测层**只负责给窗口打分；
* **存储层**只负责读写 SQLite；
* **界面层**只读状态容器，业务线程只写状态容器，二者通过锁解耦，
  界面卡顿不会影响采集与统计。

因此替换任意一层（SQLite → PostgreSQL、TUI → 别的界面）都不需要改动其他层。

---

## 5. 各层要点

### 5.1 采集层 `netflow/capture.py`

* `AsyncSniffer` 在独立线程抓包，`prn` 回调**只做「计数 + 入队」**；
* BPF 过滤器在内核态先行过滤，降低用户态开销；
* 有界队列 `Queue(maxsize=10000)`，队满 **drop-tail**（丢新包并计数），
  保证抓包线程永不被下游拖慢；丢包日志按每 5000 个限流一次；
* `--packet-limit` 通过 Scapy 的 `stop_filter` 实现，避免在抓包线程内 join 自身导致死锁；
* 支持 `--replay` 回放 pcap（按报文时间戳限速），用于离线演示与可复现实验。

### 5.2 统计层 `netflow/stats.py`

消费者线程按固定时间窗口聚合，输出 10 维特征（顺序由 `FEATURE_NAMES` 单点定义）：

| # | 特征 | 含义 |
| --- | --- | --- |
| 1 | `packet_count` | 窗口内总包数 |
| 2 | `byte_count` | 窗口内总字节数（优先取 IP 层长度） |
| 3–5 | `tcp_ratio` / `udp_ratio` / `icmp_ratio` | 各协议包数占比 |
| 6 | `unique_src_ips` | 唯一源 IP 数（扫描类异常的关键指标） |
| 7 | `syn_ratio` | SYN 包数 / 总包数 |
| 8 | `avg_pkt_len` | `byte_count / packet_count` |
| 9 | `pps` | 包/秒（按窗口**实际时长**计算） |
| 10 | `bps` | **字节**/秒（非比特；乘 8 得 bit/s） |

同时记录 Top-5 源 IP 与目的端口。为防扫描/DDoS 撑爆内存，单窗口最多维护 20 万个
不同键，超限则截断 Top-N 统计（总包数仍准确）。

### 5.3 存储层 `netflow/database.py`

```sql
-- stats:  id, ts, window_start, duration, packet_count, byte_count,
--         tcp_ratio, udp_ratio, icmp_ratio, unique_src_ips, syn_ratio,
--         avg_pkt_len, pps, bps, anomaly_score, is_anomaly,
--         top_src_ips(JSON), top_dst_ports(JSON), created_at
-- alerts: id, ts, anomaly_score, threshold, feature_snapshot(JSON),
--         is_anomaly, message, created_at
```

WAL 模式 + 单连接加锁，适配「采集线程 + 消费者线程 + UI 线程」的低并发写入。

### 5.4 检测层 `netflow/model.py`

* 加载 `model.joblib`（支持「模型 + 标准化器 + 阈值 + 元信息」字典包，也兼容裸估计器）；
* 对每个窗口调用 `decision_function`，**分数越低越异常**；
* `score < threshold` 即判定为异常，写 `alerts` 表并在界面高亮；
* 模型缺失时默认降级为「只统计、不检测」（`--strict-model` 可改为直接退出）。

### 5.5 表现层 `netflow/ui/`

* `ansi.py`：ANSI 转义、光标控制、**显示宽度计算**（中文按 2 列，保证表格对齐）、
  Windows 下通过 `ctypes` 开启 VT 模式；
* `keys.py`：Windows 用 `msvcrt`、POSIX 用 `termios`+`select`，进入时切 cbreak、
  退出时完整还原终端属性；
* `state.py`：线程安全状态容器，写入方是消费者线程，读取方是渲染循环；
* `dashboard.py`：`render_dashboard()` 是**纯函数**（快照 + 终端尺寸 → 定宽文本行），
  因此 UI 排版可以被单元测试断言；
* `plain.py`：重定向 / 老终端下的逐行输出。

---

## 6. 数据集与模型训练

### 6.1 获取 CIC-IDS2017

1. 官网：<https://www.unb.ca/cic/datasets/ids-2017.html>（Kaggle 亦有镜像）
2. 下载 `MachineLearningCVE` 压缩包（约 200 MB），解压得到 8 个 CSV：
   `Monday-WorkingHours.pcap_ISCX.csv` … `Friday-WorkingHours.pcap_ISCX.csv`，
   其中 `Wednesday-workingHours.pcap_ISCX.csv` 等文件同时含 `BENIGN` 与攻击样本。
3. 训练时**只取 `Label == BENIGN` 的行**（脚本自动过滤）。

### 6.2 训练

```bash
python -m netflow.train_model --csv data/MachineLearningCVE/*.csv --out model.joblib
```

常用参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--csv` | — | 一个或多个 CSV，支持通配符 |
| `--synthetic` | 关 | 无数据集时用合成 BENIGN 流量兜底 |
| `--window` | 5 | 窗口长度，**必须与 `main.py -w` 一致** |
| `--n-estimators` | 200 | 树的数量 |
| `--contamination` | 0.01 | 预期异常比例，决定 sklearn 自带的阈值零点 |
| `--n-jobs` | 1 | 并行度；受限环境（禁止命名管道）下不要设 `-1` |
| `--threshold` | `auto` | `auto` = sklearn 校准点；也可给固定值如 `-0.1` |
| `--clip-quantile` | 无 | 如 `0.999`，裁剪极端值 |
| `--keep-csv` | 无 | 导出特征矩阵，便于检查域偏移 |
| `--max-rows` | 无 | 限制读取行数，便于快速试跑 |

### 6.3 特征域对齐（关键设计）

实时系统输出的是「5 秒**窗口级**聚合特征」，而 CIC-IDS2017 的 CSV 是「单条**流级**
特征」。直接混用会产生严重域偏移，因此训练脚本分两种模式：

* **窗口聚合模式（优先）**：CSV 含 `Timestamp`、`Source IP` 等列时，先按同样的
  5 秒窗口聚合流，再计算与 `stats.py` **完全一致**的 10 维特征，训练与推理同源；
* **逐流近似模式（退化）**：官方 `MachineLearningCVE` 目录的 CSV 不含时间戳/源 IP，
  此时把每条流当作一个窗口，并做如下近似（**论文中必须说明**）：
  `tcp/udp/icmp_ratio` 由单条流的 Protocol 二值化（0/1）；
  `unique_src_ips` 恒为 1（该维不携带信息）；
  `pps`/`bps` 直接取 `Flow Packets/s`、`Flow Bytes/s`。

特征映射表：

| 实时特征 | CIC-IDS2017 来源列 |
| --- | --- |
| `packet_count` | `Total Fwd Packets + Total Backward Packets` |
| `byte_count` | `Total Length of Fwd Packets + Total Length of Bwd Packets` |
| `tcp/udp/icmp_ratio` | `Protocol`（6 / 17 / 1） |
| `unique_src_ips` | `Source IP` 去重计数（仅窗口模式） |
| `syn_ratio` | `SYN Flag Count / 包数` |
| `avg_pkt_len` / `pps` / `bps` | 由上述列派生 |

训练结束会打印**特征统计表**（min / median / max），务必与实时输出的量级比对；
量级差 1~2 个数量级即说明存在域偏移，需要重新标定窗口长度或特征口径。

### 6.4 无数据集时的替代方案

```bash
python -m netflow.train_model --synthetic --synthetic-hours 1 --synthetic-out data/synthetic.csv
```

> 合成数据仅用于打通程序链路与演示，**不可用于论文中的检测效果论证**。

---

## 7. 运行参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `-i/--iface` | Scapy 默认网卡 | 监听网卡名 |
| `--bpf` | `tcp or udp or icmp` | BPF 过滤器 |
| `-w/--window` | 5.0 | 统计窗口（秒） |
| `-d/--db` | `traffic_monitor.db` | 数据库路径 |
| `-m/--model` | `model.joblib` | 模型路径 |
| `--threshold` | 模型内保存值 | 异常判定阈值 |
| `--queue-size` | 10000 | 有界队列容量 |
| `--top-n` | 5 | Top-N 源 IP / 目的端口 |
| `--duration` | 无 | 运行 N 秒后自动停止 |
| `--packet-limit` | 无 | 采集 N 个包后自动停止 |
| `--demo` | 关 | 演示模式：自动准备示例 pcap 并回放 |
| `--replay` / `--replay-speed` | 无 / 1.0 | 回放 pcap；`0` = 不限速（仅压力测试） |
| `--no-auto-train` | 关 | 关闭「模型缺失时自动训练引导模型」 |
| `--strict-model` | 关 | 模型缺失时直接退出 |
| `--ui` / `--ui-style` | auto / ascii | 界面模式与绘制风格 |
| `--refresh` / `--history` | 0.5 / 60 | 刷新间隔、趋势保留窗口数 |
| `-c/--config` | 无 | 加载 JSON 配置文件 |
| `--log-level` / `--log-file` | INFO / 无 | 日志级别与文件（UTF-8） |
| `--list-ifaces` | — | 列出可用网卡后退出 |
| `--show-stats N` / `--show-alerts N` | — | 查询最近 N 条记录后退出 |
| `--export-csv PATH` | — | 导出 stats 表为 CSV 后退出 |
| `--make-sample PATH` | — | 生成示例 pcap 后退出 |

### 配置文件

命令行优先级高于配置文件，配置文件高于内置默认值：

```bash
cp config.example.json config.json
python main.py --config config.json -i eth0 -w 3   # -w 3 覆盖文件中的 window
```

---

## 8. 数据查询

```bash
python main.py --show-stats 20        # 最近 20 个窗口
python main.py --show-alerts 20       # 最近 20 条告警
python main.py --export-csv stats.csv # 导出为 CSV（UTF-8-BOM，Excel 可直接打开）
```

也可以直接用 `sqlite3`：

```sql
-- 最近 10 个异常窗口
SELECT ts, anomaly_score, packet_count, unique_src_ips, syn_ratio
FROM stats WHERE is_anomaly = 1 ORDER BY id DESC LIMIT 10;

-- 按小时统计平均包速率与异常次数
SELECT substr(ts, 1, 13) AS hour,
       ROUND(AVG(pps), 1)  AS avg_pps,
       SUM(is_anomaly)     AS anomalies
FROM stats GROUP BY hour ORDER BY hour;

-- 查看告警的特征快照（含 Top-5 源 IP 与目的端口）
SELECT ts, anomaly_score, feature_snapshot FROM alerts ORDER BY id DESC LIMIT 5;
```

---

## 9. 检测效果说明（重要）

以下数据来自实测：合成 BENIGN 数据训练（`contamination=0.03`，`n_estimators=200`），
再用自建 pcap 回放（3 个正常窗口 + 2 个 SYN 洪泛窗口）。

### 9.1 回放实测

| 窗口类型 | 关键特征 | 异常分数 | 判定 |
| --- | --- | --- | --- |
| 正常 ×3 | ~2000 包/5s，唯一源 IP 40，SYN 0.00 | 0.0989 / 0.1047 / 0.0992 | 正常 |
| SYN 洪泛 ×2 | ~4000 包/5s，唯一源 IP 3150/4653，SYN 0.89/1.00 | -0.0105 / -0.0349 | **告警** |

阈值 0.0000（sklearn 校准点）下：**2 个洪泛窗口全部检出，3 个正常窗口零误报**。

### 9.2 阈值标定

`decision_function` 的零点由训练时的 `contamination` 决定，训练脚本会打印标定表：

| 目标误报率 | 对应阈值（示例） | 说明 |
| --- | --- | --- |
| P0.1% | -0.0585 | 极保守，几乎不告警 |
| P0.5% | -0.0155 | 极保守 |
| **P1%** | **0.0000** | **与 `contamination` 一致（`--threshold auto`）** |
| P2% | 0.0690 | 较灵敏 |
| P5% | 0.1356 | 误报偏多 |

> **为什么默认阈值不是 -0.1？** 实测 `-0.1` 约等于正常分数分布的 P0.1，
> 比 `contamination` 声明的误报率严格约一个数量级，实战中几乎不告警。
> 需要保守策略时显式指定 `--threshold -0.1` 即可。

### 9.3 两个必须了解的算法局限

定向诊断（构造单个特征极端异常的样本）结果：

| 样本 | 分数 | 低于该分数的训练样本占比 |
| --- | --- | --- |
| 正常中位窗口 | 0.3096 | 100.00% |
| 回放正常窗口 | 0.1836 | 14.72% |
| 回放 SYN 洪泛 | 0.0586 | 1.39% |
| 构造的**极端** SYN 洪泛（20 万源 IP、4 万 pps） | -0.0513 | **仅 0.28%** |
| 仅 `syn_ratio=1.0` 异常，其余正常 | 0.2268 | 28.33% |
| 仅 `unique_src_ips=5000` 异常，其余正常 | 0.2388 | 37.78% |

1. **分数饱和**：即使把攻击放大到正常流量的上百倍，分数也只降到 -0.05。
   原因是孤立森林的分割阈值取自节点内训练数据的取值范围，样本一旦完全落在范围
   之外，路径长度就不再随「超出多少」而缩短。
2. **特征稀释**：10 维特征中只有 1 维异常时，其余 9 维正常会显著拉长路径长度，
   分数几乎落在正常分布中心——高维孤立森林的典型弱点。

### 9.4 使用建议

* 阈值按**可接受的误报率**标定（训练脚本每次都会打印标定表），不要固定套用经验值；
* 训练数据的特征量级必须与实时输出对齐（用 `--keep-csv` 导出后比对）；
* 不要把孤立森林的分数当作唯一判据，工程上建议再叠加**逐特征阈值规则**
  （例如 `syn_ratio > 0.8` 且 `unique_src_ips > 500` 直接告警）。

---

## 10. 测试

```bash
python -m unittest discover -s tests -v     # 29 项，约 1 秒
python tests/test_netflow.py                # 也可以直接运行
```

覆盖范围：配置三级合并与校验、窗口聚合与特征向量、SQLite 读写与导出、
模型评分方向与阈值判定、TUI 渲染的**定宽约束**（含中文宽度与 ANSI 颜色）、
格式化辅助函数。

各模块也带 `__main__` 自检入口：

```bash
python -m netflow.capture           # Scapy 版本与可用网卡
python -m netflow.stats             # 窗口聚合与输出格式
python -m netflow.database          # 建库、写入、查询
python -m netflow.model             # 现场训练最小模型并评分
python -m netflow.sample            # 生成示例 pcap
python -m netflow.ui.dashboard      # 渲染一帧仪表盘（纯文本，便于查看排版）
python -m netflow.ui.ansi           # 中文显示宽度与补齐效果
```

---

## 11. 常见问题

| 现象 | 原因与处理 |
| --- | --- |
| `未检测到 Scapy` | 未安装依赖，执行 `python -m pip install -r requirements.txt` |
| 抓不到包 / 启动即失败 | 权限不足（Windows 需管理员 + Npcap；Linux 需 sudo），或网卡名不对（`--list-ifaces`） |
| 提示 `未找到模型文件，异常检测已禁用` | 会自动训练引导模型；若被 `--no-auto-train` 关闭，请先运行 `train_model` |
| 界面是一堆乱码控制字符 | 终端不支持 ANSI：用 `--ui plain`，或改用 Windows Terminal |
| 重定向到文件后没有界面 | 属预期行为：非 TTY 时自动降级为纯文本（`--ui tui` 可强制） |
| 表格错位 | 终端字体把中文渲染成 1 列宽；改用等宽 CJK 字体，或用 `--ui plain` |
| 丢包数持续增长 | 增大 `--queue-size`，收窄 `--bpf`，或调大 `-w` 窗口 |
| 全是告警 / 从不告警 | 阈值与数据不匹配：比对训练时打印的特征统计表，按标定表调整 `--threshold` |
| 训练报 `Permission denied`（命名管道） | 受限环境禁止创建管道：不要用 `--n-jobs -1`，保持默认单进程 |
| 中文乱码 | 重定向前设置 `PYTHONIOENCODING=utf-8` |

---

## 12. 已知限制与后续改进

* 孤立森林的分数饱和与特征稀释问题（见 9.3），后续可引入滑动基线做分数排序，
  或在检测层之上叠加逐特征规则；
* 目前为单机单网卡采集，后续可通过多实例 + 集中式存储扩展为分布式采集；
* 概念漂移尚未处理，后续可加入周期性重训与漂移检测；
* 未解析加密流量（TLS 1.3 / QUIC）的载荷特征，仅使用流级统计特征；
* 界面为终端 UI，如需图形化展示应另行扩展表现层（本层已是可插拔设计）。
