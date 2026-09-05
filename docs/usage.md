# 使用指南

## 1. 环境

- Python ≥ 3.9（开发验证环境 3.12）
- 依赖：`pip install -r requirements.txt`（numpy / pandas / scikit-learn / joblib）
- 运行命令时把 `src` 加入模块搜索路径：

```powershell
# Windows PowerShell
$env:PYTHONPATH = "$PWD\src"
# Linux / macOS
export PYTHONPATH="$PWD/src"
```

## 2. 命令总览

```text
python -m arkids {init-demo-data|fetch-nslkdd|train|simulate|serve|dashboard|demo} [选项]
```

### 2.1 一键演示 demo

```bash
python -m arkids demo
# = 生成 4000 条演示数据 → 训练 RF → 用 1500 条新样本做“检测+防御”仿真
```

### 2.2 生成演示数据

```bash
python -m arkids init-demo-data --n 4000 --seed 42 --out data/demo_flows.csv
```

### 2.3 训练模型

```bash
# 随机森林(默认)
python -m arkids train --data data/demo_flows.csv --algo rf \
    --out models/arkids_rf.joblib --report run/train_report_rf.txt

# 神经网络(MLP)
python -m arkids train --data data/demo_flows.csv --algo mlp \
    --out models/arkids_mlp.joblib --report run/train_report_mlp.txt
```

输出：控制台报告 + `run/*.txt` 与 `run/*.json`（机器可读指标）。

### 2.4 使用真实 NSL-KDD 数据

```bash
python -m arkids fetch-nslkdd --dir data/nslkdd      # 尽力从镜像下载
# 或手动下载 KDDTrain+.txt / KDDTest+.txt 放入 data/nslkdd/

# 训练: 直接指定 NSL-KDD 文件(自动识别无表头格式)
python -m arkids train --data data/nslkdd/KDDTrain+.txt \
    --algo rf --out models/nslkdd_rf.joblib

# 在 KDDTest+.txt 上做批量“检测+防御”仿真
python -m arkids simulate --data data/nslkdd/KDDTest+.txt \
    --model models/nslkdd_rf.joblib --block-hits 5
```

### 2.5 检测与防御仿真（闭环演示）

```bash
python -m arkids simulate --data data/demo_eval.csv --model models/arkids_rf.joblib \
    --threshold 0.5 --attacker-pool 5 --block-hits 3 --window 60 --limit 1500
```

关键参数：
- `--threshold` 攻击判定阈值（调低更敏感）；
- `--attacker-pool` 攻击源个数（仿真时收敛攻击源以便观察封禁）；
- `--block-hits` 触发封禁的窗口内告警次数；`--window` 证据窗口秒数；
- `--dry-run` 只打印防御动作不写文件；`--speed N` 每秒回放条数（演示节奏）。

### 2.6 REST 检测服务

```bash
python -m arkids serve --model models/arkids_rf.joblib --host 127.0.0.1 --port 8735
```

```bash
curl -s localhost:8735/health
# {"status":"ok","service":"arkids"}

# 用一条真实流特征(41 字段)检测
curl -s -X POST localhost:8735/detect -H "Content-Type: application/json" -d '{
  "features": {
    "duration": 0, "protocol_type": "tcp", "service": "private", "flag": "S0",
    "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0,
    "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
    "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
    "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    "is_host_login": 0, "is_guest_login": 0, "count": 120, "srv_count": 120,
    "serror_rate": 1.0, "srv_serror_rate": 1.0, "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0, "dst_host_count": 200, "dst_host_srv_count": 200,
    "dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0,
    "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0
  }}'
# {"verdict":"dos","score":0.99...,"attack":true,"probs":{...}}

curl -s -X POST localhost:8735/defense/block -H "Content-Type: application/json" \
     -d '{"src_ip":"203.0.113.66"}'
curl -s localhost:8735/defense/status
```

### 2.7 真实流量监控控制台（内嵌 Wireshark/tshark 引擎）

> 本控制台**不构造数据**：只消费本机网卡实时抓包或用户提供的真实抓包文件；
> 无数据源时界面显示“等待真实流量”。

```bash
python -m arkids dashboard --port 8642                    # 打开 http://127.0.0.1:8642
python -m arkids dashboard --interface "以太网"             # 直接对指定网卡抓包
python -m arkids dashboard --pcap capture.pcap             # 回放真实抓包(.pcap/.pcapng)
python -m arkids dashboard --pcap a.pcapng --display-filter "tcp.port==443"
```

界面模块：

| 模块 | 说明 |
| --- | --- |
| 数据源 | “实时抓包”选择本机网卡(tshark `-D`)或“回放文件”上传/选择真实 pcap；支持 tshark 捕获过滤器 `-f` 与显示过滤器 `-Y` |
| 🌐 实时网络拓扑 | 真实主机(私网/公网)连线图：线宽=真实流量、红=命中威胁；包速率/告警速率趋势 |
| 📦 封包浏览 | 实时数据包表(时间/源/目标/协议/端口/TCP标志/长度)，本地搜索 + CSV 导出 |
| ⚠ 威胁与处置 | 60s 流统计启发式检测：TCP SYN 洪泛、端口扫描、高连接速率(可解释证据)；一键“阻断源 IP”→ deny 规则 |
| 🧱 防火墙规则 | deny/allow 规则在线编辑 + nftables/iptables 脚本导出(处置台) |
| 🤖 AI 研判 | 本地规则引擎建议 + (可选)大模型综合研判；密钥见下 |

关键参数：`--auto-block` 开启“检测即自动加 deny 规则”（**默认关闭**，避免误伤真实业务）；
实时抓包保存目录 `run/captures/`(自动落盘真实 pcap)；`--state-dir` 存放防火墙规则等状态。

**Wireshark 联动**：检测到 tshark/Wireshark 后，工具栏显示引擎版本并可一键
“用 Wireshark 打开”当前抓包接口或已保存/加载的真实文件复核。
无 tshark 时：可安装 [Wireshark](https://www.wireshark.org/download.html)(含 Npcap、
以管理员运行) 启用实时抓包；或使用“回放文件”模式(内置解析器直读 .pcap/.pcapng，无需 tshark)。

**在线 LLM 研判（可选）**：设置 `DEEPSEEK_API_KEY`(Windows 系统凭据库
`reasonix:DEEPSEEK_API_KEY` 也会自动读取，密钥不入库)；`ARKIDS_LLM_INSECURE=1` 可关闭
TLS 校验。未配置/失败时自动回退规则引擎。

### 2.8 运行测试

```bash
python -m unittest discover -s tests -v    # 29 项用例
```

## 3. 常见问题

| 现象 | 处理 |
| --- | --- |
| 模型训练较慢 | 设置 `ARKIDS_N_JOBS=4`（多核并行）；数据量大时用 `fetch-nslkdd` 后训练 |
| 想换更真实的评估 | 接入 NSL-KDD/CICIDS2017（第 2.4 节） |
| REST 服务端口被占 | `--port` 换端口 |
| 输出中文乱码 | 设置 `PYTHONIOENCODING=utf-8` |
| 需要打包为可安装包 | 在仓库根添加 `pyproject.toml`（setuptools）后 `pip install -e .` |
