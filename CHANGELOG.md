# 版本历史

## [0.4.0] - 2025

### 新增：真实文件解析能力增强(无 tshark 也可用)
- 内置 `RawPcapngReader`：纯标准库增量解析 **pcapng**(Wireshark 默认格式)，支持
  SHB/IDB/EPB/SPB、if_tsresol/if_tsoffset、大端/小端序、注释等其它块安全跳过
- 无 tshark 的回放模式自动识别 pcap/pcapng 并分发解析器
- 用 Wireshark 官方仓库 **真实抓包样例**验证(dhcp.pcapng 4 包、大端序变体、
  含注释+IPv6 样例)——来源与核验见 docs/third_party_tools.md
- 单元测试新增 pcapng 增量/分块/端到端回放用例(29 项全部通过)
- 外部工具调研文档(docs/third_party_tools.md)：scapy/dpkt/Npcap/Wireshark
  官方来源、许可证与“为何不整体并入源码”的说明

## [0.3.0] - 2025

### 重大变更：可视化控制台改为“真实流量监控”(不再构造/播放仿真数据)
- 新增 `capture.py`：内嵌 Wireshark/tshark 引擎 —— 实时抓包以原始 pcap 字节管道
  (`tshark -F pcap -w -`)驱动，内建解析器增量解码并同步落盘真实 .pcap；
  支持真实 .pcap/.pcapng 回放、捕获过滤器(`-f`)与显示过滤器(`-Y`)、Wireshark GUI 一键打开
- 无 tshark 时内置经典 .pcap 解析器兜底(离线文件回放仍可用真实数据)
- 实时启发式检测(60s 流统计)：TCP SYN 洪泛 / 端口扫描 / 高连接速率，输出可解释证据
- 交互重构：数据源(实时抓包/回放文件)双模式、接口选择与刷新、封包浏览+搜索+CSV 导出、
  威胁一键“阻断源 IP”处置、自动联动 deny 默认关闭(避免误伤真实业务)
- dashboard 不再依赖训练模型/合成回放；离线算法评测保留在 `train`/`simulate`(实验链路)
- 单元测试新增解析/检测/服务端到端用例，共 26 项全部通过

### 其它
- 版本升至 0.3.0(版本资源/图标/README/打包文档同步)

## [0.2.0] - 2025

### 新增
- 可视化控制台(Web Dashboard)：实时攻防网络 Canvas 动画、威胁等级/KPI、每秒流量与封禁趋势
- 攻击日志面板(按攻击类型过滤)、防火墙规则在线编辑器(增删/启停/脚本预览)
- AI 智能建议：离线可解释规则引擎 + 可选 DeepSeek 大模型增强(密钥不入库、失败自动回退)
- 工程化：pyproject.toml(标准元数据/console 入口/data files)、单一版本源 version.py、
  `--version`、图标(assets/arkids.ico 16~256 多尺寸)、favicon
- 打包：PyInstaller 单文件/目录版 exe(含前端与默认模型, 双击进入控制台并自动开浏览器)、
  wheel 构建脚本

### 变更
- `python -m arkids demo|dashboard|simulate` 等命令行为不变；新增 `dashboard` 命令
- 控制台默认使用独立状态目录 run/dashboard 并“干净启动”(--no-reset 保留)

### 修复
- 打包版入口改为 scripts/entry.py(绝对导入), 修复 frozen 环境相对导入错误

## [0.1.0] - 2025
- 首个可运行版本：NSL-KDD 兼容数据集/演示数据、RF/GB/MLP 五分类检测、置信度阈值判决、
  证据累积式自动封禁与规则导出、攻击仿真闭环、REST 服务、文档与 13 项单元测试
