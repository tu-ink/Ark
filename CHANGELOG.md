# 版本历史

## [0.9.0] - 2025

### 深度抓包排错器(区分“权限/驱动/无流量”), 修复“抓不到包”现场定位
- 工具箱新增“抓包排错(深度)”: 检测 Npcap 驱动/管理员权限/tshark 引擎/接口枚举,
  并对 3 个候选接口各做 2s 真实抓包, 分类给出结论:
    * denied   → 权限受限(Npcap 限制非管理员, 需以管理员运行/开启 Allow non-admin)
    * no_device→ 驱动/接口异常(Npcap 与 Wireshark 位数或驱动问题)
    * no_traffic→ 接口无流量(换有流量的网卡, 与 Wireshark 选一致的接口)
    * ok       → 链路可用并提示应使用哪个接口
- 界面可复制排错报告; 提供管理员启动方式提示(源码/打包版命令)
- 实测: 本机“以太网”2s 抓到 6 包(OK), 其它接口 no_traffic —— 印证此前“抓不到”
  多为选到静默接口/权限提示不清
- GET /api/diag/capture?full=1|0、POST /api/diag/elevate
- 测试 34 项通过; 版本 0.9.0

## [0.8.0] - 2025

### 抓包可用性 + 工具按需整合 + 日志页修复
- 自动找“有流量的网卡”: tshark 引擎自动模式会对各接口短时抓包探测, 优先选中流量
  非零的接口, 修复“选了静默网卡抓不到包”; 快照封包窗口 220→500(日志更连续)
- 外部工具“按实际使用”整合: 仅保留并展示 Wireshark(抓包引擎/复核)、010 Editor
  (抓包十六进制复核)、CyberChef(解码/解密); Burp Suite/蚁剑 不再参与自动联动
  (标记 integrated=false, 需要时手动启动), 避免无意义占位
- 修复前端日志页 BUG: 封包/最近封包列表由“每 1s 整表重建”改为“增量追加”
  (消除闪烁、滚动位置重置与数据抖动); 威胁列表按内容变化才刷新
- 测试 33 项通过; 文档/版本 0.8.0

## [0.7.0] - 2025

### 抓包修复 + 外部安全工具联动整合
- 修复“抓包无法使用”: 工具发现扩大到工作区/便携位置(如 D:/deepseek_work/Wireshark、
  <盘>:/Wireshark、cwd 祖先目录); tshark 输出改 UTF-8 容错; 接口名保留完整
  `\Device\NPF_...`; 引擎默认 auto=优先已装 Wireshark/tshark, 否则自研嗅探
- 回放策略: 无显示过滤器时优先内置解析器直读(无子进程更稳); 指定 `-Y` 才走 tshark
- 新增 exttools.py: 自动发现 工作区 Wireshark/Burp Suite/蚁剑/010 Editor/CyberChef
  并一键启动; 抓包文件可送 Wireshark/010 复核; GET /api/ext-tools、POST /api/ext-tools/open
- UI: 工具箱新增“外部工具联动”卡片; 引擎选择支持自动(auto)
- 测试 33 项通过(含外部工具列表端点); 文档/版本 0.7.0

## [0.6.0] - 2025

### 自研抓包引擎: 不再依赖外部抓包工具(Wireshark/tshark/Npcap)
- 新增 `sniffer.py`：内置抓包引擎 —— Windows 原始套接字 + SIO_RCVALL(全部 IPv4
  出入站, 需管理员)/Linux AF_PACKET(需 root), 无需安装任何第三方抓包软件;
  抓到报文经内建解码(RAW 链路 101)并同步落盘自产经典 pcap(101/Ethernet)
- capture 解码扩展: RAW(101) 裸 IP 与 SLL(113) 链路支持; pcapng 文件同样按链路解码
- dashboard 引擎可切换: `--engine sniffer|tshark`(默认 sniffer); 内置引擎界面/自检
  文案与提示同步(自检: 内置引擎/管理员权限为关键项, tshark/Npcap 降为可选)
- UI 数据源条增加引擎选择与说明; 状态与落盘文件在“内置模式”下可用
- 单元测试新增 RAW 解码与自产 pcap 写入回读用例(32 项全部通过)
- 说明: 抓包仍需管理员/root(操作系统安全模型), 但不再要求安装任何抓包工具

## [0.5.0] - 2025

### 前端重构为“工具台”应用壳 + 一体化可用性
- 界面重构为带侧边导航的应用壳(实时总览/封包浏览/威胁与处置/规则与脚本/工具箱/设置)，
  修复问题：部分数据不显示(空态占位与健壮渲染)、表格下拉/滚动异常(固定表头+独立滚动区)、
  按钮尺寸不统一(统一 34px/小按钮 28px)、文字/符号渲染(去除强依赖 emoji、字体栈回退)
- 工具箱·环境自检向导(`GET /api/selfcheck`)：应用/tshark/Npcap/Wireshark/网卡/管理员/
  存储/内置解析器 8 项一键体检 + 诊断报告复制 + 官方下载链接；npcap 检测改为按服务查询
- 工具箱·官方真实样例：联网一键获取 Wireshark 官方仓库样例并自动回放(内置解析)
- 工具箱·数据导出：服务端全量封包/威胁 CSV
- 新增元数据状态：idle/live/replay/replay_done/error 及版本字段；回放完成保留结果可复核
- 设置页：自动联动开关(双处同步)、LLM 说明、停止并清空会话
- 单元测试新增自检结构用例(30 项全部通过)

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
