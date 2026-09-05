# 外部工具调研与来源核验（GitHub）

> 目的：补齐"真实流量采集/解析"所需能力。结论先行——
> **本项目未把第三方抓包源码整体并入仓库**，而是：核验来源后用官方真实样例验证了
> 自研 pcap/pcapng 解析器；实时抓包驱动保留为运行时可选依赖(Wireshark/tshark)；
> 代码层面参考下列开源项目的公开格式与行为，许可证与出处均记录如下。

## 1. GitHub 检索到的相关项目

| 项目 | 官方地址 | 许可证 | 用途 | 安全核验记录 |
| --- | --- | --- | --- | --- |
| Wireshark / tshark | https://github.com/wireshark/wireshark（官方, 同步自 gitlab.com/wireshark/wireshark） | GPL-2.0 | 实时抓包/解码引擎；本项目优先调用其 CLI(tshark) | 官方组织托管；以 `-F pcap -w -` 原始字节流驱动，避免解析其内部格式 |
| Npcap | https://github.com/nmap/npcap（Nmap 项目官方） | GPL-2.0 自例外 | Windows 抓包驱动/库（用户态无法替代） | 官方仓库、签名驱动；**不并入仓库**（内核驱动需官方安装器安装） |
| Scapy | https://github.com/secdev/scapy | GPL-2.0 | Python 抓包/构造/解析库 | 官方仓库；GPL 传染、体积大，**未并入** |
| dpkt | https://github.com/kbandla/dpkt | BSD-3-Clause | Python 快速 pcap/pcapng 解析 | 官方仓库、BSD 宽松；作为**实现对照**参考，未拷贝其代码 |
| pyshark | https://github.com/KimiNewt/pyshark | MIT | tshark 封装 | 需 tshark；未并入 |

## 2. 决策矩阵

| 能力 | 方案 | 理由 |
| --- | --- | --- |
| .pcap 解析(无 tshark) | 自研 `RawPcapReader`(src/arkids/capture.py) | 纯标准库、几十行、已单测 |
| **.pcapng 解析(无 tshark)** | 自研 `RawPcapngReader` | pcapng 为 Wireshark 默认格式；参照 dpkt/规范 自行实现，规避 GPL/依赖负担 |
| 实时抓包(Windows) | 调用官方 tshark(运行时检测) | 抓包需要 Npcap **内核驱动**，任何纯源码方案都无法替代；驱动须用官方安装器 |
| 一键复核 | 打开已装的 Wireshark GUI | 原生 GUI 不可 iframe 内嵌；提供“打开 Wireshark”联动而非伪造内嵌 |

## 3. 真实样例验证（来源：Wireshark 官方仓库 test/captures）

下载自 `gitlab.com/wireshark/wireshark/-/raw/master/test/captures/`
（与 github.com/wireshark/wireshark 同源、官方发布），**均为真实抓包**，仅存放于
`run/samples/`(不入库)，用于端到端验证：

| 文件 | 说明 | 自研解析器结果 |
| --- | --- | --- |
| dhcp.pcapng | 真实 DHCP(DISCOVER→ACK) | 4 包解析正确(0.0.0.0:68 → 255.255.255.255:67, UDP) |
| dhcp_big_endian.pcapng | 大端序 pcapng 变体 | 4 包解析正确(与 tshark 打开结果一致) |
| comments.pcapng | 带注释块 + IPv6(MLD) | 5 包；注释块被安全跳过, IPv6 地址解析 |

Dashboard 实测：`LiveMonitor.start_pcap(dhcp.pcapng)` → 快照 packets=4、节点正常。

## 4. 如何在你的环境启用“实时抓包”（无法用源码替代的部分）

1. 从官方渠道安装 **Npcap**：https://npcap.com/（或 Wireshark 安装包内包含）；
2. 安装 **Wireshark**（含 tshark）：https://www.wireshark.org/download.html；
3. 以管理员运行 ArkIDS，选择网卡开始抓包；控制台会显示 tshark 版本并可“用 Wireshark 打开”。
> 核验安装文件哈希后安装；不要运行任何第三方打包的抓包驱动。
