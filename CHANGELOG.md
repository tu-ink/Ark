# 版本历史

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
