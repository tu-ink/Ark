"""ArkIDS —— 基于人工智能的网络攻击智能检测与防御系统(课程/研究原型项目).

主题: 基于人工智能智能检测防御网络攻击
    - 机器学习检测引擎: 以 NSL-KDD 为标准数据格式(内置可离线复现的演示数据集),
      训练 随机森林 / 多层感知机 等模型, 输出 攻击类别 + 威胁概率。
    - 智能防御联动: 依据检测置信度与滑动时间窗口, 自动执行告警、IP 封禁、
      防火墙规则生成、Webhook 通知等防御动作, 形成“检测→决策→防御→反馈”闭环。

模块划分:
    config     全局常量与路径
    dataset    数据集加载(NSL-KDD)与演示数据合成
    features   特征工程(类别编码 + 数值标准化)
    models     模型训练/评估与持久化
    detector   流式检测引擎(阈值/置信度决策)
    defense    防御执行引擎(封禁、规则、告警)
    firewall   防火墙规则库(在线编辑/脚本导出)
    advisor    AI 智能建议(规则引擎 + 可选 LLM)
    dashboard  可视化控制台服务(实时攻防仿真 + API)
    webui      控制台前端(HTML/CSS/JS)
    simulate   实时流量回放与攻击仿真演示
    server     极简 REST 检测服务(stdlib)
    cli        命令行入口(python -m arkids / arkids)
"""
from .version import __version__, VERSION_INFO  # noqa: F401

__all__ = ["__version__", "VERSION_INFO"]
