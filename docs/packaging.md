# 打包与发布说明（ArkIDS）

## 1. 版本与元数据（工程化约定）

- **单一版本源**：`src/arkids/version.py`（`__version__ = "0.3.0"`）。
  `pyproject.toml` 通过 `[tool.setuptools.dynamic] version = {attr=...}` 读取；
  `arkids --version` / `python -m arkids --version`、PyInstaller 版本资源同源。
- **标准元数据**：`pyproject.toml`（PEP 621）：名称、描述、作者、License(MIT)、
  依赖、classifiers、console 入口 `arkids = arkids.cli:main`、src 布局、
  包数据 `arkids/webui/*`。
- **控制台入口**：安装后可直接执行 `arkids`（等价 `python -m arkids`）。

## 2. 产物一览（dist/）

| 产物 | 说明 |
| --- | --- |
| `arkids-0.3.0-py3-none-any.whl` | 标准 Python wheel：`pip install <file>.whl` 后使用 `arkids` 命令 |
| `ArkIDS.exe`（单文件） | PyInstaller 单文件版，内置 webui 与默认演示模型；**双击运行即进入可视化控制台并自动打开浏览器** |
| `ArkIDS/`（目录版） | 目录分发版，冷启动更快、便于 AV 白名单；运行 `ArkIDS\ArkIDS.exe` |
| `ArkIDS-0.3.0-win64.zip` | 目录版打包 zip（含 exe、LICENSE、图标） |

> exe 在无 Python 环境的目标 Windows 机器上直接运行；内置模型为演示数据训练产物，
> 训练真实模型请使用源码版执行 `arkids train --data <NSL-KDD> --out models/xxx.joblib`，
> 再以 `--model` 指定。

## 3. 如何重新打包

```bash
# 一键发布(图标→wheel→单文件exe→目录版→zip)
python scripts/build_release.py

# 或分步
python scripts/make_icon.py              # 重新生成图标 assets/arkids.ico 等
python scripts/make_wheel.py             # 生成 wheel
python -m PyInstaller --noconfirm --clean arkids.spec        # 单文件
python -m PyInstaller --noconfirm --clean arkids_onedir.spec # 目录版
```

## 4. 图标

- 源生成器：`scripts/make_icon.py`（纯标准库绘制盾牌 + 受保护核心；可改配色/图形后重跑）。
- 产物：`assets/arkids.ico`（16/24/32/48/64/128/256 多尺寸，用于 exe 与快捷方式）、
  `assets/arkids.png`（256 预览）、`webui/favicon.ico`（网页标签页）。
- Windows 资源：`assets/version_info.txt`（文件版本 0.3.0、产品名、版权，嵌入 exe）。

## 5. 安装 wheel（开发者/服务器）

```bash
pip install dist/arkids-0.3.0-py3-none-any.whl     # 依赖 numpy/pandas/scikit-learn/joblib
arkids --version                                   # arkids 0.3.0
arkids dashboard --port 8642                       # 可视化控制台
python -m arkids demo                              # 一键演示
```
