"""ArkIDS 版本号单一来源(工程化约定)。

其他模块统一从本文件获取版本:
    - pyproject.toml 通过 setuptools 动态读取 (attr: arkids.version.__version__)
    - `arkids --version` / `python -m arkids --version`
    - PyInstaller 版本资源(assets/version_info.txt, 由 scripts/release_check.py 自动生成)
"""

__version__ = "0.11.4"
VERSION_INFO = (0, 11, 4)

__all__ = ["__version__", "VERSION_INFO"]
