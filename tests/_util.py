"""测试辅助: 在仓库 run/ 下创建可写临时目录(兼容沙箱对系统 Temp 的 ACL 限制)。"""
import shutil
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_TMP_ROOT = _REPO / "run" / "_tests"


def make_tmp(name: str) -> str:
    p = _TMP_ROOT / name
    if p.exists():
        shutil.rmtree(str(p), ignore_errors=True)
    p.mkdir(parents=True, exist_ok=True)
    return str(p)


def cleanup_tmp(name: str) -> None:
    p = _TMP_ROOT / name
    if p.exists():
        shutil.rmtree(str(p), ignore_errors=True)
