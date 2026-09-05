"""全局配置: 数据模式常量、攻击类别映射、路径约定。"""
from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------- 路径约定
SRC_DIR = Path(__file__).resolve().parent            # src/arkids
PROJECT_ROOT = SRC_DIR.parent.parent                 # 仓库根目录
DATA_DIR = PROJECT_ROOT / "data"                     # 原始数据(已 gitignore)
MODELS_DIR = PROJECT_ROOT / "models"                 # 训练产物(*.joblib)
RUN_DIR = PROJECT_ROOT / "run"                       # 运行期产物: 告警/封禁/日志
REPORT_DIR = PROJECT_ROOT / "docs" / "experiment"    # 实验报告输出


def ensure_dirs() -> None:
    """确保所有输出目录存在。"""
    for d in (DATA_DIR, MODELS_DIR, RUN_DIR, REPORT_DIR):
        d.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------- NSL-KDD 模式
# 41 个流量特征列名(与 NSL-KDD / KDDCup99 约定一致, 第 42 列为标签)
KDD_FEATURES: list[str] = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]
LABEL_COL = "label"
assert len(KDD_FEATURES) == 41

# 原始攻击名 -> 攻击家族(标准五分类)
ATTACK_FAMILY: dict[str, str] = {
    # DoS 拒绝服务
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "apache2": "dos", "processtable": "dos",
    "udpstorm": "dos", "mailbomb": "dos",
    # Probe 探测扫描
    "ipsweep": "probe", "nmap": "probe", "portsweep": "probe", "satan": "probe",
    "mscan": "probe", "saint": "probe",
    # R2L 远程到本地
    "ftp_write": "r2l", "guess_passwd": "r2l", "imap": "r2l", "multihop": "r2l",
    "phf": "r2l", "spy": "r2l", "warezclient": "r2l", "warezmaster": "r2l",
    "sendmail": "r2l", "named": "r2l", "snmpgetattack": "r2l", "snmpguess": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "httptunnel": "r2l",
    # U2R 本地提权
    "buffer_overflow": "u2r", "loadmodule": "u2r", "perl": "u2r",
    "rootkit": "u2r", "xterm": "u2r", "ps": "u2r", "sqlattack": "u2r",
}
CLASSES = ["normal", "dos", "probe", "r2l", "u2r"]   # 检测输出类别顺序

# 合成演示数据用的小型“攻击名”池(保证覆盖 5 大类)
DEMO_ATTACK_NAMES = {
    "dos": ["neptune", "smurf", "pod", "teardrop"],
    "probe": ["satan", "nmap", "portsweep", "ipsweep"],
    "r2l": ["guess_passwd", "warezclient", "imap", "ftp_write"],
    "u2r": ["buffer_overflow", "rootkit", "perl"],
}


def to_family(label: str) -> str:
    """原始标签 -> 攻击家族; 'normal' 保持原样, 未知攻击归入 'other'。"""
    label = str(label).strip().lower()
    if label == "normal":
        return "normal"
    return ATTACK_FAMILY.get(label, "other")


def is_attack(label: str) -> bool:
    return to_family(label) != "normal"
