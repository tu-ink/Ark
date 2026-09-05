"""数据集: NSL-KDD 标准格式加载器 + 离线可复现的演示数据合成器。

设计说明:
    - 真实研究数据请使用 NSL-KDD(KDDTrain+.txt), 由 fetch-nslkdd 命令从公开
      镜像下载; 加载器按 KDDCup99 的 41 特征 + 1 标签布局解析(该数据集在
      知网收录的多数入侵检测论文中作为标准评测集使用)。
    - 为便于离线运行与单元测试, 提供 generate_demo_flows(): 生成与 NSL-KDD
      同构(同 41 列)的合成流量, 使项目在没有外网/大数据集时依然可端到端跑通;
      特征分布按攻击家族设计了可区分的统计规律(含少量标签噪声), 仅用于演示。
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from .config import (DEMO_ATTACK_NAMES, KDD_FEATURES, LABEL_COL,
                     to_family)

SERVICES = [
    "http", "ftp_data", "smtp", "domain_u", "finger", "auth", "telnet", "ssh",
    "private", "pop_3", "ftp", "ecr_i", "other", "urp_i", "ntp_u", "time",
    "netbios_ns", "bgp", "courier", "csnet_ns", "ctf", "daytime", "discard",
    "imap4", "iso_tsap", "klogin", "kshell", "ldap", "link", "login",
]
FLAGS = ["SF", "REJ", "S0", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "SH", "RSTRH", "OTH"]
NUMERIC_FEATURES = [c for c in KDD_FEATURES if c not in ("protocol_type", "service", "flag")]


def load_kdd_file(path: str | object, family_label: bool = True) -> pd.DataFrame:
    """读取 NSL-KDD 训练/测试文件(无表头, 空白分隔, 42 列)。

    family_label=True 时标签映射为 normal/dos/probe/r2l/u2r/other 家族;
    否则保留原始攻击名。
    """
    path = str(path)
    cols = KDD_FEATURES + [LABEL_COL]
    df = pd.read_csv(
        path,
        sep=r"\s+",
        header=None,
        names=cols,
        encoding="latin-1",
        engine="python",
    )
    df[LABEL_COL] = df[LABEL_COL].str.strip(".").str.lower()
    if family_label:
        df["attack_family"] = df[LABEL_COL].map(lambda s: to_family(s))
        df[LABEL_COL] = df["attack_family"]
    df = df.drop(columns=[c for c in df.columns if c not in KDD_FEATURES + [LABEL_COL]])
    return df


def load_any(path: str) -> pd.DataFrame:
    """自动识别数据文件: 带表头的演示 CSV 或无表头的 NSL-KDD 文件。"""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        head = fh.readline(2048)
    if LABEL_COL in head:                      # 演示/预处理后 CSV(含表头)
        df = pd.read_csv(path)
    else:                                      # 原始 NSL-KDD
        df = load_kdd_file(path)
    return df


# --------------------------------------------------------------------------
# 演示数据合成: 按攻击家族设计可区分的特征统计规律(仅供离线演示与测试)
# --------------------------------------------------------------------------
def _pick(rng: np.random.Generator, seq):
    return seq[int(rng.integers(0, len(seq)))]


def _mk_normal(rng: np.random.Generator, row: dict) -> None:
    row["protocol_type"] = _pick(rng, ["tcp", "tcp", "udp", "icmp"])
    row["service"] = _pick(rng, SERVICES[:16] + ["other"])
    row["flag"] = "SF" if rng.random() < 0.82 else _pick(rng, FLAGS)
    row["duration"] = int(rng.integers(0, 2800))
    row["src_bytes"] = int(rng.integers(0, 5000))
    row["dst_bytes"] = int(rng.integers(0, 8000))
    row["logged_in"] = int(rng.random() < 0.55)
    row["count"] = int(rng.integers(1, 40))
    row["srv_count"] = int(rng.integers(1, 40))
    row["serror_rate"] = float(rng.random() * 0.08)
    row["srv_serror_rate"] = float(rng.random() * 0.08)
    row["same_srv_rate"] = float(0.4 + rng.random() * 0.6)
    row["srv_diff_host_rate"] = float(rng.random() * 0.4)
    row["dst_host_count"] = int(rng.integers(1, 60))
    row["dst_host_srv_count"] = int(rng.integers(1, 60))
    row["dst_host_same_srv_rate"] = float(0.3 + rng.random() * 0.7)
    row["dst_host_diff_srv_rate"] = float(rng.random() * 0.4)
    row["dst_host_same_src_port_rate"] = float(rng.random() * 0.6)
    row["dst_host_srv_diff_host_rate"] = float(rng.random() * 0.2)


def _mk_dos(rng: np.random.Generator, name: str, row: dict) -> None:
    row["duration"] = int(rng.integers(0, 8))
    row["logged_in"] = 0
    if name == "smurf":                        # ICMP 放大: 超高计数 + 单服务
        row["protocol_type"] = "icmp"
        row["service"] = "ecr_i"
        row["flag"] = "SF"
        row["count"] = int(rng.integers(400, 512))
        row["srv_count"] = int(rng.integers(400, 512))
        row["same_srv_rate"] = 1.0
        row["dst_host_srv_count"] = int(rng.integers(100, 255))
        row["dst_host_same_srv_rate"] = 1.0
    else:                                      # neptune / pod / teardrop: SYN 风暴
        row["protocol_type"] = "tcp"
        row["service"] = "private" if name == "neptune" else _pick(rng, ["http", "ftp_data", "private"])
        row["flag"] = "S0" if rng.random() < 0.85 else _pick(rng, ["REJ", "SF"])
        row["count"] = int(rng.integers(60, 511))
        row["srv_count"] = int(rng.integers(60, 511))
        row["serror_rate"] = 1.0 if rng.random() < 0.8 else float(rng.random() * 0.4 + 0.5)
        row["srv_serror_rate"] = row["serror_rate"]
        row["same_srv_rate"] = float(0.5 + rng.random() * 0.5)
        row["dst_host_count"] = int(rng.integers(50, 255))
        row["dst_host_srv_count"] = int(rng.integers(50, 255))
        row["dst_host_same_src_port_rate"] = float(0.5 + rng.random() * 0.5)
    row["src_bytes"] = int(rng.integers(0, 120))
    row["dst_bytes"] = int(rng.integers(0, 1000))


def _mk_probe(rng: np.random.Generator, name: str, row: dict) -> None:
    row["protocol_type"] = "tcp"
    row["service"] = "private" if name == "nmap" else _pick(rng, ["http", "ftp", "smtp", "other"])
    row["flag"] = "SF" if rng.random() < 0.7 else _pick(rng, ["REJ", "S0"])
    row["duration"] = int(rng.integers(0, 120))
    row["logged_in"] = 0
    row["count"] = int(rng.integers(1, 30))
    row["srv_count"] = int(rng.integers(1, 30))
    row["serror_rate"] = float(rng.random() * 0.5)
    row["same_srv_rate"] = float(rng.random() * 0.5)
    row["diff_srv_rate"] = float(rng.random() * 0.6)
    row["srv_diff_host_rate"] = float(0.6 + rng.random() * 0.4)   # 探测: 访问大量不同主机
    row["dst_host_count"] = int(rng.integers(20, 255))
    row["dst_host_srv_count"] = int(rng.integers(1, 20))
    row["dst_host_diff_srv_rate"] = float(0.4 + rng.random() * 0.6)
    row["dst_host_same_src_port_rate"] = float(0.2 + rng.random() * 0.5)
    row["dst_host_srv_diff_host_rate"] = float(0.4 + rng.random() * 0.6)
    row["src_bytes"] = int(rng.integers(0, 300))
    row["dst_bytes"] = int(rng.integers(0, 2000))


def _mk_r2l(rng: np.random.Generator, name: str, row: dict) -> None:
    row["protocol_type"] = "tcp"
    row["service"] = "ftp" if name in ("ftp_write",) else _pick(rng, ["ftp", "telnet", "http", "imap4", "pop_3"])
    row["flag"] = "SF" if rng.random() < 0.75 else _pick(rng, ["REJ", "S0"])
    row["duration"] = int(rng.integers(100, 3000))
    row["logged_in"] = 1
    if name == "guess_passwd":
        row["num_failed_logins"] = int(rng.integers(3, 20))
        row["service"] = "pop_3" if rng.random() < 0.5 else "ftp"
    row["src_bytes"] = int(rng.integers(2000, 500_000))
    row["dst_bytes"] = int(rng.integers(0, 3000))
    row["count"] = int(rng.integers(1, 10))
    row["srv_count"] = int(rng.integers(1, 10))
    row["same_srv_rate"] = float(0.5 + rng.random() * 0.5)
    row["dst_host_same_srv_rate"] = float(0.4 + rng.random() * 0.6)


def _mk_u2r(rng: np.random.Generator, name: str, row: dict) -> None:
    row["protocol_type"] = "tcp"
    row["service"] = "telnet" if rng.random() < 0.6 else _pick(rng, ["ftp", "http", "other"])
    row["flag"] = "SF"
    row["duration"] = int(rng.integers(10, 1500))
    row["logged_in"] = 1
    row["root_shell"] = int(rng.random() < 0.5)
    row["su_attempted"] = int(rng.random() < 0.4)
    row["num_file_creations"] = int(rng.integers(1, 20))
    row["num_shells"] = int(rng.integers(0, 3))
    row["hot"] = int(rng.integers(0, 10))
    row["src_bytes"] = int(rng.integers(500, 20000))
    row["dst_bytes"] = int(rng.integers(100, 3000))


NUMERIC_RANGES = {  # 通用“污染值”采样范围: 特征 -> (min, max)
    "duration": (0, 3000), "src_bytes": (0, 500_000), "dst_bytes": (0, 500_000),
    "hot": (0, 20), "num_failed_logins": (0, 20), "num_compromised": (0, 5),
    "num_root": (0, 5), "num_file_creations": (0, 30), "num_shells": (0, 5),
    "num_access_files": (0, 5), "num_outbound_cmds": (0, 3),
    "count": (0, 511), "srv_count": (0, 511), "dst_host_count": (0, 255),
    "dst_host_srv_count": (0, 255),
}
RATE_RANGES = {  # 比例类特征 -> [0,1]
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
}
FLAG_LIKE = {"land", "wrong_fragment", "urgent", "logged_in", "root_shell",
             "su_attempted", "is_host_login", "is_guest_login"}


def _corrupt_row(row: dict, rng: np.random.Generator, per_row: float) -> None:
    """以 per_row 概率对“整行”做一次特征污染, 模拟真实流量噪声与特征重叠。

    per_row 表示每行发生污染的期望特征比例(同时污染 1 个以上特征, 保留部分信号)。
    """
    if per_row <= 0 or rng.random() > min(1.0, per_row * 8):
        return
    n = max(1, int(rng.integers(0, 6)))  # 污染 1~5 个特征
    keys = list(KDD_FEATURES)
    for _ in range(n):
        c = keys[int(rng.integers(0, len(keys)))]
        row[c] = _value_pool(c, rng)


def _value_pool(col: str, rng: np.random.Generator):
    if col == "protocol_type":
        return ["tcp", "udp", "icmp"][int(rng.integers(0, 3))]
    if col == "service":
        return _pick(rng, SERVICES)
    if col == "flag":
        return _pick(rng, FLAGS)
    if col in FLAG_LIKE:
        return int(rng.integers(0, 2))
    if col in RATE_RANGES:
        return float(rng.random())
    lo, hi = NUMERIC_RANGES.get(col, (0, 511))
    return int(rng.integers(lo, hi + 1))


def _mk_row(rng: np.random.Generator, family: str) -> tuple[dict, str]:
    row: dict = {c: 0 for c in KDD_FEATURES}
    row["protocol_type"], row["service"], row["flag"] = "tcp", "other", "SF"
    if family == "normal":
        _mk_normal(rng, row)
        return row, "normal"
    name = _pick(rng, DEMO_ATTACK_NAMES[family])
    {"dos": _mk_dos, "probe": _mk_probe, "r2l": _mk_r2l, "u2r": _mk_u2r}[family](rng, name, row)
    return row, name


def generate_demo_flows(
    n: int = 4000,
    seed: int = 42,
    attack_ratio: float = 0.62,
    noise: float = 0.03,
    feature_noise: float = 0.06,
    hard_ratio: float = 0.18,
) -> pd.DataFrame:
    """合成与 NSL-KDD 同构的演示流量(n 行, 41 特征 + label)。

    参数:
        attack_ratio    攻击样本占比;
        noise           标签噪声率(随机改判家族, 模拟标注误差);
        feature_noise   特征污染强度(模拟真实流量中的观测噪声);
        hard_ratio      攻击样本中“伪装成正常流量”的比例, 用于模拟
                        NSL-KDD 中 R2L/U2R 等隐蔽攻击 —— 该部分样本仅靠
                        单个流量难以识别, 这也是演示模型无法达到 100% 的
                        主要原因(与文献中 R2L/U2R 检出率偏低的结论一致)。
    """
    rng = np.random.default_rng(seed)
    all_families = ["normal", "dos", "probe", "r2l", "u2r"]
    attack_families = all_families[1:]
    rows, raws = [], []
    for _ in range(n):
        # 1) 按 attack_ratio 抽取家族; noise 以一定概率“改判”家族(标注噪声)。
        fam = attack_families[int(rng.integers(0, len(attack_families)))]
        if rng.random() >= attack_ratio:
            fam = "normal"
        if rng.random() < noise:
            fam = all_families[int(rng.integers(0, len(all_families)))]
        # 2) hard_ratio: 部分攻击样本的流量特征与正常样本高度相似(隐蔽攻击),
        #    模拟 NSL-KDD 中 R2L/U2R 与正常流量难以区分的特点, 形成“硬样本”。
        if fam != "normal" and rng.random() < hard_ratio:
            row, _ = _mk_row(rng, "normal")
            raw = _pick(rng, DEMO_ATTACK_NAMES[fam])
        else:
            row, raw = _mk_row(rng, fam)
        if feature_noise > 0:
            _corrupt_row(row, rng, feature_noise)
        rows.append(row)
        raws.append(raw)  # 原始攻击名或 'normal'
    df = pd.DataFrame(rows, columns=KDD_FEATURES)
    df[LABEL_COL] = [to_family(s) for s in raws]  # 统一到家族级标签
    return df


def save_demo_csv(path: str, n: int = 4000, seed: int = 42) -> str:
    df = generate_demo_flows(n=n, seed=seed)
    df.to_csv(path, index=False)
    return path


# --------------------------------------------------------------------------
# 经典评测数据集下载(尽力而为, 网络不可用时返回 False)
# --------------------------------------------------------------------------
NSLKDD_MIRRORS = [
    "https://raw.githubusercontent.com/defencecybermadness/nsl-kdd/master/KDDTrain+.txt",
    "https://raw.githubusercontent.com/rahulrajpl/nslkdd/master/KDDTrain+.txt",
]


def fetch_nslkdd(dest_dir: str) -> list[str]:
    """尝试从公开镜像下载 NSL-KDD 训练/测试文件。返回实际下载的文件列表。"""
    import urllib.request

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for url in NSLKDD_MIRRORS:
        name = url.rstrip("/").split("/")[-1]
        if name not in ("KDDTrain+.txt", "KDDTest+.txt"):
            continue
        target = dest / name
        if target.exists():
            out.append(str(target))
            continue
        try:
            urllib.request.urlretrieve(url, str(target))  # type: ignore[attr-defined]
            out.append(str(target))
        except Exception:
            continue
    return out
