# -*- coding: utf-8 -*-
"""存储层（database）：用标准库 ``sqlite3`` 持久化统计结果与告警记录。

表结构
------
``stats`` —— 每个时间窗口一行：时间戳、包数、字节数、协议占比、唯一源 IP 数、
SYN 比例、平均包长、pps、bps，以及该窗口的异常分数与是否异常标记。

``alerts`` —— 仅记录被判定为异常的窗口：时间戳、异常分数、阈值、
特征快照（JSON）、是否异常、告警说明。

线程安全
--------
``sqlite3`` 的连接默认禁止跨线程使用。本层以 ``check_same_thread=False``
建立单一连接，并用一把互斥锁串行化所有读写：对「采集线程 + 消费者线程 +
UI 线程」这种低并发写入场景足够，且避免了多连接下的写锁竞争。
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .stats import FEATURE_NAMES, WindowStats

logger = logging.getLogger(__name__)

#: 默认数据库文件名
DEFAULT_DB_PATH = "traffic_monitor.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS stats (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT    NOT NULL,          -- 窗口结束时间 (ISO8601)
    window_start   TEXT,                      -- 窗口开始时间 (ISO8601)
    duration       REAL,                      -- 窗口实际时长（秒）
    packet_count   INTEGER NOT NULL DEFAULT 0,
    byte_count     INTEGER NOT NULL DEFAULT 0,
    tcp_ratio      REAL    NOT NULL DEFAULT 0,
    udp_ratio      REAL    NOT NULL DEFAULT 0,
    icmp_ratio     REAL    NOT NULL DEFAULT 0,
    unique_src_ips INTEGER NOT NULL DEFAULT 0,
    syn_ratio      REAL    NOT NULL DEFAULT 0,
    avg_pkt_len    REAL    NOT NULL DEFAULT 0,
    pps            REAL    NOT NULL DEFAULT 0,
    bps            REAL    NOT NULL DEFAULT 0,
    anomaly_score  REAL,                      -- decision_function 原始分数
    is_anomaly     INTEGER NOT NULL DEFAULT 0,
    top_src_ips    TEXT,                      -- JSON: [["1.2.3.4", 120], ...]
    top_dst_ports  TEXT,                      -- JSON: [[443, 80], ...]
    created_at     TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_stats_ts         ON stats(ts);
CREATE INDEX IF NOT EXISTS idx_stats_is_anomaly ON stats(is_anomaly);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               TEXT    NOT NULL,        -- 告警时间 (ISO8601)
    anomaly_score    REAL    NOT NULL,        -- 异常分数（越低越异常）
    threshold        REAL,                    -- 触发时的判定阈值
    feature_snapshot TEXT,                    -- 特征快照 JSON（含 Top-N）
    is_anomaly       INTEGER NOT NULL DEFAULT 1,
    message          TEXT,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now', 'localtime'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
"""


class TrafficDB:
    """SQLite 持久化封装（打开即自动建表，幂等）。"""

    def __init__(self, path: str = DEFAULT_DB_PATH) -> None:
        self.path = os.path.abspath(path)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        directory = os.path.dirname(self.path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10.0)
        self._conn.row_factory = sqlite3.Row
        self._configure()
        self.init_schema()

    # ------------------------------------------------------------------ #
    # 基础设施
    # ------------------------------------------------------------------ #
    def _configure(self) -> None:
        """设置 WAL 等 PRAGMA，提升并发读与写入吞吐。"""
        assert self._conn is not None
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA busy_timeout=5000")
            self._conn.commit()

    def init_schema(self) -> None:
        """建表与建索引（幂等，可重复调用）。"""
        assert self._conn is not None
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        logger.debug("数据库就绪: %s", self.path)

    def close(self) -> None:
        """关闭连接（可重复调用）。"""
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                except Exception:  # pragma: no cover
                    logger.debug("提交事务失败", exc_info=True)
                self._conn.close()
                self._conn = None

    def __enter__(self) -> "TrafficDB":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # 写入
    # ------------------------------------------------------------------ #
    def _exec_stats(
        self,
        window: WindowStats,
        anomaly_score: Optional[float] = None,
        is_anomaly: bool = False,
    ) -> int:
        """执行统计行 INSERT，**不提交**（事务由调用方控制）。"""
        assert self._conn is not None
        sql = """
            INSERT INTO stats (
                ts, window_start, duration, packet_count, byte_count,
                tcp_ratio, udp_ratio, icmp_ratio, unique_src_ips, syn_ratio,
                avg_pkt_len, pps, bps, anomaly_score, is_anomaly,
                top_src_ips, top_dst_ports
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """
        params = (
            window.end_time.isoformat(timespec="seconds"),
            window.start_time.isoformat(timespec="seconds"),
            round(window.duration, 4),
            window.packet_count,
            window.byte_count,
            window.tcp_ratio,
            window.udp_ratio,
            window.icmp_ratio,
            window.unique_src_ips,
            window.syn_ratio,
            window.avg_pkt_len,
            window.pps,
            window.bps,
            None if anomaly_score is None else float(anomaly_score),
            1 if is_anomaly else 0,
            json.dumps(window.top_src_ips, ensure_ascii=False),
            json.dumps([[str(p), c] for p, c in window.top_dst_ports], ensure_ascii=False),
        )
        cur = self._conn.execute(sql, params)
        return int(cur.lastrowid)

    def insert_stats(
        self,
        window: WindowStats,
        anomaly_score: Optional[float] = None,
        is_anomaly: bool = False,
    ) -> int:
        """写入一个统计窗口（独立事务），返回自增主键 id。"""
        with self._lock:
            rowid = self._exec_stats(window, anomaly_score, is_anomaly)
            self._conn.commit()
            return rowid

    def _exec_alert(
        self,
        ts: datetime,
        anomaly_score: float,
        threshold: Optional[float] = None,
        feature_snapshot: Optional[str] = None,
        message: Optional[str] = None,
        is_anomaly: bool = True,
    ) -> int:
        """执行告警行 INSERT，**不提交**（事务由调用方控制）。"""
        assert self._conn is not None
        sql = """
            INSERT INTO alerts (ts, anomaly_score, threshold, feature_snapshot,
                                is_anomaly, message)
            VALUES (?,?,?,?,?,?)
        """
        with self._lock:
            cur = self._conn.execute(
                sql,
                (
                    ts.isoformat(timespec="seconds"),
                    float(anomaly_score),
                    None if threshold is None else float(threshold),
                    feature_snapshot,
                    int(is_anomaly),
                    message,
                ),
            )
            return int(cur.lastrowid)

    def insert_alert(
        self,
        ts: datetime,
        anomaly_score: float,
        threshold: Optional[float] = None,
        feature_snapshot: Optional[str] = None,
        message: Optional[str] = None,
        is_anomaly: bool = True,
    ) -> int:
        """写入一条告警记录（独立事务），返回自增主键 id。"""
        with self._lock:
            rowid = self._exec_alert(ts, anomaly_score, threshold,
                                     feature_snapshot, message, is_anomaly)
            self._conn.commit()
            return rowid

    def insert_window(
        self,
        window: WindowStats,
        anomaly_score: Optional[float] = None,
        is_anomaly: bool = False,
        threshold: Optional[float] = None,
        message: Optional[str] = None,
    ) -> Tuple[int, Optional[int]]:
        """写入统计行，并在异常时追加告警行。

        Returns
        -------
        (stats_id, alert_id)
            ``alert_id`` 在非异常时为 ``None``。
        """
        # 统计行与告警行放在同一个事务里提交：异常窗口由 2 次 commit 降为 1 次
        with self._lock:
            stats_id = self._exec_stats(window, anomaly_score, is_anomaly)
            alert_id = None
            if is_anomaly and anomaly_score is not None:
                alert_id = self._exec_alert(
                    ts=window.end_time,
                    anomaly_score=anomaly_score,
                    threshold=threshold,
                    feature_snapshot=window.to_json(),
                    message=message,
                    is_anomaly=True,
                )
            self._conn.commit()
        return stats_id, alert_id

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def query_stats(
        self,
        limit: int = 20,
        only_anomaly: bool = False,
        since: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """查询最近若干条统计记录（按时间倒序）。"""
        assert self._conn is not None
        sql = "SELECT * FROM stats"
        where: List[str] = []
        params: List[Any] = []
        if only_anomaly:
            where.append("is_anomaly = 1")
        if since:
            where.append("ts >= ?")
            params.append(since)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def query_alerts(self, limit: int = 20, since: Optional[str] = None) -> List[Dict[str, Any]]:
        """查询最近若干条告警记录（按时间倒序）。"""
        assert self._conn is not None
        sql = "SELECT * FROM alerts"
        params: List[Any] = []
        if since:
            sql += " WHERE ts >= ?"
            params.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def summary(self) -> Dict[str, Any]:
        """返回数据库概览：窗口数、异常窗口数、告警数、时间范围、累计流量。"""
        assert self._conn is not None
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*)                          AS windows,
                       COALESCE(SUM(is_anomaly), 0)      AS anomaly_windows,
                       MIN(ts)                           AS first_ts,
                       MAX(ts)                           AS last_ts,
                       AVG(anomaly_score)                AS avg_score,
                       COALESCE(SUM(packet_count), 0)    AS total_packets,
                       COALESCE(SUM(byte_count), 0)      AS total_bytes
                FROM stats
                """
            ).fetchone()
            alerts = self._conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()
        result: Dict[str, Any] = dict(row) if row else {}
        result["alerts"] = int(alerts["c"]) if alerts else 0
        return result

    def fetch_feature_matrix(self, limit: int = 1000) -> Tuple[List[str], List[List[float]]]:
        """导出最近若干窗口的特征矩阵，供离线分析或重新训练使用。"""
        rows = self.query_stats(limit=limit)
        matrix = [[float(r[name] or 0.0) for name in FEATURE_NAMES] for r in reversed(rows)]
        return list(FEATURE_NAMES), matrix

    def export_stats_csv(self, csv_path: str, limit: Optional[int] = None) -> int:
        """把 stats 表导出为 CSV（UTF-8-BOM，Excel 可直接打开），返回行数。"""
        import csv

        assert self._conn is not None
        sql = "SELECT * FROM stats ORDER BY id"
        if limit:
            sql += " LIMIT {0}".format(int(limit))
        with self._lock:
            cur = self._conn.execute(sql)
            columns = [d[0] for d in cur.description]
            rows = cur.fetchall()
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(columns)
            writer.writerows([tuple(r) for r in rows])
        logger.info("已导出 %d 行到 %s", len(rows), csv_path)
        return len(rows)


# ---------------------------------------------------------------------- #
# 控制台输出辅助（供 --show-stats / --show-alerts 使用）
# ---------------------------------------------------------------------- #
def format_recent(db: TrafficDB, limit: int = 10, alerts: bool = False) -> List[str]:
    """返回用于打印的文本行列表（不直接 print，便于测试与 UI 复用）。"""
    lines: List[str] = []
    if alerts:
        rows = db.query_alerts(limit=limit)
        if not rows:
            return ["暂无告警记录。"]
        lines.append("{0:<20} {1:>10} {2:>10}  说明".format("时间", "异常分数", "阈值"))
        lines.append("-" * 72)
        for r in rows:
            lines.append("{0:<20} {1:>10.4f} {2:>10}  {3}".format(
                r["ts"], r["anomaly_score"],
                "N/A" if r["threshold"] is None else "{0:.4f}".format(r["threshold"]),
                r["message"] or "",
            ))
        return lines

    rows = db.query_stats(limit=limit)
    if not rows:
        return ["暂无统计数据。"]
    lines.append("{0:<20} {1:>8} {2:>10} {3:>6} {4:>6} {5:>10} {6:>8}".format(
        "时间", "包数", "字节", "TCP%", "UDP%", "唯一源IP", "分数"))
    lines.append("-" * 80)
    for r in rows:
        lines.append("{0:<20} {1:>8} {2:>10} {3:>6.1f} {4:>6.1f} {5:>10} {6:>8}".format(
            r["ts"], r["packet_count"], r["byte_count"],
            (r["tcp_ratio"] or 0) * 100, (r["udp_ratio"] or 0) * 100,
            r["unique_src_ips"],
            "N/A" if r["anomaly_score"] is None else "{0:.4f}".format(r["anomaly_score"]),
        ))
    return lines


def print_recent(db: TrafficDB, limit: int = 10, alerts: bool = False) -> None:
    """在控制台打印最近若干条统计记录或告警记录。"""
    print("\n".join(format_recent(db, limit=limit, alerts=alerts)))


def _self_test() -> int:  # pragma: no cover - 手工自检入口
    """``python -m netflow.database`` 自检：写入一个窗口并读回。"""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    db = TrafficDB("traffic_monitor_selftest.db")
    now = datetime.now()
    window = WindowStats(now, now, 5.0, 1200, 850000, 936, 240, 24, 144, 45,
                         top_src_ips=[("10.0.0.1", 300)], top_dst_ports=[(443, 500)])
    sid = db.insert_stats(window, anomaly_score=-0.05)
    aid = db.insert_alert(now, -0.25, threshold=-0.1,
                          feature_snapshot=window.to_json(), message="测试告警")
    print("写入 stats id={0}, alert id={1}".format(sid, aid))
    print_recent(db, limit=5)
    print_recent(db, limit=5, alerts=True)
    print("概览:", db.summary())
    db.close()
    os.remove(db.path)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_test())
