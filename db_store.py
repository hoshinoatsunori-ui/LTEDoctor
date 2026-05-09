"""
db_store.py
SQLite 中間ストア。全ログを統一スキーマに格納する。
"""

import sqlite3
import logging
from datetime import datetime
from typing import Optional
from chipset_parser import ChipsetRecord
from at_parser import AtRecord

logger = logging.getLogger(__name__)

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS chipset_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dbv_rel_sec     REAL,
    dbv_abs_ts      TEXT,
    chip_tick_us    INTEGER,
    pid             INTEGER,
    level           TEXT,
    level_int       INTEGER,
    message         TEXT,
    source_file     TEXT,
    source_line     INTEGER,
    module          TEXT,
    fsm_name        TEXT,
    fsm_next_state  TEXT,
    is_boot_anchor  INTEGER DEFAULT 0,
    is_at_corr_anchor INTEGER DEFAULT 0,
    utc_ts_est      TEXT,
    align_confidence TEXT
);

CREATE TABLE IF NOT EXISTS at_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    abs_ts          TEXT,
    rel_ms          INTEGER,
    direction       TEXT,
    raw_text        TEXT,
    is_command      INTEGER DEFAULT 0,
    is_response     INTEGER DEFAULT 0,
    is_urc          INTEGER DEFAULT 0,
    is_ok           INTEGER DEFAULT 0,
    is_error        INTEGER DEFAULT 0,
    error_code      TEXT,
    is_anchor_candidate INTEGER DEFAULT 0,
    utc_ts_est      TEXT,
    align_confidence TEXT
);

CREATE TABLE IF NOT EXISTS align_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT,
    log_type    TEXT,
    offset_s    REAL,
    confidence  TEXT,
    anchor_count INTEGER,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS pcap_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    frame_no        INTEGER,
    utc_ts          TEXT,
    src_ip          TEXT,
    dst_ip          TEXT,
    protocol        TEXT,
    length          INTEGER,
    summary         TEXT,
    src_port        INTEGER,
    dst_port        INTEGER,
    tcp_flags       TEXT,
    payload_len     INTEGER,
    nas_msg_type    TEXT,
    emm_cause       INTEGER,
    is_anchor_candidate INTEGER DEFAULT 0,
    event_type      TEXT
);

CREATE TABLE IF NOT EXISTS correlated_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT,
    rule_id         TEXT,
    rule_desc       TEXT,
    severity        TEXT,
    diagnosis       TEXT,
    trigger_ts      TEXT,
    trigger_source  TEXT,
    trigger_raw     TEXT,
    evidence        TEXT,      -- JSON配列: 根拠レコードのサマリー
    confidence      TEXT
);

CREATE TABLE IF NOT EXISTS anchors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT,
    anchor_type     TEXT,      -- "boot" / "at_corr" / "cereg" / "kcnx"
    source          TEXT,      -- "chipset" / "at" / "pcap"
    utc_ts          TEXT,
    raw_text        TEXT,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS current_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    utc_ts      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    value_ma    REAL,
    duration_s  REAL DEFAULT 0,
    raw_text    TEXT,
    source_file TEXT
);

CREATE INDEX IF NOT EXISTS idx_chip_utc    ON chipset_events(utc_ts_est);
CREATE INDEX IF NOT EXISTS idx_at_utc      ON at_events(utc_ts_est);
CREATE INDEX IF NOT EXISTS idx_chip_tick   ON chipset_events(chip_tick_us);
CREATE INDEX IF NOT EXISTS idx_pcap_utc    ON pcap_events(utc_ts);
CREATE INDEX IF NOT EXISTS idx_corr_ts     ON correlated_events(trigger_ts);
CREATE INDEX IF NOT EXISTS idx_current_utc ON current_events(utc_ts);
"""

def _ts(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


class DiagDb:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        logger.info("DB 初期化: %s", path)

    def insert_chipset(self, records: list[ChipsetRecord]) -> int:
        rows = [
            (r.dbv_rel_sec, _ts(r.dbv_abs_ts), r.chip_tick_us, r.pid,
             r.level, r.level_int, r.message, r.source_file, r.source_line,
             r.module, r.fsm_name, r.fsm_next_state,
             int(r.is_boot_anchor), int(r.is_at_corr_anchor),
             _ts(r.utc_ts_est), r.align_confidence)
            for r in records if r.is_umac
        ]
        self.conn.executemany("""
            INSERT INTO chipset_events
            (dbv_rel_sec,dbv_abs_ts,chip_tick_us,pid,level,level_int,message,
             source_file,source_line,module,fsm_name,fsm_next_state,
             is_boot_anchor,is_at_corr_anchor,utc_ts_est,align_confidence)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, rows)
        self.conn.commit()
        logger.info("chipset_events: %d 件 挿入", len(rows))
        return len(rows)

    def insert_at(self, records: list[AtRecord]) -> int:
        rows = [
            (_ts(r.abs_ts), r.rel_ms, r.direction, r.raw_text,
             int(r.is_command), int(r.is_response), int(r.is_urc),
             int(r.is_ok), int(r.is_error), r.error_code,
             int(r.is_anchor_candidate), _ts(r.utc_ts_est), r.align_confidence)
            for r in records
        ]
        self.conn.executemany("""
            INSERT INTO at_events
            (abs_ts,rel_ms,direction,raw_text,is_command,is_response,is_urc,
             is_ok,is_error,error_code,is_anchor_candidate,utc_ts_est,align_confidence)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, rows)
        self.conn.commit()
        logger.info("at_events: %d 件 挿入", len(rows))
        return len(rows)

    def insert_pcap(self, records) -> int:
        """pcap_parser.PcapRecord のリストを pcap_events に挿入する"""
        rows = [
            (r.frame_no, _ts(r.utc_ts), r.src_ip, r.dst_ip, r.protocol,
             r.length, r.summary, r.src_port, r.dst_port, r.tcp_flags,
             r.payload_len, r.nas_msg_type, r.emm_cause,
             int(r.is_anchor_candidate), r.event_type)
            for r in records
        ]
        self.conn.executemany("""
            INSERT INTO pcap_events
            (frame_no,utc_ts,src_ip,dst_ip,protocol,length,summary,
             src_port,dst_port,tcp_flags,payload_len,nas_msg_type,emm_cause,
             is_anchor_candidate,event_type)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, rows)
        self.conn.commit()
        logger.info("pcap_events: %d 件 挿入", len(rows))
        return len(rows)

    def insert_current(self, records: list) -> int:
        """current_events に電流消費イベントを挿入する（otii_parser.CurrentEvent のリスト）。"""
        rows = [
            (r.utc_ts.isoformat(), r.event_type, r.value_ma,
             r.duration_s, r.raw_text, r.source_file)
            for r in records
        ]
        self.conn.executemany("""
            INSERT INTO current_events
            (utc_ts, event_type, value_ma, duration_s, raw_text, source_file)
            VALUES (?,?,?,?,?,?)
        """, rows)
        self.conn.commit()
        logger.info("current_events: %d 件 挿入", len(rows))
        return len(rows)

    def insert_correlated(self, rows: list[dict]) -> int:
        """correlated_events に相関結果を挿入する"""
        import json
        from datetime import datetime
        now = datetime.utcnow().isoformat()
        data = [
            (now, r["rule_id"], r["rule_desc"], r["severity"],
             r["diagnosis"], r["trigger_ts"], r["trigger_source"],
             r["trigger_raw"], json.dumps(r.get("evidence", []), ensure_ascii=False),
             r.get("confidence", "MEDIUM"))
            for r in rows
        ]
        self.conn.executemany("""
            INSERT INTO correlated_events
            (created_at,rule_id,rule_desc,severity,diagnosis,
             trigger_ts,trigger_source,trigger_raw,evidence,confidence)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, data)
        self.conn.commit()
        logger.info("correlated_events: %d 件 挿入", len(data))
        return len(data)

    def insert_anchors(self, rows: list[dict]) -> int:
        """anchors テーブルに整合アンカーを記録する"""
        from datetime import datetime
        now = datetime.utcnow().isoformat()
        data = [
            (now, r["anchor_type"], r["source"], r["utc_ts"],
             r.get("raw_text", ""), r.get("notes", ""))
            for r in rows
        ]
        self.conn.executemany("""
            INSERT INTO anchors (created_at,anchor_type,source,utc_ts,raw_text,notes)
            VALUES (?,?,?,?,?,?)
        """, data)
        self.conn.commit()
        return len(data)

    def query(self, sql: str, params=()) -> list[tuple]:
        cur = self.conn.execute(sql, params)
        return cur.fetchall()

    def close(self):
        self.conn.close()
