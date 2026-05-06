"""
chipset_parser.py
DebugView++ (.dblog / .txt) 形式のチップセットログをパースする。

外側フォーマット（タブ区切り5列）:
  col[0]  DebugView相対時刻 [s]
  col[1]  PC絶対時刻 (YYYY/MM/DD HH:MM:SS.mmm)
  col[2]  PID
  col[3]  プロセス名
  col[4]  ペイロード

LogCreator.exe ペイロード（UMAC内部ログ）:
  datetime , ip , subsystem , tick_us , level , "message" , source_file , line , module
  ※ tick_us = チップ起動からの経過時間 [μs]（"logs timestamp unit: US" で確定）
"""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── 定数 ──────────────────────────────────────────────────────────
UMAC_LEVEL_MAP = {
    "EMERGENCY": 0, "ALERT": 1, "CRITICAL": 2, "ERROR": 3,
    "WARNING": 4, "NOTICE": 5, "INFO": 6, "DEBUG": 7,
}

# チップ起動を示すアンカーキーワード（tick_us リセット直後）
BOOT_ANCHOR_MSG = "Initialising the system..."

# AT レイヤーとの相関に使えるアンカー
AT_CORR_ANCHOR_MSG = "AT_Entry: Rat in use"

# FSM 状態遷移抽出
RE_SM_STATE = re.compile(r'SM_SET_NEXT_STATE\((\w+),\s*(\w+)\)')

# ConsoleD 同期エラー（除外対象）
RE_CONSOLED_SYNC = re.compile(r'ConsoleD: findPacket\(\) failed')

# ── データクラス ───────────────────────────────────────────────────
@dataclass
class ChipsetRecord:
    """パース済み1レコード"""
    # DebugView外側
    dbv_rel_sec: float          # DebugView相対時刻 [s]
    dbv_abs_ts: datetime        # PC絶対時刻 (tzaware UTC想定)
    pid: int
    process: str
    raw_payload: str

    # UMAC内部（LogCreator.exe のみ）
    is_umac: bool = False
    chip_tick_us: Optional[int] = None   # チップ起動からの経過 [μs]
    level: Optional[str] = None
    level_int: Optional[int] = None
    message: Optional[str] = None
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    module: Optional[str] = None

    # 導出フィールド（time_aligner が埋める）
    utc_ts_est: Optional[datetime] = None   # 推定UTC時刻
    align_confidence: Optional[str] = None  # HIGH/MEDIUM/LOW

    # アンカーフラグ
    is_boot_anchor: bool = False
    is_at_corr_anchor: bool = False

    # FSM 状態遷移（あれば）
    fsm_name: Optional[str] = None
    fsm_next_state: Optional[str] = None


# ── パーサー本体 ───────────────────────────────────────────────────
_RE_DBV_LINE = re.compile(
    r'^([\d.]+)\t'            # col[0] rel_sec
    r'([\d/]+ [\d:.]+)\t'    # col[1] abs_ts
    r'(\d+)\t'                # col[2] pid
    r'(\S+)\t'                # col[3] process
    r'(.*)'                   # col[4] payload
)

_RE_UMAC_PAYLOAD = re.compile(
    r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'   # datetime (無視)
    r' , [\d.]+'                               # ip
    r' , \w+'                                  # subsystem
    r' , (\d+)'                                # tick_us
    r' , (\w+)'                                # level
    r' ,"(.*?)"'                               # message
    r' , (\S+)'                                # source_file
    r' , (\d+)'                                # line
    r' , (\w+)'                                # module
)

def _parse_dbv_ts(ts_str: str) -> datetime:
    """'2026/04/13 17:09:25.864' → datetime (naive, ローカル扱い)"""
    return datetime.strptime(ts_str.strip(), "%Y/%m/%d %H:%M:%S.%f")


def parse_file(path: str, encoding: str = "utf-8") -> list[ChipsetRecord]:
    """
    DebugView++ ログファイルをパースして ChipsetRecord のリストを返す。
    ConsoleD の同期エラー行はスキップする。
    """
    records: list[ChipsetRecord] = []
    skipped = 0

    with open(path, encoding=encoding, errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.rstrip("\n\r")
            if not raw.strip():
                continue

            m = _RE_DBV_LINE.match(raw)
            if not m:
                logger.debug("line %d: フォーマット不一致 スキップ: %s", lineno, raw[:60])
                skipped += 1
                continue

            rel_sec_s, abs_ts_s, pid_s, proc, payload = m.groups()

            # ConsoleD 同期エラーは除外
            if RE_CONSOLED_SYNC.search(payload):
                skipped += 1
                continue

            try:
                dbv_abs = _parse_dbv_ts(abs_ts_s)
            except ValueError:
                logger.warning("line %d: abs_ts パース失敗: %s", lineno, abs_ts_s)
                skipped += 1
                continue

            rec = ChipsetRecord(
                dbv_rel_sec=float(rel_sec_s),
                dbv_abs_ts=dbv_abs,
                pid=int(pid_s),
                process=proc,
                raw_payload=payload,
            )

            # UMAC 内部ログの追加パース
            if proc == "LogCreator.exe":
                _parse_umac(rec, payload)

            records.append(rec)

    logger.info("パース完了: %d 件, スキップ %d 件 (%s)", len(records), skipped, path)
    return records


def _parse_umac(rec: ChipsetRecord, payload: str) -> None:
    """LogCreator.exe ペイロードから UMAC フィールドを埋める"""
    m = _RE_UMAC_PAYLOAD.match(payload)
    if not m:
        return

    tick_us_s, level, msg, src_file, src_line_s, module = m.groups()
    rec.is_umac = True
    rec.chip_tick_us = int(tick_us_s)
    rec.level = level
    rec.level_int = UMAC_LEVEL_MAP.get(level, 99)
    rec.message = msg
    rec.source_file = src_file
    rec.source_line = int(src_line_s)
    rec.module = module

    # アンカー判定
    if BOOT_ANCHOR_MSG in msg:
        rec.is_boot_anchor = True
    if AT_CORR_ANCHOR_MSG in msg:
        rec.is_at_corr_anchor = True

    # FSM 状態遷移
    sm = RE_SM_STATE.search(msg)
    if sm:
        rec.fsm_name = sm.group(1)
        rec.fsm_next_state = sm.group(2)


# ── 起動アンカー検出 ──────────────────────────────────────────────
def find_boot_anchor(records: list[ChipsetRecord]) -> Optional[ChipsetRecord]:
    """
    'Initialising the system...' レコードを返す。
    チップ起動UTC時刻 = dbv_abs_ts - chip_tick_us / 1e6
    """
    for r in records:
        if r.is_boot_anchor:
            return r
    return None


def estimate_chip_boot_time(records: list[ChipsetRecord]) -> Optional[datetime]:
    """
    起動アンカーから チップ起動時刻（naive datetime）を推定する。
    """
    anchor = find_boot_anchor(records)
    if anchor is None or anchor.chip_tick_us is None:
        logger.warning("起動アンカーが見つかりません")
        return None
    offset_s = anchor.chip_tick_us / 1_000_000.0
    boot_time = anchor.dbv_abs_ts - __import__('datetime').timedelta(seconds=offset_s)
    logger.info(
        "推定チップ起動時刻: %s  (アンカーtick=%d us, offset=%.6f s)",
        boot_time.isoformat(), anchor.chip_tick_us, offset_s,
    )
    return boot_time


def apply_utc_estimates(
    records: list[ChipsetRecord],
    boot_time: Optional[datetime] = None,
) -> None:
    """
    全 UMAC レコードに utc_ts_est を付与する。
    boot_time が与えられた場合: utc_ts_est = boot_time + chip_tick_us / 1e6
    なければ: dbv_abs_ts をそのまま使い、confidence=LOW
    """
    import datetime as dt
    if boot_time is None:
        for r in records:
            if r.is_umac:
                r.utc_ts_est = r.dbv_abs_ts
                r.align_confidence = "LOW"
        return

    for r in records:
        if r.is_umac and r.chip_tick_us is not None:
            r.utc_ts_est = boot_time + dt.timedelta(microseconds=r.chip_tick_us)
            r.align_confidence = "MEDIUM"  # boot_anchorが1点のみ → MEDIUM
        elif r.is_umac:
            r.utc_ts_est = r.dbv_abs_ts
            r.align_confidence = "LOW"


# ── サマリー出力 ──────────────────────────────────────────────────
def summary(records: list[ChipsetRecord]) -> dict:
    from collections import Counter
    umac = [r for r in records if r.is_umac]
    return {
        "total_records": len(records),
        "umac_records": len(umac),
        "level_dist": dict(Counter(r.level for r in umac if r.level)),
        "module_dist": dict(Counter(r.module for r in umac if r.module)),
        "fsm_transitions": [(r.fsm_name, r.fsm_next_state) for r in umac if r.fsm_name],
        "boot_anchor_found": any(r.is_boot_anchor for r in records),
        "at_corr_anchors": [r.message for r in records if r.is_at_corr_anchor],
    }
