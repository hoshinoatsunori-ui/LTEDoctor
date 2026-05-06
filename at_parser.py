"""
at_parser.py  Rev 2.0
ホストマイコン ↔ モジュール間 ATコマンドログをパースする。

【TX/RX分離ファイル対応】
  TXファイル: ホスト送信コマンドのみ（タイムスタンプ = 送信時刻）
  RXファイル: モジュール応答のみ（OK/ERROR/URC/中間レスポンス）
  → parse_tx_rx_pair() で両ファイルを渡すと自動的にペアリングする

【RXファイルの特徴】
  - 空行付きで2行1セットになっている場合がある（空行は無視）
  - 同一タイムスタンプに複数レスポンスが来る場合がある
  - +KSUP: 0 はモジュールリセット完了通知（アンカー候補）

【サポートフォーマット】
  フォーマットA（絶対時刻）: [YYYY-MM-DD HH:MM:SS.mmm] <payload>
  フォーマットB（相対時刻）: T+<rel_ms>ms [TX/RX] <payload>
  フォーマットC（混在1ファイル）: [ts] [TX/RX] <payload>
"""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ── URC 定義 ──────────────────────────────────────────────────────
_URC_PREFIXES = (
    "+CEREG:", "+CREG:", "+CGREG:",
    "+KCNX_IND:", "+KUDP_DATA:", "+KTCP_DATA:", "+KUDP_IND:", "+KTCP_IND:",
    "+WIND:", "+CIEV:", "+CMTI:", "+CMT:",
    "+KSREP:", "+KPATTERN:", "+KSUP:",   # +KSUP: リセット完了
    "+KBNDCFG:",                          # バンド変更通知
)

# アンカー候補コマンド
_ANCHOR_CMDS = (
    "AT+CEREG", "AT+CGACT", "AT+CGDCONT",
    "AT+KCNXCFG", "AT+CFUN", "AT+CPWROFF",
)

# KCNX_IND の状態コード
KCNX_IND_STATE = {
    "0": "切断",
    "1": "接続確立",
    "2": "接続中",
    "5": "接続エラー",
}

# ── データクラス ───────────────────────────────────────────────────
@dataclass
class AtRecord:
    abs_ts: Optional[datetime]
    rel_ms: Optional[int]
    raw_ts_str: str
    direction: str          # "TX" | "RX" | "UNKNOWN"
    raw_text: str

    # 分類フラグ
    is_command:   bool = False
    is_response:  bool = False   # OK/ERROR 終端
    is_urc:       bool = False
    is_ok:        bool = False
    is_error:     bool = False
    error_code:   Optional[str] = None
    is_reset_urc: bool = False   # +KSUP: 0

    # セマンティクス
    cereg_stat:   Optional[int] = None   # +CEREG の stat値
    kcnx_state:   Optional[str] = None   # +KCNX_IND の状態名
    kcnx_cause:   Optional[str] = None
    cesq_rsrq:    Optional[int] = None   # 信号品質
    cesq_rsrp:    Optional[int] = None

    # ペアリング (parse_tx_rx_pair が埋める)
    paired_tx:    Optional["AtRecord"] = field(default=None, repr=False)
    paired_rx:    list["AtRecord"]     = field(default_factory=list, repr=False)

    # アンカーフラグ
    is_anchor_candidate: bool = False

    # time_aligner が埋める
    utc_ts_est:        Optional[datetime] = None
    align_confidence:  Optional[str] = None


# ── パース ─────────────────────────────────────────────────────────
_RE_FMT_A = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2} [\d:.]+)\]\s*(.*)'
)
_RE_FMT_B = re.compile(
    r'^T\+(\d+)ms\s+\[?(TX|RX|>>|<<)\]?\s*(.*)'
)
_RE_FMT_C = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2} [\d:.]+)\]\s*\[?(TX|RX|>>|<<)\]?\s*(.*)'
)

def _parse_ts(ts_s: str) -> Optional[datetime]:
    ts_s = ts_s.strip()
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in ts_s else "%Y-%m-%d %H:%M:%S"
    try:
        return datetime.strptime(ts_s, fmt)
    except ValueError:
        return None

def _norm_dir(d: str) -> str:
    return "TX" if d in ("TX", ">>") else "RX" if d in ("RX", "<<") else "UNKNOWN"


def parse_file(
    path: str,
    direction: Optional[str] = None,   # "TX" / "RX" を強制指定
    encoding: str = "utf-8",
) -> list[AtRecord]:
    """
    単一ファイルをパースする。
    direction を指定すると全行をその方向として扱う（TX/RX分離ファイル用）。
    """
    records: list[AtRecord] = []
    skipped = 0

    with open(path, encoding=encoding, errors="replace") as f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.rstrip("\n\r")
            if not raw.strip():
                continue

            rec = _try_parse_line(raw, forced_direction=direction)
            if rec is None:
                skipped += 1
                continue
            if not rec.raw_text.strip():
                continue   # 空ペイロード行は除外
            _classify(rec)
            records.append(rec)

    logger.info("ATログ パース完了: %d 件, スキップ %d 件 [%s] (%s)",
                len(records), skipped, direction or "auto", path)
    return records


def _try_parse_line(
    raw: str,
    forced_direction: Optional[str] = None,
) -> Optional[AtRecord]:
    # フォーマットC（方向付き混在）を先に試みる
    m = _RE_FMT_C.match(raw)
    if m and m.group(2):
        ts_s, dir_s, text = m.groups()
        d = forced_direction or _norm_dir(dir_s)
        return AtRecord(abs_ts=_parse_ts(ts_s), rel_ms=None,
                        raw_ts_str=ts_s, direction=d, raw_text=text.strip())

    # フォーマットA（方向なし絶対時刻）
    m = _RE_FMT_A.match(raw)
    if m:
        ts_s, text = m.groups()
        d = forced_direction or "UNKNOWN"
        return AtRecord(abs_ts=_parse_ts(ts_s), rel_ms=None,
                        raw_ts_str=ts_s, direction=d, raw_text=text.strip())

    # フォーマットB（相対時刻）
    m = _RE_FMT_B.match(raw)
    if m:
        rel_s, dir_s, text = m.groups()
        d = forced_direction or _norm_dir(dir_s)
        return AtRecord(abs_ts=None, rel_ms=int(rel_s),
                        raw_ts_str=f"T+{rel_s}ms", direction=d, raw_text=text.strip())

    return None


def _classify(rec: AtRecord) -> None:
    txt = rec.raw_text.strip()
    upper = txt.upper()

    # ── TX ──
    if rec.direction == "TX":
        cmd_upper = upper.lstrip("+")
        if upper.startswith("AT") or upper.startswith("+++") or txt.startswith("at%"):
            rec.is_command = True
            if any(upper.startswith(a.upper()) for a in _ANCHOR_CMDS):
                rec.is_anchor_candidate = True
        return

    # ── RX ──
    if upper == "OK":
        rec.is_response = True; rec.is_ok = True; return

    if upper.startswith("ERROR") or re.match(r'\+CM[ES] ERROR', upper):
        rec.is_response = True; rec.is_error = True
        m = re.search(r'ERROR:\s*(\S+)', txt, re.I)
        if m: rec.error_code = m.group(1)
        return

    # URC / 中間レスポンス
    for pfx in _URC_PREFIXES:
        if txt.startswith(pfx):
            rec.is_urc = True
            break

    # +KSUP リセット完了
    if txt.startswith("+KSUP:"):
        rec.is_reset_urc = True
        rec.is_anchor_candidate = True

    # +CEREG セマンティクス
    m = re.match(r'\+CEREG:\s*(\d+)(?:,(\d+))?', txt)
    if m:
        rec.cereg_stat = int(m.group(2) if m.group(2) else m.group(1))
        if rec.cereg_stat in (1, 5):
            rec.is_anchor_candidate = True  # 登録成功
        rec.is_urc = True

    # +KCNX_IND セマンティクス
    m = re.match(r'\+KCNX_IND:\s*\d+,(\d+),(\d+)', txt)
    if m:
        rec.kcnx_state = KCNX_IND_STATE.get(m.group(1), m.group(1))
        rec.kcnx_cause = m.group(2)
        if m.group(1) == "1":
            rec.is_anchor_candidate = True  # PDN確立
        rec.is_urc = True

    # +CESQ 信号品質
    m = re.match(r'\+CESQ:\s*\d+,\d+,\d+,\d+,(\d+),(\d+)', txt)
    if m:
        rsrq_raw, rsrp_raw = int(m.group(1)), int(m.group(2))
        rec.cesq_rsrq = rsrq_raw if rsrq_raw != 255 else None
        rec.cesq_rsrp = rsrp_raw if rsrp_raw != 255 else None


# ── TX/RX ペアリング ───────────────────────────────────────────────
def parse_tx_rx_pair(
    tx_path: str,
    rx_path: str,
    encoding: str = "utf-8",
) -> list[AtRecord]:
    """
    TXファイル・RXファイルを読み込み、時刻順にマージしてペアリングを行う。
    各TXコマンドにそれに続くRXレコード群を paired_rx として関連付ける。
    返値は全レコードを時刻順に並べたリスト。
    """
    tx_recs = parse_file(tx_path, direction="TX", encoding=encoding)
    rx_recs = parse_file(rx_path, direction="RX", encoding=encoding)

    # 時刻順マージ
    all_recs = sorted(
        tx_recs + rx_recs,
        key=lambda r: r.abs_ts or datetime.min,
    )

    # ペアリング: TXコマンドの後に来るRXを次のTXまで紐付ける
    last_tx: Optional[AtRecord] = None
    for rec in all_recs:
        if rec.direction == "TX" and rec.is_command:
            last_tx = rec
        elif rec.direction == "RX" and last_tx is not None:
            rec.paired_tx = last_tx
            last_tx.paired_rx.append(rec)

    # time_aligner 向けに abs_ts → utc_ts_est を仮設定
    for rec in all_recs:
        if rec.abs_ts:
            rec.utc_ts_est = rec.abs_ts
            rec.align_confidence = "MEDIUM"

    logger.info("ペアリング完了: TX=%d RX=%d 合計=%d",
                len(tx_recs), len(rx_recs), len(all_recs))
    return all_recs


# ── サマリー ───────────────────────────────────────────────────────
def summary(records: list[AtRecord]) -> dict:
    from collections import Counter
    tx = [r for r in records if r.direction == "TX"]
    rx = [r for r in records if r.direction == "RX"]

    cereg_seq = [(r.abs_ts.strftime("%H:%M:%S.%f")[:12], r.cereg_stat)
                 for r in rx if r.cereg_stat is not None]
    kcnx_seq  = [(r.abs_ts.strftime("%H:%M:%S.%f")[:12], r.kcnx_state, r.kcnx_cause)
                 for r in rx if r.kcnx_state]
    resets    = [r.abs_ts.isoformat() for r in rx if r.is_reset_urc]
    cesq_vals = [(r.abs_ts.strftime("%H:%M:%S"), r.cesq_rsrp, r.cesq_rsrq)
                 for r in rx if r.cesq_rsrp is not None]

    return {
        "tx_total": len(tx),
        "rx_total": len(rx),
        "commands": len([r for r in tx if r.is_command]),
        "ok_responses": len([r for r in rx if r.is_ok]),
        "error_responses": len([r for r in rx if r.is_error]),
        "urcs": len([r for r in rx if r.is_urc]),
        "resets_ksup": resets,
        "cereg_sequence": cereg_seq,
        "kcnx_sequence": kcnx_seq,
        "cesq_rsrp_log": cesq_vals,
        "anchor_candidates": [r.raw_text for r in records if r.is_anchor_candidate],
    }
