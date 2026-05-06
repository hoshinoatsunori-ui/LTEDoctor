"""
event_correlator.py  Ph.3
SQLite 中間ストアから統合クエリでイベントを抽出し、
rules.yaml の相関ルールを評価して correlated_events テーブルに書き込む。

イベント種別 (event_type):
  EVT_ATTACH      : +CEREG:1/5 / NAS Attach Accept
  EVT_DETACH      : +CEREG:0/2 / NAS Detach
  EVT_TX          : AT+KUDPSND / UDPパケット / TCPデータ送信
  EVT_RX          : +KUDP_DATA / TCPペイロード受信
  EVT_PDN_ERROR   : +KCNX_IND state=5
  EVT_NWREJECT    : Attach Reject / EMM cause
  EVT_TIMEOUT     : ATコマンドに OK/ERR なし（command はあるが response が後続しない）
  EVT_RESET       : +KSUP: 0（モジュールリセット完了）
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# ── イベント種別定数 ───────────────────────────────────────────────
EVT_ATTACH    = "EVT_ATTACH"
EVT_DETACH    = "EVT_DETACH"
EVT_TX        = "EVT_TX"
EVT_RX        = "EVT_RX"
EVT_PDN_ERROR = "EVT_PDN_ERROR"
EVT_NWREJECT  = "EVT_NWREJECT"
EVT_TIMEOUT   = "EVT_TIMEOUT"
EVT_RESET     = "EVT_RESET"

# ── イベントレコード ──────────────────────────────────────────────
@dataclass
class Event:
    event_type: str
    utc_ts: datetime
    source: str          # "at" / "chipset" / "pcap"
    raw_text: str
    db_id: Optional[int] = None
    extra: dict = field(default_factory=dict)


# ── SQLite からイベント抽出 ────────────────────────────────────────
def extract_events(conn) -> list[Event]:
    """
    chipset_events / at_events / pcap_events を横断してイベントリストを生成する。
    utc_ts_est / utc_ts が NULL のレコードは除外する。
    """
    events: list[Event] = []

    # ── AT イベント ──
    cur = conn.execute("""
        SELECT id, utc_ts_est, direction, raw_text,
               is_command, is_response, is_urc, is_ok, is_error,
               is_anchor_candidate
        FROM at_events
        WHERE utc_ts_est IS NOT NULL
        ORDER BY utc_ts_est
    """)
    pending_cmds: list[Event] = []  # タイムアウト検出用

    for row in cur.fetchall():
        db_id, ts_s, direction, raw, is_cmd, is_resp, is_urc, is_ok, is_err, is_anc = row
        try:
            ts = datetime.fromisoformat(ts_s).replace(tzinfo=None)
        except (ValueError, TypeError):
            continue

        ev_type = None
        # +CEREG URC → ATTACH / DETACH
        m = re.match(r'\+CEREG:\s*(\d+)(?:,(\d+))?', raw or "")
        if m:
            stat = int(m.group(2) if m.group(2) else m.group(1))
            ev_type = EVT_ATTACH if stat in (1, 5) else EVT_DETACH

        # +KCNX_IND state=5 → PDN_ERROR
        m2 = re.match(r'\+KCNX_IND:\s*\d+,(\d+),(\d+)', raw or "")
        if m2 and m2.group(1) == "5":
            ev_type = EVT_PDN_ERROR

        # +KSUP: 0 → RESET
        if (raw or "").startswith("+KSUP:"):
            ev_type = EVT_RESET

        # AT+KUDPSND / AT+KUDPEND → TX
        if direction == "TX" and is_cmd and re.match(r'AT\+KUDP(SND|END)', raw or "", re.I):
            ev_type = EVT_TX

        # +KUDP_DATA / +KTCP_DATA → RX
        if (raw or "").startswith(("+KUDP_DATA:", "+KTCP_DATA:")):
            ev_type = EVT_RX

        if ev_type:
            events.append(Event(ev_type, ts, "at", raw or "", db_id=db_id))

        # タイムアウト検出: コマンド送信を記録
        if direction == "TX" and is_cmd:
            pending_cmds.append(Event(EVT_TIMEOUT, ts, "at", raw or "", db_id=db_id))
        elif direction == "RX" and (is_ok or is_err):
            # 直近の未応答コマンドを解決
            if pending_cmds:
                pending_cmds.pop()

    # 未応答コマンド → TIMEOUT イベント
    for ev in pending_cmds:
        events.append(Event(EVT_TIMEOUT, ev.utc_ts, "at", ev.raw_text, db_id=ev.db_id))

    # ── pcap イベント ──
    cur2 = conn.execute("""
        SELECT id, utc_ts, event_type, summary, nas_msg_type, emm_cause
        FROM pcap_events
        WHERE utc_ts IS NOT NULL AND event_type IS NOT NULL
        ORDER BY utc_ts
    """)
    for row in cur2.fetchall():
        db_id2, ts_s, ev_type, summary, nas_type, emm_cause = row
        try:
            ts = datetime.fromisoformat(ts_s).replace(tzinfo=None)
        except (ValueError, TypeError):
            continue

        # NAS Attach Accept → ATTACH
        if nas_type and "attach accept" in str(nas_type).lower():
            ev_type = EVT_ATTACH
        # NAS Attach Reject → NWREJECT
        elif nas_type and "reject" in str(nas_type).lower():
            ev_type = EVT_NWREJECT

        events.append(Event(
            ev_type, ts, "pcap", summary or "",
            db_id=db_id2,
            extra={"nas_msg_type": nas_type, "emm_cause": emm_cause},
        ))

    events.sort(key=lambda e: e.utc_ts)
    logger.info("イベント抽出: 計 %d 件", len(events))
    return events


# ── rules.yaml 読み込み ───────────────────────────────────────────
def load_rules(path: str = None) -> list[dict]:
    """
    rules.yaml を読み込んで返す。
    path が None の場合、このファイルと同階層の rules.yaml を探す。
    """
    try:
        import yaml
    except ImportError:
        logger.error("PyYAML が見つかりません: pip install pyyaml")
        return []

    if path is None:
        path = os.path.join(os.path.dirname(__file__), "rules.yaml")

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    rules = data.get("rules", [])
    logger.info("ルール読み込み: %d 件 (%s)", len(rules), path)
    return rules


# ── ルール評価 ───────────────────────────────────────────────────
def _ts_diff_ms(a: datetime, b: datetime) -> float:
    """a - b をミリ秒で返す（符号あり）"""
    return (a - b).total_seconds() * 1000.0


def _match_event(ev: Event, cond: dict) -> bool:
    """
    条件 cond が単一イベント ev にマッチするか判定。
    """
    src = cond.get("source", "any")
    if src != "any" and ev.source != src:
        return False

    if "event" in cond and ev.event_type != cond["event"]:
        return False

    if "match" in cond:
        if cond["match"].lower() not in ev.raw_text.lower():
            return False

    return True


def _find_within(events: list[Event], center_ts: datetime,
                 cond: dict) -> list[Event]:
    """
    center_ts の前後 within_ms 内で cond にマッチするイベントを返す。
    """
    within_ms = cond.get("within_ms", 5000)
    lo = center_ts - timedelta(milliseconds=within_ms)
    hi = center_ts + timedelta(milliseconds=within_ms)
    return [e for e in events
            if lo <= e.utc_ts <= hi and _match_event(e, cond)]


def evaluate_rules(
    events: list[Event],
    rules: list[dict],
) -> list[dict]:
    """
    ルールリストを全イベントに対して評価し、マッチした相関レコードを返す。
    """
    results: list[dict] = []

    for rule in rules:
        rid       = rule.get("id", "?")
        rdesc     = rule.get("description", "")
        severity  = rule.get("severity", "medium")
        diagnosis = rule.get("diagnosis", rdesc)
        conditions = rule.get("conditions", [])
        trigger    = rule.get("trigger", {})

        trigger_event   = trigger.get("event")
        trigger_match   = trigger.get("match_at")
        trigger_count   = trigger.get("count", 1)
        trigger_window  = trigger.get("window_ms", 0)

        # トリガー合致イベントを収集
        triggered = [
            e for e in events
            if e.event_type == trigger_event
            and (trigger_match is None or
                 trigger_match.lower() in e.raw_text.lower())
        ]

        if not triggered:
            continue

        # count モード（同一イベントが window_ms 内に count 回）
        if trigger_count > 1:
            triggered = _collect_bursts(triggered, trigger_count, trigger_window)

        for trig_ev in triggered:
            # 条件評価
            evidence: list[str] = [f"[{trig_ev.source}] {trig_ev.raw_text}"]
            all_pass = True

            for cond in conditions:
                matches = _find_within(events, trig_ev.utc_ts, cond)
                absent  = cond.get("absent", False)

                if absent:
                    if matches:
                        all_pass = False
                        break
                    # absent=True かつ matches が空 → 条件成立
                else:
                    if not matches:
                        all_pass = False
                        break
                    evidence += [f"[{m.source}] {m.raw_text}" for m in matches[:3]]

            if not all_pass:
                continue

            # 信頼度: トリガーと証拠のソース多様性で決定
            sources = {trig_ev.source}
            for cond in conditions:
                if not cond.get("absent"):
                    found = _find_within(events, trig_ev.utc_ts, cond)
                    sources.update(e.source for e in found)
            confidence = "HIGH" if len(sources) > 1 else "MEDIUM"

            results.append({
                "rule_id":       rid,
                "rule_desc":     rdesc,
                "severity":      severity,
                "diagnosis":     diagnosis,
                "trigger_ts":    trig_ev.utc_ts.isoformat(),
                "trigger_source": trig_ev.source,
                "trigger_raw":   trig_ev.raw_text,
                "evidence":      evidence,
                "confidence":    confidence,
            })
            logger.info("ルール %s マッチ: ts=%s  %s",
                        rid, trig_ev.utc_ts.isoformat(), diagnosis)

    logger.info("相関評価完了: %d 件 マッチ", len(results))
    return results


def _collect_bursts(events: list[Event], count: int, window_ms: int) -> list[Event]:
    """
    window_ms 内に count 件以上の同一イベントが集まった場合、
    先頭イベントをトリガーとして返す（重複排除）。
    """
    triggers = []
    used = set()
    for i, ev in enumerate(events):
        if i in used:
            continue
        window = [
            j for j, e2 in enumerate(events)
            if j not in used
            and abs(_ts_diff_ms(e2.utc_ts, ev.utc_ts)) <= window_ms
        ]
        if len(window) >= count:
            triggers.append(ev)
            used.update(window)
    return triggers


# ── メインエントリポイント ────────────────────────────────────────
def correlate(
    db,
    rules_path: str = None,
) -> list[dict]:
    """
    DiagDb インスタンスを受け取り、イベント抽出 → ルール評価 → DB書き込みを行う。
    マッチした相関レコードのリストを返す。
    """
    events  = extract_events(db.conn)
    rules   = load_rules(rules_path)
    results = evaluate_rules(events, rules)

    if results:
        db.insert_correlated(results)

    # アンカー情報も保存
    _save_anchors(db)

    return results


def _save_anchors(db) -> None:
    """chipset_events / at_events からアンカーを anchors テーブルに保存する"""
    anchor_rows = []

    # チップセット起動アンカー
    rows = db.query("""
        SELECT utc_ts_est, message FROM chipset_events
        WHERE is_boot_anchor = 1
    """)
    for ts_s, msg in rows:
        anchor_rows.append({
            "anchor_type": "boot",
            "source": "chipset",
            "utc_ts": ts_s,
            "raw_text": msg or "",
            "notes": "チップセット起動アンカー",
        })

    # AT 相関アンカー
    rows2 = db.query("""
        SELECT utc_ts_est, message FROM chipset_events
        WHERE is_at_corr_anchor = 1
    """)
    for ts_s, msg in rows2:
        anchor_rows.append({
            "anchor_type": "at_corr",
            "source": "chipset",
            "utc_ts": ts_s,
            "raw_text": msg or "",
            "notes": "AT相関アンカー",
        })

    # ATログ: +CEREG:1 (接続成功アンカー)
    rows3 = db.query("""
        SELECT utc_ts_est, raw_text FROM at_events
        WHERE raw_text LIKE '+CEREG:%' AND is_anchor_candidate = 1
    """)
    for ts_s, raw in rows3:
        anchor_rows.append({
            "anchor_type": "cereg",
            "source": "at",
            "utc_ts": ts_s,
            "raw_text": raw or "",
            "notes": "+CEREG アンカー",
        })

    if anchor_rows:
        db.insert_anchors(anchor_rows)
        logger.info("anchors: %d 件 保存", len(anchor_rows))


# ── サマリー出力 ─────────────────────────────────────────────────
def print_summary(results: list[dict]) -> None:
    if not results:
        print("相関ルール: マッチなし")
        return

    print(f"\n=== 相関診断レポート ({len(results)} 件) ===")
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for r in sorted(results, key=lambda x: severity_order.get(x["severity"], 9)):
        sev = r["severity"].upper()
        ts  = r["trigger_ts"][:19]
        print(f"\n  [{sev}] {r['rule_id']}  {ts}  confidence={r['confidence']}")
        print(f"  {r['diagnosis']}")
        print(f"  トリガー: [{r['trigger_source']}] {r['trigger_raw']}")
        if r.get("evidence") and len(r["evidence"]) > 1:
            for ev in r["evidence"][1:4]:
                print(f"    根拠: {ev}")
