"""
doctor.py  --  LTE Doctor 統合 Flask Web アプリ (port 5001)
  Tab 1: 診断設定 (Setup)
  Tab 2: 診断セッション (Sessions)
  Tab 3: タイムライン (Timeline)
"""

import glob
import json
import logging
import math
import os
import sqlite3
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import pandas as pd
from flask import Flask, jsonify, render_template_string, request

# ── ロガー設定 ───────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# ── パス設定 ─────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
SESSIONS_DIR = os.path.join(SCRIPT_DIR, "sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

# スクリプトディレクトリを sys.path に追加（他モジュールのインポート用）
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import chipset_parser
import at_parser
import pcap_parser
import time_aligner
import db_store
import event_correlator
import otii_parser

app = Flask(__name__)

# ── タスク管理 ────────────────────────────────────────────────
_tasks: dict[str, dict] = {}   # task_id -> {status, step, session_id, error}
_tasks_lock = threading.Lock()

MAX_WAVEFORM_PTS = 5_000   # 表示点数上限（ウィンドウ幅に応じて適応的に減らす）

# CSV メモリキャッシュ: {path: (mtime, df_with_datetime_index)}
_csv_cache: dict = {}
_CSV_CACHE_LIMIT = 4       # 最大保持ファイル数


# ── ユーティリティ ────────────────────────────────────────────
def _detect_logs(folder: str) -> dict:
    """ログフォルダ内のファイルを検出して辞書で返す。"""
    def fp(*parts):
        return os.path.join(folder, *parts)

    chipset_path = fp("DebugView++.dblog")
    at_tx_path   = fp("uart1-2.log")
    at_rx_path   = fp("uart1-1.log")
    pcap_path    = fp("wireshark.pcapng")
    otii_csvs    = sorted(glob.glob(fp("OTII", "*.csv")))

    return {
        "chipset":   chipset_path if os.path.isfile(chipset_path) else None,
        "at_tx":     at_tx_path   if os.path.isfile(at_tx_path)   else None,
        "at_rx":     at_rx_path   if os.path.isfile(at_rx_path)   else None,
        "pcap":      pcap_path    if os.path.isfile(pcap_path)    else None,
        "otii_csvs": [c for c in otii_csvs if os.path.isfile(c)],
    }


def _task_update(task_id: str, **kwargs) -> None:
    with _tasks_lock:
        _tasks[task_id].update(kwargs)


def _safe_json(v):
    """NaN / None / inf を JSON セーフな値に変換する。"""
    if v is None:
        return None
    try:
        f = float(v)
        if math.isnan(f) or math.isinf(f):
            return None
        return f
    except (TypeError, ValueError):
        return v


# ── パイプライン実行（バックグラウンドスレッド）────────────────
def _run_pipeline(task_id: str, folder: str) -> None:
    """バックグラウンドでフルパイプラインを実行してセッションを保存する。"""
    try:
        _task_update(task_id, status="running", step="ログ検出中...")
        logs = _detect_logs(folder)

        # ── 1. パース ──
        _task_update(task_id, step="チップセットログをパース中...")
        chip_recs = []
        if logs["chipset"]:
            try:
                chip_recs = chipset_parser.parse_file(logs["chipset"])
            except Exception as e:
                logger.warning("chipset_parser エラー: %s", e)

        _task_update(task_id, step="ATログをパース中...")
        at_recs = []
        if logs["at_tx"] and logs["at_rx"]:
            try:
                at_recs = at_parser.parse_tx_rx_pair(logs["at_tx"], logs["at_rx"])
            except Exception as e:
                logger.warning("at_parser エラー: %s", e)

        _task_update(task_id, step="pcapをパース中...")
        pcap_recs = []
        if logs["pcap"]:
            try:
                pcap_recs = pcap_parser.parse_file(logs["pcap"])
            except Exception as e:
                logger.warning("pcap_parser エラー: %s", e)

        _task_update(task_id, step="電流ログをパース中...")
        current_evts = []
        for csv_path in logs["otii_csvs"]:
            try:
                evts = otii_parser.parse_csv(csv_path)
                current_evts.extend(evts)
            except Exception as e:
                logger.warning("otii_parser エラー [%s]: %s", csv_path, e)

        # ── 2. タイムスタンプ整合 ──
        _task_update(task_id, step="タイムスタンプ整合中...")
        if chip_recs:
            try:
                time_aligner.align_chipset(chip_recs)
            except Exception as e:
                logger.warning("align_chipset エラー: %s", e)
        if at_recs:
            try:
                time_aligner.align_at_log(at_recs)
            except Exception as e:
                logger.warning("align_at_log エラー: %s", e)

        # ── 3. DB 格納 ──
        _task_update(task_id, step="データベースに格納中...")
        _jst = timezone(timedelta(hours=9))
        session_id = datetime.now(_jst).strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        db_path = os.path.join(SESSIONS_DIR, f"session_{session_id}.sqlite")
        db = db_store.DiagDb(db_path)

        if chip_recs:
            db.insert_chipset(chip_recs)
        if at_recs:
            db.insert_at(at_recs)
        if pcap_recs:
            db.insert_pcap(pcap_recs)
        if current_evts:
            db.insert_current(current_evts)

        # ── 4. 相関診断 ──
        _task_update(task_id, step="相関診断を実行中...")
        findings = []
        try:
            findings = event_correlator.correlate(db)
        except Exception as e:
            logger.warning("event_correlator エラー: %s", e)

        db.close()

        # ── 5. サマリー集計 ──
        summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "medium").lower()
            if sev in summary:
                summary[sev] += 1

        # ── 6. セッション JSON 保存 ──
        _task_update(task_id, step="セッションを保存中...")
        session_data = {
            "id":          session_id,
            "created_at":  datetime.now(_jst).isoformat(),
            "log_folder":  folder,
            "db_path":     db_path,
            "otii_csvs":   logs["otii_csvs"],
            "findings":    findings,
            "summary":     summary,
        }
        json_path = os.path.join(SESSIONS_DIR, f"session_{session_id}.json")
        with open(json_path, "w", encoding="utf-8") as fp:
            json.dump(session_data, fp, ensure_ascii=False, indent=2, default=str)

        _task_update(task_id, status="done", step="完了", session_id=session_id)
        logger.info("パイプライン完了: session_id=%s", session_id)

    except Exception as e:
        logger.exception("パイプライン実行エラー")
        _task_update(task_id, status="error", step="エラー", error=str(e))


# ── タイムライン用データ取得 ──────────────────────────────────
def _load_waveform(otii_csvs: list, t_lo: datetime, t_hi: datetime) -> dict:
    """OTII CSV から波形データを返す（メモリキャッシュで2回目以降は高速）。

    初回: CSV全体を読んで DatetimeIndex 付き DataFrame をキャッシュ
    2回目以降: キャッシュから時間範囲スライスのみ（ディスクI/Oなし）
    """
    all_t  = []
    all_mA = []

    # ウィンドウ幅に応じた表示点数（狭い＝高解像度、広い＝低解像度）
    window_s = (t_hi - t_lo).total_seconds() if t_lo and t_hi else 3600
    max_pts  = min(MAX_WAVEFORM_PTS, max(500, int(window_s * 30)))

    for csv_path in otii_csvs:
        if not os.path.isfile(csv_path):
            continue
        try:
            mtime = os.path.getmtime(csv_path)
            # キャッシュミス or ファイル更新 → 読み込みなおし
            if csv_path not in _csv_cache or _csv_cache[csv_path][0] != mtime:
                logger.info("CSV キャッシュ読み込み: %s", csv_path)
                df = pd.read_csv(csv_path, usecols=lambda c: c in ["datetime", "current_A"])
                df["datetime"] = pd.to_datetime(df["datetime"], utc=False, errors="coerce")
                df = df.dropna(subset=["datetime"]).set_index("datetime").sort_index()
                # キャッシュ上限を超えたら最古エントリを削除
                if len(_csv_cache) >= _CSV_CACHE_LIMIT:
                    _csv_cache.pop(next(iter(_csv_cache)))
                _csv_cache[csv_path] = (mtime, df)

            df_cached = _csv_cache[csv_path][1]

            # 時間範囲スライス（DatetimeIndex の二分探索で O(log n)）
            lo_ts = pd.Timestamp(t_lo)
            hi_ts = pd.Timestamp(t_hi)
            sub = df_cached.loc[lo_ts:hi_ts]

            # JST/UTC ミスマッチ補正:
            # at_events は JST のまま格納されることがあるため、
            # データが得られない場合は -9h (UTC換算) で再試行する
            if sub.empty:
                lo_utc = lo_ts - pd.Timedelta(hours=9)
                hi_utc = hi_ts - pd.Timedelta(hours=9)
                sub = df_cached.loc[lo_utc:hi_utc]
            if sub.empty:
                continue

            # 間引き
            dec = max(1, math.ceil(len(sub) / max_pts))
            sub = sub.iloc[::dec]

            all_t.extend(sub.index.strftime("%Y-%m-%dT%H:%M:%S.%f").tolist())
            all_mA.extend(
                [None if pd.isna(v) else round(float(v) * 1000, 4) for v in sub["current_A"]]
            )
        except Exception as e:
            logger.warning("波形読み込みエラー [%s]: %s", csv_path, e)

    return {"t": all_t, "mA": all_mA}


def _load_events(db_path: str, t_lo: datetime, t_hi: datetime) -> list:
    """SQLite から AT / pcap / current イベントを取得する。"""
    events = []
    lo_s = t_lo.isoformat()
    hi_s = t_hi.isoformat()

    try:
        conn = sqlite3.connect(db_path)

        # AT イベント (y=1)
        try:
            cur = conn.execute(
                """SELECT utc_ts_est, raw_text, direction FROM at_events
                    WHERE utc_ts_est BETWEEN ? AND ?
                    ORDER BY utc_ts_est""",
                (lo_s, hi_s),
            )
            for ts_s, raw, direction in cur.fetchall():
                events.append({
                    "ts":     ts_s,
                    "label":  f"[AT] {(raw or '').strip()[:80]}",
                    "source": "at",
                    "y":      1,
                    "dir":    direction or "",
                })
        except sqlite3.OperationalError:
            pass

        # pcap イベント (y=2)
        try:
            cur = conn.execute(
                """SELECT utc_ts, summary, nas_msg_type, protocol FROM pcap_events
                    WHERE utc_ts BETWEEN ? AND ?
                      AND event_type IS NOT NULL
                    ORDER BY utc_ts""",
                (lo_s, hi_s),
            )
            for ts_s, summary, nas_type, protocol in cur.fetchall():
                events.append({
                    "ts":       ts_s,
                    "label":    f"[pcap] {(summary or '').strip()[:80]}",
                    "source":   "pcap",
                    "y":        2,
                    "nas_type": nas_type or "",
                    "protocol": protocol or "",
                })
        except sqlite3.OperationalError:
            pass

        # current イベント (y=3)
        try:
            cur = conn.execute(
                """SELECT utc_ts, raw_text FROM current_events
                    WHERE utc_ts BETWEEN ? AND ?
                    ORDER BY utc_ts""",
                (lo_s, hi_s),
            )
            for ts_s, raw in cur.fetchall():
                events.append({
                    "ts":     ts_s,
                    "label":  f"[current] {(raw or '').strip()[:80]}",
                    "source": "current",
                    "y":      3,
                })
        except sqlite3.OperationalError:
            pass

        conn.close()
    except Exception as e:
        logger.warning("イベント取得エラー: %s", e)

    return events


# ── API ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/detect")
def api_detect():
    folder = request.args.get("folder", "").strip()
    if not folder:
        return jsonify({"error": "folderが指定されていません"})
    if not os.path.isdir(folder):
        return jsonify({"error": f"フォルダが見つかりません: {folder}"})
    logs = _detect_logs(folder)
    return jsonify({
        "chipset":    bool(logs["chipset"]),
        "at_tx":      bool(logs["at_tx"]),
        "at_rx":      bool(logs["at_rx"]),
        "pcap":       bool(logs["pcap"]),
        "otii_count": len(logs["otii_csvs"]),
        "otii_csvs":  logs["otii_csvs"],
    })


@app.route("/api/diagnose", methods=["POST"])
def api_diagnose():
    data = request.get_json(force=True, silent=True) or {}
    folder = (data.get("folder") or "").strip()
    if not folder:
        return jsonify({"error": "folderが指定されていません"})
    if not os.path.isdir(folder):
        return jsonify({"error": f"フォルダが見つかりません: {folder}"})

    task_id = uuid.uuid4().hex
    with _tasks_lock:
        _tasks[task_id] = {
            "status":     "pending",
            "step":       "準備中...",
            "session_id": None,
            "error":      None,
        }

    t = threading.Thread(target=_run_pipeline, args=(task_id, folder), daemon=True)
    t.start()
    return jsonify({"task_id": task_id})


@app.route("/api/task/<task_id>")
def api_task(task_id: str):
    with _tasks_lock:
        info = _tasks.get(task_id)
    if info is None:
        return jsonify({"error": "タスクが見つかりません"}), 404
    return jsonify(info)


@app.route("/api/sessions")
def api_sessions():
    sessions = []
    pattern = os.path.join(SESSIONS_DIR, "session_*.json")
    for path in sorted(glob.glob(pattern), reverse=True):
        try:
            with open(path, encoding="utf-8") as fp:
                data = json.load(fp)
            sessions.append({
                "id":         data["id"],
                "created_at": data["created_at"],
                "log_folder": data["log_folder"],
                "summary":    data["summary"],
            })
        except Exception as e:
            logger.warning("セッション読み込みエラー [%s]: %s", path, e)
    return jsonify(sessions)


@app.route("/api/session/<session_id>")
def api_session(session_id: str):
    path = os.path.join(SESSIONS_DIR, f"session_{session_id}.json")
    if not os.path.isfile(path):
        return jsonify({"error": "セッションが見つかりません"}), 404
    try:
        with open(path, encoding="utf-8") as fp:
            data = json.load(fp)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/timeline/<session_id>")
def api_timeline(session_id: str):
    json_path = os.path.join(SESSIONS_DIR, f"session_{session_id}.json")
    if not os.path.isfile(json_path):
        return jsonify({"error": "セッションが見つかりません"}), 404

    try:
        with open(json_path, encoding="utf-8") as fp:
            session = json.load(fp)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    db_path   = session.get("db_path", "")
    otii_csvs = session.get("otii_csvs", [])
    findings  = session.get("findings", [])

    center_ts_s = request.args.get("center_ts", "").strip()
    window_s    = int(request.args.get("window_s", 120))

    # セッション全体の時間範囲を DB から取得
    t_session_lo: Optional[datetime] = None
    t_session_hi: Optional[datetime] = None
    if os.path.isfile(db_path):
        try:
            conn = sqlite3.connect(db_path)
            for table, col in [
                ("at_events",      "utc_ts_est"),
                ("pcap_events",    "utc_ts"),
                ("current_events", "utc_ts"),
            ]:
                try:
                    row = conn.execute(
                        f"SELECT MIN({col}), MAX({col}) FROM {table}"
                    ).fetchone()
                    if row and row[0] and row[1]:
                        lo = datetime.fromisoformat(row[0])
                        hi = datetime.fromisoformat(row[1])
                        if t_session_lo is None or lo < t_session_lo:
                            t_session_lo = lo
                        if t_session_hi is None or hi > t_session_hi:
                            t_session_hi = hi
                except sqlite3.OperationalError:
                    pass
            conn.close()
        except Exception as e:
            logger.warning("DB 時刻範囲取得エラー: %s", e)

    # ウィンドウ決定
    if center_ts_s:
        try:
            center_ts = datetime.fromisoformat(center_ts_s)
        except ValueError:
            return jsonify({"error": "center_ts の形式が不正です"}), 400
        half = timedelta(seconds=window_s / 2)
        t_lo = center_ts - half
        t_hi = center_ts + half
    else:
        # center_ts 未指定: セッション開始から window_s 秒 (または全体)
        if t_session_lo:
            t_lo = t_session_lo
            if t_session_hi:
                span = (t_session_hi - t_session_lo).total_seconds()
                t_hi = t_session_lo + timedelta(seconds=min(window_s, span))
            else:
                t_hi = t_session_lo + timedelta(seconds=window_s)
        else:
            return jsonify({
                "waveform":   {"t": [], "mA": []},
                "events":     [],
                "findings":   findings,
                "t_lo":       None,
                "t_hi":       None,
                "session_lo": None,
                "session_hi": None,
            })

    waveform = _load_waveform(otii_csvs, t_lo, t_hi)
    events   = _load_events(db_path, t_lo, t_hi) if os.path.isfile(db_path) else []

    return jsonify({
        "waveform":   waveform,
        "events":     events,
        "findings":   findings,
        "t_lo":       t_lo.isoformat(),
        "t_hi":       t_hi.isoformat(),
        "session_lo": t_session_lo.isoformat() if t_session_lo else None,
        "session_hi": t_session_hi.isoformat() if t_session_hi else None,
    })


# ── HTML ─────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LTE Doctor</title>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:      #1e1e2e;
  --mantle:  #181825;
  --crust:   #11111b;
  --surface0:#313244;
  --surface1:#45475a;
  --overlay0:#6c7086;
  --text:    #cdd6f4;
  --subtext: #bac2de;
  --blue:    #89b4fa;
  --green:   #a6e3a1;
  --red:     #f38ba8;
  --yellow:  #f9e2af;
  --peach:   #fab387;
  --mauve:   #cba6f7;
  --teal:    #94e2d5;
}
body {
  font-family: 'Segoe UI', system-ui, sans-serif;
  background: var(--bg); color: var(--text);
  display: flex; flex-direction: column; height: 100vh; overflow: hidden;
}

/* ── ヘッダー ── */
#app-header {
  flex-shrink: 0;
  background: var(--crust);
  border-bottom: 1px solid var(--surface0);
  padding: 0 16px;
  display: flex; align-items: center; gap: 16px;
}
#app-header h1 { font-size: 1rem; color: var(--blue); white-space: nowrap; padding: 10px 0; }

/* ── タブ ── */
.tabs { display: flex; gap: 0; }
.tab-btn {
  padding: 10px 20px; cursor: pointer;
  background: transparent; border: none; color: var(--overlay0);
  font-size: 0.88rem; border-bottom: 2px solid transparent;
  transition: color 0.15s, border-color 0.15s;
  white-space: nowrap;
}
.tab-btn:hover { color: var(--subtext); }
.tab-btn.active { color: var(--blue); border-bottom-color: var(--blue); }

/* ── タブパネル ── */
.tab-panel { display: none; flex: 1; overflow: hidden; }
.tab-panel.active { display: flex; flex-direction: column; }

/* ── 共通コンポーネント ── */
.card {
  background: var(--mantle); border: 1px solid var(--surface0);
  border-radius: 8px; padding: 16px; margin-bottom: 12px;
}
.field-label { font-size: 0.78rem; color: var(--overlay0); margin-bottom: 4px; }
.text-input {
  width: 100%; background: var(--surface0); border: 1px solid var(--surface1);
  color: var(--text); padding: 8px 12px; border-radius: 6px;
  font-size: 0.88rem; outline: none;
}
.text-input:focus { border-color: var(--blue); }
.btn {
  padding: 8px 18px; border: none; border-radius: 6px; cursor: pointer;
  font-size: 0.88rem; font-weight: 600; transition: background 0.15s;
}
.btn-primary   { background: var(--blue);     color: var(--crust); }
.btn-primary:hover   { background: var(--mauve); }
.btn-secondary { background: var(--surface0); color: var(--text); }
.btn-secondary:hover { background: var(--surface1); }
.badge {
  display: inline-flex; align-items: center; justify-content: center;
  padding: 2px 8px; border-radius: 12px; font-size: 0.72rem; font-weight: 700;
}
.badge-critical { background: #45001a; color: var(--red); }
.badge-high     { background: #3d1f00; color: var(--peach); }
.badge-medium   { background: #2c2900; color: var(--yellow); }
.badge-low      { background: #1a2a1a; color: var(--green); }
.badge-info     { background: #1a2040; color: var(--blue); }
.icon-ok  { color: var(--green); }
.icon-ng  { color: var(--red); }
.spinner-ring {
  display: inline-block; width: 16px; height: 16px;
  border: 2px solid var(--surface1); border-top-color: var(--blue);
  border-radius: 50%; animation: spin 0.7s linear infinite; vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }
.progress-bar-wrap {
  background: var(--surface0); border-radius: 4px; height: 6px; overflow: hidden;
}
.progress-bar { height: 100%; background: var(--blue); width: 0%; transition: width 0.3s; }

/* ── Tab 1: Setup ── */
#tab-setup { padding: 20px; overflow-y: auto; }
#setup-inner { max-width: 640px; }
#detect-result { margin-top: 12px; }
.detect-item {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 0; border-bottom: 1px solid var(--surface0);
  font-size: 0.85rem;
}
.detect-item:last-child { border-bottom: none; }
#progress-area { display: none; margin-top: 12px; }
#progress-step { font-size: 0.82rem; color: var(--subtext); margin-bottom: 6px; }
#done-link {
  display: none; margin-top: 10px; color: var(--blue);
  text-decoration: none; font-size: 0.88rem; cursor: pointer;
}
#done-link:hover { text-decoration: underline; }

/* ── Tab 2: Sessions ── */
#tab-sessions { padding: 20px; overflow-y: auto; }
.session-card {
  background: var(--mantle); border: 1px solid var(--surface0);
  border-radius: 8px; padding: 14px 16px; margin-bottom: 10px;
  cursor: pointer; transition: border-color 0.15s, background 0.15s;
}
.session-card:hover { border-color: var(--blue); background: var(--surface0); }
.session-header { display: flex; align-items: baseline; gap: 10px; margin-bottom: 6px; }
.session-ts     { font-size: 0.9rem; font-weight: 600; color: var(--blue); }
.session-folder { font-size: 0.75rem; color: var(--overlay0); word-break: break-all; }
.session-badges { display: flex; gap: 6px; flex-wrap: wrap; }
#sessions-empty { color: var(--overlay0); font-size: 0.88rem; padding: 20px 0; }

/* ── Tab 3: Timeline ── */
#tab-timeline { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
#timeline-toolbar {
  flex-shrink: 0; display: flex; align-items: center; gap: 8px;
  padding: 6px 12px; background: var(--mantle);
  border-bottom: 1px solid var(--surface0);
}
#timeline-session-label { font-size: 0.8rem; color: var(--overlay0); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
#timeline-body { flex: 2; display: flex; overflow: hidden; }

/* 所見パネル */
#findings-panel {
  width: 300px; flex-shrink: 0;
  background: var(--mantle); border-right: 1px solid var(--surface0);
  display: flex; flex-direction: column; overflow: hidden;
}
#findings-title {
  padding: 8px 12px; font-size: 0.78rem; color: var(--overlay0);
  border-bottom: 1px solid var(--surface0); background: var(--crust);
  flex-shrink: 0;
}
#findings-list { flex: 1; overflow-y: auto; }
.finding-item {
  padding: 10px 12px; border-bottom: 1px solid var(--surface0);
  cursor: pointer; transition: background 0.12s;
}
.finding-item:hover { background: var(--surface0); }
.finding-item.active {
  background: var(--surface0); border-left: 3px solid var(--blue);
  padding-left: 9px;
}
.finding-rule { font-size: 0.72rem; color: var(--overlay0); margin-bottom: 3px; }
.finding-diag { font-size: 0.8rem; color: var(--subtext); line-height: 1.4; }

/* チャートエリア */
#chart-panel { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
#tl-chart { flex: 1; min-height: 0; }
#tl-empty {
  flex: 1; display: flex; align-items: center; justify-content: center;
  color: var(--overlay0); font-size: 0.9rem;
}
#tl-loading {
  display: none; position: absolute; inset: 0;
  align-items: center; justify-content: center;
  background: rgba(30,30,46,0.75); z-index: 10; gap: 10px;
  font-size: 0.88rem; color: var(--subtext);
}
#chart-panel { position: relative; }

/* 所見アイテム内トリガ時刻 */
.finding-ts {
  font-size: 0.7rem; color: var(--teal);
  font-variant-numeric: tabular-nums; margin: 2px 0;
}

/* ルールマッチ詳細ペイン（3カラム） */
#rule-detail-pane {
  display: none; flex: 1; min-height: 0;
  background: var(--crust); border-top: 2px solid var(--surface0);
  flex-direction: row;
}
.detail-col {
  flex: 1; min-width: 0; overflow-y: auto;
  padding: 8px 12px;
  border-right: 1px solid var(--surface0);
}
.detail-col:last-child { border-right: none; }
.detail-col-title {
  font-size: 0.72rem; font-weight: 700; color: var(--overlay0);
  padding-bottom: 5px; margin-bottom: 6px;
  border-bottom: 1px solid var(--surface0);
  position: sticky; top: 0; background: var(--crust); z-index: 1;
}
.detail-log-item {
  display: flex; gap: 6px; align-items: baseline;
  padding: 2px 0; border-bottom: 1px solid rgba(69,71,90,0.4);
  font-size: 0.76rem; line-height: 1.45;
}
.detail-log-ts   { color: var(--teal); white-space: nowrap; font-family: monospace; flex-shrink: 0; }
.detail-log-text { color: var(--subtext); word-break: break-all; font-family: monospace; }
.at-dir { font-size: 0.68rem; font-weight: 700; padding: 0 4px; border-radius: 3px; flex-shrink: 0; }
.at-dir-tx { background: #1a2a3a; color: var(--blue); }
.at-dir-rx { background: #1a2a1a; color: var(--green); }
.detail-empty { color: var(--overlay0); font-size: 0.78rem; padding: 8px 0; }
.detail-header {
  display: flex; align-items: baseline; gap: 8px; margin-bottom: 5px; flex-wrap: wrap;
}
.detail-rule-id  { font-size: 0.9rem; font-weight: 700; color: var(--text); }
.detail-rule-desc { font-size: 0.75rem; color: var(--overlay0); }
.detail-ts       { font-size: 0.75rem; color: var(--teal); margin-left: auto; font-variant-numeric: tabular-nums; }
.detail-diagnosis {
  font-size: 0.82rem; color: var(--subtext); line-height: 1.45;
  margin-bottom: 8px; padding: 5px 8px;
  background: var(--surface0); border-radius: 4px;
}
.detail-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; margin-bottom: 8px; }
.detail-table th {
  color: var(--overlay0); font-weight: 600; text-align: left;
  padding: 2px 10px 2px 0; white-space: nowrap; width: 60px; vertical-align: top;
}
.detail-table td { color: var(--text); font-family: 'Consolas', monospace; font-size: 0.77rem; word-break: break-all; }
.detail-ev-title { font-size: 0.72rem; color: var(--overlay0); font-weight: 600; margin-bottom: 4px; }
.detail-ev-item {
  font-family: 'Consolas', monospace; font-size: 0.76rem; color: var(--subtext);
  padding: 3px 8px; margin-bottom: 3px;
  background: var(--surface0); border-radius: 4px;
  border-left: 3px solid var(--blue);
}
</style>
</head>
<body>

<div id="app-header">
  <h1>LTE Doctor</h1>
  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('setup')">① 診断設定</button>
    <button class="tab-btn" onclick="switchTab('sessions')">② セッション一覧</button>
    <button class="tab-btn" onclick="switchTab('timeline')">③ タイムライン</button>
  </div>
</div>

<!-- ────────────── Tab 1: Setup ────────────── -->
<div id="tab-setup" class="tab-panel active">
<div id="setup-inner">

  <div class="card">
    <div class="field-label">ログフォルダ</div>
    <div style="display:flex;gap:8px;margin-bottom:10px">
      <input id="folder-input" class="text-input" type="text"
        placeholder="例: C:\logs\2026-04-13"
        onkeydown="if(event.key==='Enter')doDetect()">
      <button class="btn btn-secondary" onclick="doDetect()">検出</button>
    </div>
    <div id="detect-result" style="display:none"></div>
  </div>

  <div class="card" id="diagnose-card" style="display:none">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
      <button class="btn btn-primary" onclick="doDiagnose()">診断開始</button>
      <span id="diagnose-status" style="font-size:0.82rem;color:var(--overlay0)"></span>
    </div>
    <div id="progress-area">
      <div id="progress-step"></div>
      <div class="progress-bar-wrap">
        <div class="progress-bar" id="progress-bar"></div>
      </div>
    </div>
    <a id="done-link" onclick="onDoneLink()">✓ 完了 — タイムラインを表示</a>
  </div>

</div>
</div>

<!-- ────────────── Tab 2: Sessions ────────────── -->
<div id="tab-sessions" class="tab-panel">
  <div style="padding:16px 20px;display:flex;align-items:center;justify-content:space-between">
    <span style="font-size:0.9rem;font-weight:600">保存済みセッション</span>
    <button class="btn btn-secondary" onclick="loadSessions()">更新</button>
  </div>
  <div style="flex:1;overflow-y:auto;padding:0 20px 20px">
    <div id="sessions-list"></div>
    <div id="sessions-empty" style="display:none">セッションがありません</div>
  </div>
</div>

<!-- ────────────── Tab 3: Timeline ────────────── -->
<div id="tab-timeline" class="tab-panel">
  <div id="timeline-toolbar">
    <span id="timeline-session-label">セッション未選択</span>
    <button class="btn btn-secondary" style="font-size:0.78rem;padding:5px 12px"
      onclick="showFullSession()">全体表示</button>
  </div>
  <div id="timeline-body">
    <div id="findings-panel">
      <div id="findings-title">所見リスト</div>
      <div id="findings-list"></div>
    </div>
    <div id="chart-panel">
      <div id="tl-loading">
        <span class="spinner-ring"></span>波形データを読み込み中...（初回のみ時間がかかります）
      </div>
      <div id="tl-empty">セッションを選択してください</div>
      <div id="tl-chart" style="display:none"></div>
    </div>
  </div>
  <div id="rule-detail-pane">
    <div class="detail-col" id="detail-rule"></div>
    <div class="detail-col" id="detail-pcap">
      <div class="detail-col-title">PCAP</div>
      <div id="detail-pcap-list"></div>
    </div>
    <div class="detail-col" id="detail-at">
      <div class="detail-col-title">ATコマンド</div>
      <div id="detail-at-list"></div>
    </div>
  </div>
</div>

<script>
// ══════════════════════════════════════════════════════
//  グローバル状態
// ══════════════════════════════════════════════════════
const COLORS = {
  bg:    '#1e1e2e', plot: '#181825', grid: '#313244', zero: '#45475a',
  text:  '#cdd6f4', blue: '#89b4fa', green: '#a6e3a1',
  red:   '#f38ba8', peach: '#fab387', mauve: '#cba6f7'
};

let currentSessionId  = null;
let activeTaskId      = null;
let taskPollTimer     = null;
let doneSessionId     = null;
const TL_WINDOW_S     = 120;
let activeFindings    = [];    // 重要度順ソート済みfindings（左パネル表示順）
let activeFindingIdx  = null;  // 現在選択中のインデックス
let chartData         = null;  // 全セッションデータ（初回ロード後キャッシュ）
let chartDomainTop    = [0.35, 1.0];  // 電流波形ドメイン（renderChart と共有）

// ══════════════════════════════════════════════════════
//  タブ切り替え
// ══════════════════════════════════════════════════════
function switchTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  const idx = { setup: 0, sessions: 1, timeline: 2 }[name];
  document.querySelectorAll('.tab-btn')[idx].classList.add('active');
  if (name === 'sessions') loadSessions();
}

// ══════════════════════════════════════════════════════
//  Tab 1: 診断設定
// ══════════════════════════════════════════════════════
async function doDetect() {
  const folder = document.getElementById('folder-input').value.trim();
  if (!folder) return;
  const res = await fetch('/api/detect?folder=' + encodeURIComponent(folder));
  const d   = await res.json();
  const el  = document.getElementById('detect-result');

  if (d.error) {
    el.style.display = 'block';
    el.innerHTML = '<span style="color:var(--red)">' + esc(d.error) + '</span>';
    document.getElementById('diagnose-card').style.display = 'none';
    return;
  }

  const items = [
    { label: 'DebugView++.dblog (chipset)', ok: d.chipset, extra: '' },
    { label: 'uart1-2.log (AT TX)',          ok: d.at_tx,   extra: '' },
    { label: 'uart1-1.log (AT RX)',           ok: d.at_rx,   extra: '' },
    { label: 'wireshark.pcapng (pcap)',       ok: d.pcap,    extra: '' },
    {
      label: 'OTII/*.csv (電流)', ok: d.otii_count > 0,
      extra: d.otii_count > 0 ? ' (' + d.otii_count + ' ファイル)' : ''
    },
  ];

  let html = '';
  items.forEach(it => {
    html += '<div class="detect-item">' +
      '<span class="' + (it.ok ? 'icon-ok' : 'icon-ng') + '">' +
      (it.ok ? '✓' : '✗') + '</span>' +
      '<span>' + esc(it.label) + it.extra + '</span>' +
      '</div>';
  });
  el.style.display = 'block';
  el.innerHTML = html;
  document.getElementById('diagnose-card').style.display = 'block';
  document.getElementById('done-link').style.display = 'none';
  document.getElementById('progress-area').style.display = 'none';
  document.getElementById('progress-bar').style.width = '0%';
  document.getElementById('diagnose-status').textContent = '';
}

async function doDiagnose() {
  const folder = document.getElementById('folder-input').value.trim();
  if (!folder) return;
  stopTaskPoll();
  document.getElementById('done-link').style.display = 'none';
  document.getElementById('diagnose-status').innerHTML = '開始中...';
  document.getElementById('progress-area').style.display = 'block';
  document.getElementById('progress-bar').style.width = '5%';

  const res = await fetch('/api/diagnose', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ folder }),
  });
  const d = await res.json();
  if (d.error) {
    document.getElementById('diagnose-status').textContent = d.error;
    return;
  }
  activeTaskId = d.task_id;
  startTaskPoll();
}

const STEP_KEYWORDS = [
  'ログ検出', 'チップセット', 'AT', 'pcap', '電流',
  'タイムスタンプ', 'データベース', '相関', 'セッション'
];

function stepProgress(step) {
  const idx = STEP_KEYWORDS.findIndex(k => step.includes(k));
  return idx < 0 ? 10 : Math.round((idx + 1) / STEP_KEYWORDS.length * 90) + 5;
}

function startTaskPoll() {
  taskPollTimer = setInterval(async () => {
    if (!activeTaskId) return;
    try {
      const res = await fetch('/api/task/' + activeTaskId);
      const d   = await res.json();
      const step = d.step || '';
      document.getElementById('progress-step').textContent = step;
      document.getElementById('progress-bar').style.width  = stepProgress(step) + '%';
      document.getElementById('diagnose-status').innerHTML =
        '<span class="spinner-ring"></span>';

      if (d.status === 'done') {
        stopTaskPoll();
        document.getElementById('progress-bar').style.width = '100%';
        document.getElementById('diagnose-status').textContent = '';
        doneSessionId = d.session_id;
        document.getElementById('done-link').style.display = 'inline';
      } else if (d.status === 'error') {
        stopTaskPoll();
        document.getElementById('diagnose-status').textContent =
          'エラー: ' + (d.error || '不明');
      }
    } catch (e) {
      // ネットワークエラーは無視して継続
    }
  }, 1000);
}

function stopTaskPoll() {
  if (taskPollTimer) { clearInterval(taskPollTimer); taskPollTimer = null; }
}

function onDoneLink() {
  if (doneSessionId) openSession(doneSessionId);
}

// ══════════════════════════════════════════════════════
//  Tab 2: Sessions
// ══════════════════════════════════════════════════════
async function loadSessions() {
  const res = await fetch('/api/sessions');
  const sessions = await res.json();
  const list  = document.getElementById('sessions-list');
  const empty = document.getElementById('sessions-empty');

  if (!Array.isArray(sessions) || !sessions.length) {
    list.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  list.innerHTML = sessions.map(s => {
    const ts = toJST(s.created_at);
    const sm = s.summary || {};
    const badges = [
      sm.critical > 0 ? '<span class="badge badge-critical">CRITICAL ' + sm.critical + '</span>' : '',
      sm.high     > 0 ? '<span class="badge badge-high">HIGH '     + sm.high     + '</span>' : '',
      sm.medium   > 0 ? '<span class="badge badge-medium">MEDIUM '  + sm.medium   + '</span>' : '',
    ].join('');
    const sid = s.id || '';
    return '<div class="session-card" onclick="openSession(\'' + esc(sid) + '\')">' +
      '<div class="session-header"><span class="session-ts">' + esc(ts) + '</span></div>' +
      '<div class="session-folder">' + esc(s.log_folder || '') + '</div>' +
      (badges ? '<div class="session-badges" style="margin-top:8px">' + badges + '</div>' : '') +
      '</div>';
  }).join('');
}

async function openSession(sessionId) {
  currentSessionId  = sessionId;
  activeFindingIdx  = null;
  chartData         = null;
  switchTab('timeline');
  document.getElementById('timeline-session-label').textContent =
    'セッション: ' + sessionId;
  document.getElementById('tl-empty').style.display = 'none';
  document.getElementById('tl-chart').style.display = 'block';
  await loadFullSession();
}

// ══════════════════════════════════════════════════════
//  Tab 3: Timeline
// ══════════════════════════════════════════════════════

// セッション全体を1回だけロード。以降のFindingクリックはクライアントサイドのみ。
async function loadFullSession() {
  if (!currentSessionId) return;
  setTlLoading(true);
  try {
    const res = await fetch('/api/timeline/' + currentSessionId + '?window_s=86400');
    const d   = await res.json();
    if (d.error) { alert(d.error); return; }
    chartData = d;
    renderFindings(d.findings || []);
    renderChart(d);
  } finally {
    setTlLoading(false);
  }
}

function renderFindings(findings) {
  const sev_order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  activeFindings = [...findings].sort(
    (a, b) => (sev_order[a.severity] ?? 9) - (sev_order[b.severity] ?? 9)
  );
  const list = document.getElementById('findings-list');
  list.innerHTML = activeFindings.map((f, i) => {
    const sev = (f.severity || 'medium').toLowerCase();
    const ts  = (f.trigger_ts || '').slice(11, 23);  // HH:MM:SS.mmm
    return '<div class="finding-item" id="finding-' + i + '" ' +
      'onclick="onFindingClick(' + i + ')">' +
      '<div class="finding-rule">' +
        '<span class="badge badge-' + sev + '">' + sev.toUpperCase() + '</span> ' +
        esc(f.rule_id || '?') +
      '</div>' +
      '<div class="finding-ts">' + esc(ts) + ' UTC</div>' +
      '<div class="finding-diag">' + esc(f.diagnosis || f.rule_desc || '') + '</div>' +
      '</div>';
  }).join('');

  // 選択中の項目のアクティブ状態を復元
  if (activeFindingIdx !== null) {
    const el = document.getElementById('finding-' + activeFindingIdx);
    if (el) el.classList.add('active');
  }
}

function onFindingClick(idx) {
  activeFindingIdx = idx;
  document.querySelectorAll('.finding-item').forEach(el => el.classList.remove('active'));
  const el = document.getElementById('finding-' + idx);
  if (el) { el.classList.add('active'); el.scrollIntoView({ block: 'nearest' }); }
  const f = activeFindings[idx];
  if (!f) return;
  renderRuleDetail(f);

  // ── クライアントサイドのみ（サーバー通信なし）──
  if (!f.trigger_ts || !chartData) return;
  const activeKey = (f.rule_id || '') + '|' + (f.trigger_ts || '');

  // x 軸ズーム範囲を計算
  const center = new Date(hasOffset(f.trigger_ts) ? f.trigger_ts : f.trigger_ts + 'Z');
  const halfMs = TL_WINDOW_S * 500;
  const t_lo = new Date(center.getTime() - halfMs).toISOString().slice(0, 23);
  const t_hi = new Date(center.getTime() + halfMs).toISOString().slice(0, 23);

  // shapes を再構築して x 軸ズームと同時に更新
  Plotly.relayout('tl-chart', {
    'xaxis.range': [t_lo, t_hi],
    shapes: buildShapes(chartData.findings || [], activeKey, chartData.events || [], t_lo, t_hi),
  });

  // ログパネルを更新
  populateLogPanels(t_lo, t_hi);
}

// Findingマーカー + Eventライン の shapes を構築する
function buildShapes(findings, activeKey, events, t_lo, t_hi) {
  const shapes = [];
  const hasActive = activeKey !== null;
  const domLo = chartDomainTop[0];
  const domHi = chartDomainTop[1];

  // Finding トリガー縦線
  findings.forEach(f => {
    if (!f.trigger_ts) return;
    const key = (f.rule_id || '') + '|' + (f.trigger_ts || '');
    const isActive = hasActive && key === activeKey;
    shapes.push({
      type: 'line', xref: 'x', yref: 'paper',
      x0: f.trigger_ts, x1: f.trigger_ts, y0: 0, y1: 1,
      line: {
        color:  isActive ? COLORS.yellow : COLORS.red,
        width:  isActive ? 3 : 1,
        dash:   isActive ? 'solid' : 'dash',
      },
      opacity: isActive ? 1.0 : (hasActive ? 0.25 : 0.55),
    });
  });

  // Event ライン（現在ウィンドウ内のみ）
  const evColor = { at: COLORS.blue, pcap: COLORS.green, current: COLORS.peach };
  let evCount = 0;
  for (const ev of events) {
    if (!ev.ts) continue;
    if (t_lo && ev.ts < t_lo) continue;
    if (t_hi && ev.ts > t_hi) continue;
    if (++evCount > 300) break;
    shapes.push({
      type: 'line', xref: 'x', yref: 'paper',
      x0: ev.ts, x1: ev.ts, y0: domLo, y1: domHi,
      line: { color: evColor[ev.source] || COLORS.text, width: 0.5, dash: 'dot' },
      opacity: 0.35,
    });
  }
  return shapes;
}

function renderRuleDetail(f) {
  const pane   = document.getElementById('rule-detail-pane');
  const ruleEl = document.getElementById('detail-rule');
  if (!f) { pane.style.display = 'none'; return; }
  pane.style.display = 'flex';

  const sev      = (f.severity || 'medium').toLowerCase();
  const ts       = (f.trigger_ts || '').slice(0, 23).replace('T', ' ');
  const srcColor = { at: COLORS.blue, pcap: COLORS.green, current: COLORS.peach };

  const evidenceHtml = (f.evidence || []).map(e => {
    const m    = e.match(/^\[(\w+)\]\s*(.*)/s);
    const src  = m ? m[1] : '';
    const text = m ? m[2] : e;
    const col  = srcColor[src] || COLORS.text;
    return '<div class="detail-ev-item" style="border-left-color:' + col + '">' +
      (src ? '<span style="color:' + col + ';font-weight:600">[' + esc(src) + ']</span> ' : '') +
      esc(text) + '</div>';
  }).join('');

  ruleEl.innerHTML =
    '<div class="detail-col-title">マッチ詳細</div>' +
    '<div class="detail-header">' +
      '<span class="badge badge-' + sev + '">' + sev.toUpperCase() + '</span>' +
      '<span class="detail-rule-id">' + esc(f.rule_id || '') + '</span>' +
      '<span class="detail-rule-desc">' + esc(f.rule_desc || '') + '</span>' +
      '<span class="detail-ts">' + esc(ts) + ' UTC</span>' +
    '</div>' +
    '<div class="detail-diagnosis">' + esc(f.diagnosis || '') + '</div>' +
    '<table class="detail-table">' +
      '<tr><th>トリガー</th><td>[' + esc(f.trigger_source || '') + '] ' +
        esc(f.trigger_raw || '') + '</td></tr>' +
      '<tr><th>確信度</th><td>' + esc(f.confidence || '') + '</td></tr>' +
    '</table>' +
    '<div class="detail-ev-title">マッチした根拠 (' + (f.evidence || []).length + ' 件)</div>' +
    evidenceHtml;
}

function showFullSession() {
  if (!chartData) return;
  activeFindingIdx = null;
  document.querySelectorAll('.finding-item').forEach(el => el.classList.remove('active'));
  document.getElementById('rule-detail-pane').style.display = 'none';
  // x 軸を全体にリセット（クライアントサイドのみ）
  Plotly.relayout('tl-chart', {
    'xaxis.autorange': true,
    shapes: buildShapes(chartData.findings || [], null, chartData.events || [], null, null),
  });
}

function renderChart(d) {
  const wv       = d.waveform  || { t: [], mA: [] };
  const events   = d.events    || [];
  const findings = d.findings  || [];
  const tLo      = d.t_lo;
  const tHi      = d.t_hi;
  const hasWaveform = wv.t && wv.t.length > 0;

  // サブプロット y 軸ドメイン
  const domain_current = hasWaveform ? [0.52, 1.0] : [0.0, 1.0];
  const domain_scatter = [0.0, 0.48];
  chartDomainTop = domain_current;  // buildShapes が参照

  const traces = [];

  // ── 電流波形 ──
  if (hasWaveform) {
    traces.push({
      x: wv.t, y: wv.mA,
      name: '電流 (mA)', mode: 'lines',
      line: { color: COLORS.blue, width: 1 },
      xaxis: 'x', yaxis: 'y',
      hovertemplate: '%{x|%H:%M:%S.%L}<br>%{y:.2f} mA<extra></extra>'
    });
  }

  // shapes を buildShapes で構築（Finding クリック時と共通）
  const activeKey = activeFindingIdx !== null && activeFindings[activeFindingIdx]
    ? (activeFindings[activeFindingIdx].rule_id || '') + '|' +
      (activeFindings[activeFindingIdx].trigger_ts || '')
    : null;
  const shapes = buildShapes(findings, activeKey, events, tLo, tHi);

  // ── イベントスキャッタ ──
  const srcColor = { at: COLORS.blue, pcap: COLORS.green, current: COLORS.peach };
  const grouped = {};
  events.forEach(ev => {
    if (!grouped[ev.source]) grouped[ev.source] = [];
    grouped[ev.source].push(ev);
  });

  Object.entries(grouped).forEach(([src, evs]) => {
    traces.push({
      x: evs.map(e => e.ts),
      y: evs.map(e => e.y),
      mode: 'markers',
      name: src,
      marker: { color: srcColor[src] || COLORS.text, size: 6, opacity: 0.8 },
      xaxis: 'x', yaxis: 'y2',
      text: evs.map(e => e.label),
      hovertemplate: '%{text}<br>%{x|%H:%M:%S.%L}<extra></extra>'
    });
  });

  const layout = {
    paper_bgcolor: COLORS.bg,
    plot_bgcolor:  COLORS.plot,
    font: { color: COLORS.text, size: 11 },
    margin: { l: 64, r: 16, t: 12, b: 40 },
    showlegend: false,
    hovermode: 'x unified',
    uirevision: currentSessionId,   // セッションが変わるまでズーム状態を保持
    hoverlabel: {
      bgcolor: COLORS.plot, bordercolor: COLORS.grid,
      font: { color: COLORS.text }
    },
    shapes: shapes,
    xaxis: {
      range: [tLo, tHi],
      type: 'date',
      gridcolor: COLORS.grid, zerolinecolor: COLORS.zero,
    },
    yaxis: {
      title: hasWaveform ? '電流 (mA)' : '',
      domain: domain_current,
      gridcolor: COLORS.grid, zerolinecolor: COLORS.zero,
    },
    yaxis2: {
      domain: domain_scatter,
      tickvals: [1, 2, 3],
      ticktext: ['AT', 'pcap', 'current'],
      gridcolor: COLORS.grid, zerolinecolor: COLORS.zero,
      range: [0, 4],
    },
  };

  Plotly.react('tl-chart', traces, layout, { responsive: true });
  attachPlotlyListener();
}

// ══════════════════════════════════════════════════════
//  ユーティリティ
// ══════════════════════════════════════════════════════
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function populateLogPanels(t_lo, t_hi) {
  const pcapList = document.getElementById('detail-pcap-list');
  const atList   = document.getElementById('detail-at-list');
  if (!pcapList || !atList) return;

  const empty = '<div class="detail-empty">表示範囲内にデータなし</div>';
  if (!chartData || !chartData.events) {
    pcapList.innerHTML = atList.innerHTML = empty;
    return;
  }

  const inRange = ev => {
    if (!ev.ts) return false;
    if (t_lo && ev.ts < t_lo) return false;
    if (t_hi && ev.ts > t_hi) return false;
    return true;
  };

  const pcapEvts = chartData.events.filter(e => e.source === 'pcap' && inRange(e));
  const atEvts   = chartData.events.filter(e => e.source === 'at'   && inRange(e));

  const renderItems = evts => evts.map(e => {
    const ts   = (e.ts || '').slice(11, 23);
    const text = (e.label || '').replace(/^\[\w+\]\s*/, '');
    const dir  = e.dir
      ? `<span class="at-dir at-dir-${e.dir.toLowerCase()}">${esc(e.dir)}</span>`
      : (e.nas_type ? `<span class="at-dir at-dir-rx">${esc(e.protocol||'NAS')}</span>` : '');
    return `<div class="detail-log-item">
      <span class="detail-log-ts">${esc(ts)}</span>
      ${dir}
      <span class="detail-log-text">${esc(text)}</span>
    </div>`;
  }).join('') || empty;

  pcapList.innerHTML = renderItems(pcapEvts);
  atList.innerHTML   = renderItems(atEvts);
}

let _plotlyListenerAttached = false;
function attachPlotlyListener() {
  if (_plotlyListenerAttached) return;
  _plotlyListenerAttached = true;
  document.getElementById('tl-chart').on('plotly_relayout', ed => {
    const lo = ed['xaxis.range[0]'] ?? (ed['xaxis.range'] && ed['xaxis.range'][0]);
    const hi = ed['xaxis.range[1]'] ?? (ed['xaxis.range'] && ed['xaxis.range'][1]);
    if (lo && hi) populateLogPanels(lo, hi);
  });
}

function hasOffset(s) {
  return s && (s.includes('+') || s.endsWith('Z'));
}

function setTlLoading(on) {
  const el = document.getElementById('tl-loading');
  if (el) el.style.display = on ? 'flex' : 'none';
}

function toJST(isoStr) {
  if (!isoStr) return '';
  // タイムゾーン指定なし(旧UTC形式)は末尾に'Z'を補完してUTCとして解釈
  const hasOffset = isoStr.includes('+') || isoStr.endsWith('Z');
  const d = new Date(hasOffset ? isoStr : isoStr + 'Z');
  return d.toLocaleString('ja-JP', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  });
}

// 初期化
loadSessions();
</script>
</body>
</html>"""


if __name__ == "__main__":
    print("LTE Doctor 起動中... http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=True, use_reloader=False)
