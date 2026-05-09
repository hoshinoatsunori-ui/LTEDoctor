"""
otii_parser.py
OTII Arc が出力した CSV から電流消費イベントを検出する。

検出イベント:
  EVT_PEAK_CURRENT  : 短時間の電流ピーク（閾値超過が MIN_ACTIVE_S 未満）
  EVT_RADIO_ACTIVE  : ラジオアクティブ区間（閾値超過が MIN_ACTIVE_S 以上継続）
  EVT_CURRENT_DROP  : スリープ移行（閾値を下回った瞬間）

検出パラメータ (PEAK_MA / SLEEP_MA) はデバイスに合わせて調整してください。
"""

from dataclasses import dataclass
from datetime import datetime

import numpy as np
import pandas as pd

# ── 検出パラメータ ───────────────────────────────────────────────────────────
DETECT_HZ    = 100      # 検出用ダウンサンプル後レート [Hz]
SMOOTH_WIN   = 5        # ローリング中央値ウィンドウ（サンプル数、50ms @100Hz）
PEAK_MA      = 30.0     # ラジオアクティブ判定閾値 [mA]
SLEEP_MA     = 2.0      # スリープ判定閾値 [mA]
MIN_ACTIVE_S = 0.10     # EVT_RADIO_ACTIVE の最小継続時間 [s]
DEBOUNCE_S   = 0.05     # 連続エッジの最小間隔（チャタリング除去） [s]


@dataclass
class CurrentEvent:
    event_type:  str       # "EVT_PEAK_CURRENT" / "EVT_RADIO_ACTIVE" / "EVT_CURRENT_DROP"
    utc_ts:      datetime  # UTC（OTII datetime カラムは UTC として扱う）
    value_ma:    float     # 電流値 [mA]
    duration_s:  float     # 区間継続時間 [s]（RADIO_ACTIVE のみ有意）
    raw_text:    str = ""
    source_file: str = ""


def parse_csv(
    csv_path: str,
    peak_ma:      float = PEAK_MA,
    sleep_ma:     float = SLEEP_MA,
    min_active_s: float = MIN_ACTIVE_S,
) -> list[CurrentEvent]:
    """OTII CSV を読んで電流消費イベントのリストを返す。"""
    df = pd.read_csv(csv_path)

    required = {"timestamp_s", "datetime", "current_A"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"必須カラムがありません: {missing} in {csv_path}")

    df["datetime"] = pd.to_datetime(df["datetime"])
    if len(df) < 2:
        return []

    # サンプルレート推定（先頭 1001 点の差分中央値）
    diff = np.diff(df["timestamp_s"].values[:1001])
    pos  = diff[diff > 0]
    dt_s = float(np.median(pos)) if len(pos) > 0 else 0.00025
    orig_hz = int(round(1.0 / dt_s)) if dt_s > 0 else 4000

    # 検出用ダウンサンプル
    dec   = max(1, orig_hz // DETECT_HZ)
    df_ds = df.iloc[::dec].reset_index(drop=True)
    n     = len(df_ds)

    current_ma = (df_ds["current_A"] * 1000).values.astype(float)
    # ローリング中央値でノイズ除去
    smooth = (
        pd.Series(current_ma)
        .rolling(SMOOTH_WIN, center=True, min_periods=1)
        .median()
        .values
    )

    dt_ds = 1.0 / (orig_hz / dec)  # 検出レートのサンプル間隔 [s]

    above = smooth >= peak_ma
    below = smooth <= sleep_ma

    above_edge = np.concatenate([[0], np.diff(above.astype(int))])
    below_edge = np.concatenate([[0], np.diff(below.astype(int))])

    events: list[CurrentEvent] = []
    last_peak_ts = None
    last_drop_ts = None

    for i in range(n):
        ts  = df_ds.loc[i, "datetime"]
        val = float(smooth[i])

        # 上昇エッジ: スリープ → ラジオアクティブ
        if above_edge[i] == 1:
            if last_peak_ts is None or (ts - last_peak_ts).total_seconds() > DEBOUNCE_S:
                last_peak_ts = ts
                # アクティブ区間の終端を探す
                end_i = i
                for j in range(i + 1, n):
                    if smooth[j] < peak_ma:
                        break
                    end_i = j
                duration = (end_i - i) * dt_ds
                peak_val = float(smooth[i : end_i + 1].max())

                if duration >= min_active_s:
                    ev_type = "EVT_RADIO_ACTIVE"
                    text    = f"radio active peak={peak_val:.1f}mA dur={duration:.2f}s"
                else:
                    ev_type = "EVT_PEAK_CURRENT"
                    text    = f"current peak {peak_val:.1f}mA ({duration * 1000:.0f}ms)"

                events.append(CurrentEvent(
                    event_type  = ev_type,
                    utc_ts      = ts,
                    value_ma    = round(peak_val, 3),
                    duration_s  = round(duration, 4),
                    raw_text    = text,
                    source_file = csv_path,
                ))

        # 下降エッジ: ラジオアクティブ → スリープ
        if below_edge[i] == 1:
            if last_drop_ts is None or (ts - last_drop_ts).total_seconds() > DEBOUNCE_S:
                last_drop_ts = ts
                events.append(CurrentEvent(
                    event_type  = "EVT_CURRENT_DROP",
                    utc_ts      = ts,
                    value_ma    = round(val, 4),
                    duration_s  = 0.0,
                    raw_text    = f"current drop to {val:.2f}mA",
                    source_file = csv_path,
                ))

    events.sort(key=lambda e: e.utc_ts)
    return events


def summary(events: list[CurrentEvent]) -> dict:
    """検出イベントのサマリーを返す。"""
    from collections import Counter
    c = Counter(e.event_type for e in events)
    return {
        "total":             len(events),
        "EVT_PEAK_CURRENT":  c.get("EVT_PEAK_CURRENT", 0),
        "EVT_RADIO_ACTIVE":  c.get("EVT_RADIO_ACTIVE", 0),
        "EVT_CURRENT_DROP":  c.get("EVT_CURRENT_DROP", 0),
    }
