"""
OTIIデータ読み込みスクリプト
==============================
OTII Arc の .otii3 ファイル（dataフォルダ）から
電流・電圧データを読み込みCSVへ出力する。

電圧は直接計測されていないため、電力(P)と電流(I)から
  V = P / I  で算出する（I ≒ 0 の点は NaN）。

使い方:
  python read_otii_data.py <otii3ファイルのパス> [オプション]

例:
  python read_otii_data.py "D:/data/20260413.otii3"
  python read_otii_data.py "D:/data/20260413.otii3" --recording 0 --output out.csv
  python read_otii_data.py "D:/data/20260413.otii3" --list
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import numpy as np
import pandas as pd


# ── ユーティリティ ────────────────────────────────────────────────────────────

def find_data_dir(otii3_path: str) -> str:
    """
    .otii3 ファイルと同じ階層にある 'data' フォルダを返す。
    存在しない場合は ValueError を送出。
    """
    base = os.path.dirname(os.path.abspath(otii3_path))
    data_dir = os.path.join(base, "data")
    if not os.path.isdir(data_dir):
        raise ValueError(
            f"'data' フォルダが見つかりません: {data_dir}\n"
            ".otii3 ファイルと同じ場所に 'data' フォルダが必要です。"
        )
    return data_dir


def load_project_json(data_dir: str) -> dict:
    """
    data/versions/<最新uuid>/data/project.json を読み込んで返す。
    """
    # versions フォルダ内の最初のUUIDフォルダを使用
    versions_dir = os.path.join(data_dir, "versions")
    if not os.path.isdir(versions_dir):
        raise FileNotFoundError(f"versions フォルダが見つかりません: {versions_dir}")

    uuid_dirs = [
        d for d in os.listdir(versions_dir)
        if os.path.isdir(os.path.join(versions_dir, d))
    ]
    if not uuid_dirs:
        raise FileNotFoundError("versions フォルダ内にデータがありません。")

    project_json_path = os.path.join(
        versions_dir, uuid_dirs[0], "data", "project.json"
    )
    if not os.path.isfile(project_json_path):
        raise FileNotFoundError(f"project.json が見つかりません: {project_json_path}")

    with open(project_json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_samples(data_dir: str, samples_id: str) -> np.ndarray:
    """
    data/data/project/<samples_id>/samples.dat を
    float32 の numpy 配列として読み込む。
    """
    path = os.path.join(data_dir, "data", "project", samples_id, "samples.dat")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"samples.dat が見つかりません: {path}")
    return np.fromfile(path, dtype="<f4")  # リトルエンディアン float32


# ── 録画情報の解析 ────────────────────────────────────────────────────────────

def parse_recordings(project: dict) -> list[dict]:
    """
    project.json の recordings[] を解析して
    各録画の情報（インデックス・開始時刻・電流/電力データID）を返す。
    """
    # measurement_id → data_type マッピングを作成
    mtype = {m["id"]: m["source"]["data_type"] for m in project.get("measurements", [])}

    results = []
    for idx, rec in enumerate(project.get("recordings", [])):
        start_ms = rec.get("start_time", 0)
        start_dt = datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc).astimezone()

        info = {
            "index": idx,
            "recording_id": rec["id"],
            "start_ms": start_ms,
            "start_dt": start_dt,
            "current_data_id": None,
            "power_data_id": None,
            "current_sample_rate": None,
            "power_sample_rate": None,
        }

        for entry in rec.get("data", []):
            dtype = mtype.get(entry["measurement"]["id"])
            sid = entry.get("data", {}).get("id")
            sr = entry["measurement"]["source"].get("sample_rate")
            if dtype == "current":
                info["current_data_id"] = sid
                info["current_sample_rate"] = sr
            elif dtype == "power":
                info["power_data_id"] = sid
                info["power_sample_rate"] = sr

        results.append(info)
    return results


# ── データ読み込みと変換 ──────────────────────────────────────────────────────

def load_recording(data_dir: str, rec_info: dict) -> pd.DataFrame:
    """
    1つの録画セッションから電流・電圧の DataFrame を返す。

    カラム:
        timestamp_s   : 録画開始からの経過秒（float）
        datetime      : 実時刻（ローカルタイムゾーン）
        current_A     : 電流 [A]
        power_W       : 電力 [W]（内部計算用）
        voltage_V     : 電圧 [V]（= power / current、I≒0はNaN）
    """
    # 電流データ読み込み
    if rec_info["current_data_id"] is None:
        raise ValueError("電流データ (mc) が録画に含まれていません。")

    current = load_samples(data_dir, rec_info["current_data_id"])
    sr_c = rec_info["current_sample_rate"] or 4000

    # 電力データ読み込み（電圧算出用）
    power = None
    if rec_info["power_data_id"] is not None:
        power = load_samples(data_dir, rec_info["power_data_id"])
        sr_p = rec_info["power_sample_rate"] or 4000

        # サンプルレートが違う場合は電流に合わせてリサンプル
        if sr_p != sr_c:
            # 簡易リサンプル：長さを電流サンプル数に合わせる
            ratio = sr_c / sr_p
            new_len = len(current)
            indices = np.linspace(0, len(power) - 1, new_len)
            power = np.interp(indices, np.arange(len(power)), power)

        # サンプル数を揃える（短い方に合わせる）
        n = min(len(current), len(power))
        current = current[:n]
        power = power[:n]
    else:
        n = len(current)

    # タイムスタンプ生成（録画開始からの経過秒）
    start_s = rec_info["start_ms"] / 1000.0
    t_relative = np.arange(n) / sr_c  # 録画開始からの経過秒
    t_absolute = start_s + t_relative  # Unix秒

    # 実時刻
    dt_list = pd.to_datetime(t_absolute, unit="s", utc=True).tz_convert(None)

    # 電圧算出（V = P / I）
    if power is not None:
        with np.errstate(divide="ignore", invalid="ignore"):
            voltage = np.where(np.abs(current) > 1e-9, power / current, np.nan)
    else:
        voltage = np.full(n, np.nan)

    df = pd.DataFrame({
        "timestamp_s": t_relative,
        "datetime": dt_list,
        "current_A": current,
        "power_W": power if power is not None else np.full(n, np.nan),
        "voltage_V": voltage,
    })
    return df


# ── CSV 出力 ──────────────────────────────────────────────────────────────────

def save_csv(df: pd.DataFrame, output_path: str, decimation: int = 1) -> None:
    """
    DataFrame を CSV に保存する。
    decimation > 1 の場合は間引きして出力（ファイルサイズ削減）。
    """
    if decimation > 1:
        df = df.iloc[::decimation].reset_index(drop=True)

    df_out = df[["timestamp_s", "datetime", "current_A", "voltage_V", "power_W"]].copy()
    df_out.to_csv(output_path, index=False, float_format="%.8g")
    print(f"  → 保存完了: {output_path}  ({len(df_out):,} 行)")


# ── メイン ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OTII .otii3 から電流・電圧データを読み込みCSVへ出力"
    )
    parser.add_argument(
        "otii3",
        help=".otii3 ファイルのパス（同階層に data フォルダが必要）"
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="録画セッション一覧を表示して終了"
    )
    parser.add_argument(
        "--recording", "-r",
        type=int,
        default=None,
        help="出力する録画番号（0始まり）。省略時は全録画を出力"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="出力CSVファイルパス。省略時は自動命名"
    )
    parser.add_argument(
        "--decimation", "-d",
        type=int,
        default=1,
        help="間引き率（例: 4 → 4000Hz → 1000Hz相当）。デフォルト: 1（間引きなし）"
    )
    parser.add_argument(
        "--no-power",
        action="store_true",
        help="power_W カラムを出力しない"
    )
    args = parser.parse_args()

    # ── データ読み込み ──
    print(f"OTIIファイル: {args.otii3}")
    try:
        data_dir = find_data_dir(args.otii3)
        project = load_project_json(data_dir)
    except (ValueError, FileNotFoundError) as e:
        print(f"[エラー] {e}", file=sys.stderr)
        sys.exit(1)

    recordings = parse_recordings(project)

    if not recordings:
        print("[エラー] 録画データが見つかりません。", file=sys.stderr)
        sys.exit(1)

    # ── 一覧表示 ──
    print(f"\n録画セッション数: {len(recordings)}")
    for r in recordings:
        has_v = "○" if r["power_data_id"] else "×"
        print(
            f"  [{r['index']}] 開始: {r['start_dt'].strftime('%Y-%m-%d %H:%M:%S %Z')}"
            f"  電流: {'○' if r['current_data_id'] else '×'}"
            f"  電圧算出: {has_v}"
            f"  (サンプルレート: {r['current_sample_rate']} Hz)"
        )

    if args.list:
        return

    # ── 処理対象の決定 ──
    if args.recording is not None:
        if args.recording < 0 or args.recording >= len(recordings):
            print(
                f"[エラー] 録画番号 {args.recording} は範囲外です "
                f"(0 〜 {len(recordings)-1})",
                file=sys.stderr,
            )
            sys.exit(1)
        targets = [recordings[args.recording]]
    else:
        targets = recordings

    # ── 各録画を処理 ──
    base_name = os.path.splitext(os.path.basename(args.otii3))[0]
    out_dir = os.path.dirname(os.path.abspath(args.otii3))

    for rec in targets:
        idx = rec["index"]
        print(f"\n録画 [{idx}] を処理中...")
        try:
            df = load_recording(data_dir, rec)
        except (FileNotFoundError, ValueError) as e:
            print(f"  [スキップ] {e}")
            continue

        # 統計表示
        print(f"  サンプル数: {len(df):,} ({len(df)/( rec['current_sample_rate'] or 4000):.1f} 秒)")
        print(f"  電流: min={df['current_A'].min()*1000:.3f} mA  "
              f"max={df['current_A'].max()*1000:.3f} mA  "
              f"mean={df['current_A'].mean()*1000:.3f} mA")
        if df["voltage_V"].notna().any():
            v = df["voltage_V"].dropna()
            print(f"  電圧: min={v.min():.4f} V  max={v.max():.4f} V  mean={v.mean():.4f} V")
        else:
            print("  電圧: データなし（電力データがありません）")

        # CSV保存
        if args.output and len(targets) == 1:
            out_path = args.output
        else:
            start_str = rec["start_dt"].strftime("%Y%m%d_%H%M%S")
            out_path = os.path.join(out_dir, f"{base_name}_rec{idx}_{start_str}.csv")

        if args.no_power:
            df = df.drop(columns=["power_W"])

        save_csv(df, out_path, decimation=args.decimation)

    print("\n完了。")


if __name__ == "__main__":
    main()