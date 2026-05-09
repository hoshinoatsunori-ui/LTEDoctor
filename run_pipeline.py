"""
run_pipeline.py  - LTE診断フルパイプライン
  1. ログパース（AT / chipset / pcap）
  2. タイムスタンプ整合
  3. DB格納
  4. イベント相関（Ph.3）
  5. 診断レポート出力
"""
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)

import glob
import chipset_parser, at_parser, pcap_parser, time_aligner, db_store, event_correlator
import otii_parser

# ── 1. パース ──────────────────────────────────────────────────
print("=== [1] ログパース ===", flush=True)
chip_recs = chipset_parser.parse_file("logs/DebugView++.dblog")
at_recs   = at_parser.parse_tx_rx_pair("logs/uart1-2.log", "logs/uart1-1.log")
pcap_recs = pcap_parser.parse_file("logs/wireshark.pcapng")

# OTII CSV（logs/OTII/*.csv を全件取り込む）
otii_csvs    = sorted(glob.glob("logs/OTII/*.csv"))
current_evts = []
for csv_path in otii_csvs:
    try:
        evts = otii_parser.parse_csv(csv_path)
        current_evts.extend(evts)
        print(f"  OTII    : {csv_path}  → {len(evts)} イベント検出")
    except Exception as e:
        print(f"  OTII    : {csv_path}  [スキップ] {e}")

print(f"  chipset : {len(chip_recs)} 件")
print(f"  AT      : {len(at_recs)} 件")
print(f"  pcap    : {len(pcap_recs)} 件")
print(f"  current : {len(current_evts)} イベント（OTII {len(otii_csvs)} ファイル）")

# ── 2. タイムスタンプ整合 ──────────────────────────────────────
print("\n=== [2] タイムスタンプ整合 ===", flush=True)
chip_result = time_aligner.align_chipset(chip_recs)
at_result   = time_aligner.align_at_log(at_recs)
time_aligner.print_align_report([chip_result, at_result])

# ── 3. DB格納 ──────────────────────────────────────────────────
print("\n=== [3] DB格納 ===", flush=True)
db = db_store.DiagDb("diag.sqlite")
n_chip    = db.insert_chipset(chip_recs)
n_at      = db.insert_at(at_recs)
n_pcap    = db.insert_pcap(pcap_recs)
n_current = db.insert_current(current_evts)
print(f"  chipset_events : {n_chip} 件")
print(f"  at_events      : {n_at} 件")
print(f"  pcap_events    : {n_pcap} 件")
print(f"  current_events : {n_current} 件")

# ── 4. イベント相関 ────────────────────────────────────────────
print("\n=== [4] イベント相関 (Ph.3) ===", flush=True)
results = event_correlator.correlate(db)

# ── 5. 診断レポート ────────────────────────────────────────────
print("\n=== [5] 診断レポート ===", flush=True)
event_correlator.print_summary(results)

# チップセット・ATサマリーも出力
print("\n--- chipset サマリー ---")
import json
cs = chipset_parser.summary(chip_recs)
print(json.dumps(cs, indent=2, ensure_ascii=False, default=str))

print("\n--- AT サマリー ---")
at_s = at_parser.summary(at_recs)
print(json.dumps(at_s, indent=2, ensure_ascii=False, default=str))

print("\n--- pcap サマリー ---")
pc_s = pcap_parser.summary(pcap_recs)
print(json.dumps(pc_s, indent=2, ensure_ascii=False, default=str))

db.close()
