# LTE Multi-Source Log Diagnostic System
# Claude Code 引き継ぎコンテキスト

## プロジェクト概要

Sierra Wireless HL78xx/HL79xx (Sony ALT1250チップセット) LTE-Mモジュールの
複数種類のログを統合し、通信健全性の診断・原因推定を行うPythonシステム。

**開発体制**: Finetek社 組み込みソフトウェアエンジニア（充紀）が設計・実装

---

## 実装済みモジュール（Ph.1〜Ph.3）

```
chipset_parser.py   DebugView++ (.dblog) チップセットログパーサー
at_parser.py        ATコマンドログパーサー（TX/RX分離ファイル対応）
pcap_parser.py      Wireshark pcap/pcapng パーサー（scapy/tshark/EPD自動選択）
time_aligner.py     タイムスタンプ整合エンジン（アンカー内挙法）
db_store.py         SQLite中間ストア（pcap_events/correlated_events/anchors追加済み）
event_correlator.py イベント相関エンジン (Ph.3) ← New
rules.yaml          相関ルール定義 R-001〜R-007 ← New
run_pipeline.py     フルパイプライン実行スクリプト ← New
```

---

## 対象ログ種別と取得済みサンプル

| # | ログ種別 | ファイル | 状態 |
|---|---------|---------|------|
| 1 | ATコマンドログ TX | uart1-2.log | ✅ 実サンプル取得・パーサー実装済 |
| 2 | ATコマンドログ RX | uart1-1.log | ✅ 実サンプル取得・パーサー実装済 |
| 3 | チップセットログ | DebugView__.dblog | ✅ 実サンプル取得・パーサー実装済 |
| 4 | モジュール側Wireshark | wireshark.pcapng | ✅ 解析済（EPD形式、NAS/RRC完全デコード）|
| 5 | 消費電流時系列 | 未取得 | ❌ 未実装 |
| 6 | 通信先Wireshark | 未取得 | ❌ 未実装 |

---

## ログフォーマット仕様（実機確認済み）

### チップセットログ (DebugView++ .dblog)
```
# 外側: タブ区切り5列
{dbv_rel_sec}\t{YYYY/MM/DD HH:MM:SS.mmm}\t{PID}\t{process}\t{payload}

# LogCreator.exe のペイロード（UMAC内部ログ）
{datetime} , {ip} , UMAC , {tick_us} , {level} ,"{message}" , {file} , {line} , {module}
```
- `tick_us`: チップ起動からの経過時間 **マイクロ秒**（`EMERGENCY "logs timestamp unit: US"` で確定）
- `ConsoleD.exe` の `findPacket() failed` 行はパーサーで自動除外
- 起動アンカー: `"Initialising the system..."` (tick_us=833,074)
- ATコリレーションアンカー: `"AT_Entry: Rat in use = CATM"`

### ATコマンドログ（TX/RX分離ファイル）
```
[YYYY-MM-DD HH:MM:SS.mmm] {payload}
```
- **uart1-2.log** = TX（ホスト→モジュール）: ATコマンドのみ
- **uart1-1.log** = RX（モジュール→ホスト）: OK/URC/中間レスポンス

**重要な観測事項（実サンプルより）**:
- `+KSUP: 0` = モジュールリセット完了通知（カーネル起動）
- 17:09〜17:13の約4分間でリセット**9回**、Band1での接続失敗を繰り返す
- 17:12:35に `AT+KBNDCFG=0,1→0,40000` でBand40に切替
- **唯一の接続成功**: 17:13:57.722 `+CEREG: 1`（Band40で登録）
- **接続崩壊**: 17:14:50 `+KCNX_IND: 1,5,30`（PDNエラー cause=30）→49秒で切断
- `+CCLK: "26/04/13,17:12:58+36"` → モジュール内部時刻はJST(UTC+9)
- RSRP推移: -109dBm → -97dBm → -98dBm（Band40切替後に改善）
- `at%custwa=` はSierra固有ATコマンド（セル探索閾値設定）

### タイムスタンプ整合（アンカー内挙法）

| ログ | タイムスタンプ基準 | 信頼度 |
|------|-----------------|-------|
| pcap | UTC絶対時刻 | HIGH（基準軸）|
| ATログ | PC絶対時刻 | MEDIUM（pcapアンカーで補正可）|
| チップセット | チップ起動からのμs | MEDIUM→HIGH（boot anchor使用）|
| 消費電流 | サンプリング間隔 | LOW（アンカー指定が必要）|

**チップ起動時刻の推定**:
```python
# アンカー: "Initialising the system..." tick_us=833,074
# 推定起動時刻 = dbv_abs_ts - tick_us/1e6
#             = 17:09:25.869 - 0.833074s ≈ 17:09:25.036
```

**+CCLK時刻ずれ**:
- AT+CCLK?送信: 17:13:58.056
- 応答内モジュール時刻: 17:12:58 (JST)
- PC時刻との差: 約+60秒（モジュール内部時計が約1分遅れ）
- ただしJSTとUTCの変換(+9h)に注意

---

## SQLiteスキーマ（db_store.py）

```sql
-- 主要テーブル
chipset_events  : is_umac=1 のUMACレコード、utc_ts_est, align_confidence
at_events       : TX/RX両方、is_command/is_response/is_urc フラグ付き
pcap_*_events   : (未実装) pcapレコード
correlated_events: (未実装) event_correlator の出力
anchors         : (未実装) 整合情報の保存
```

---

## イベント定義（event_correlator.py で実装予定）

```yaml
# 設計書 Rev1.0 より
EVT_ATTACH       : +CEREG:1 または NAS Attach Accept
EVT_DETACH       : +CEREG:0 または NAS Detach
EVT_TX           : AT+KUDPSND / UDPパケット検出
EVT_RX           : +KUDP_DATA / TCPペイロード
EVT_PEAK_CURRENT : 電流ピーク閾値超過
EVT_RADIO_SILENT : パケット空白 + 電流下降
EVT_NWREJECT     : Attach Reject / EMM cause
EVT_TIMEOUT      : ATコマンドにOK/ERRなし
```

## 相関ルール定義（rules.yaml で外部管理）

```yaml
- id: R-001
  description: "送信中切断"
  trigger:
    event: EVT_DETACH
  conditions:
    - source: pcap_module
      match: "NAS Attach Accept なし"
      within_ms: 5000
  severity: high
  diagnosis: "送信中切断: ネットワーク起因の疑性"

- id: R-002
  description: "ATコマンドタイムアウト連続"
  trigger:
    event: EVT_TIMEOUT
    count: 3
    window_ms: 30000
  severity: high
  diagnosis: "UART通信障害の疑い"
```

---

## 次に実装すべきもの（優先順）

### Ph.3: event_correlator.py ✅ 完了
```
# 実装済み内容:
# 1. SQLiteから at_events/pcap_events の統合クエリでイベント抽出
# 2. rules.yaml (PyYAML) でルール R-001〜R-007 読み込み
# 3. 時間窓内でトリガー+条件 (absent含む) を評価
# 4. correlated_events / anchors テーブルに書き込み
#
# 実際の検出結果:
#   R-001 HIGH: DETACH 26件（Band1失敗繰り返し + pcap Detach at 17:14:51）
#   R-003 HIGH: +KCNX_IND:1,5,30 at 17:14:50（PDN接続エラー）
#   R-004 MEDIUM: +CEREG:1 at 17:13:57 → 2分以内に切断
#   R-006 HIGH: +KSUP:0 リセット多発 at 17:09:29
```

### Ph.4: reporter.py（CLIレポート）
```python
# 実装すること
# 1. correlated_events を読み込み
# 2. タイムライン形式でASCII出力
# 3. 信頼度LOW時は免責事項を付加
# 4. JSON出力オプション
```

### pcapng解析結果（wireshark.pcapng）✅ 解析済

**フォーマット**: LINKTYPE_WIRESHARK_UPPER_PDU (252) — Sierra Wireless HL78xx モジュール内部キャプチャ
- pcap_parser.py に `parse_file_epd()` を追加、`_detect_epd_linktype()` で自動選択

**93パケット / 17:07:59〜17:17:51 UTC (592秒)**

```
プロトコル分布:
  lte_rrc.bcch_dl_sch_br : 42  (SIB ブロードキャスト)
  lte_rrc.bcch_bch       : 13  (MIB ブロードキャスト)
  nas-eps                : 12  (NAS EPS メッセージ)
  lte_rrc.dl_dcch        : 11  (DL 専用制御チャネル)
  lte_rrc.ul_dcch        : 10  (UL 専用制御チャネル)
  logcat                 :  2  (モジュール起動ログ)
  + RRC CCCH / nas-eps_plain 等
```

**NAS シーケンス (17:13:58〜17:14:54)**
```
17:13:58.311  Identity request / response        ← ネットワークが IMSI を要求
17:13:58.568  Authentication request / response  ← AKA 認証
17:13:58.822  (protected) Security mode command  ← 暗号化開始
17:13:58.886  EMM-0x5E                           ← Security mode complete?
17:13:59.078  (protected) ESM info request
17:13:59.141  ESM info response (plain)
17:13:59.919  (protected) Attach accept           ← 接続成功 EVT_ATTACH
17:13:59.983  Attach complete (plain)              ← UE 確認
17:14:00.191  (protected) EMM information
17:14:51.763  Detach request (plain)              ← ネットワーク起因 EVT_DETACH
17:14:54.068  (protected) Detach accept
```

**pcap×ATログ クロス確認**
- `+CEREG: 1` (AT: 17:13:57.722) ≒ Attach accept (pcap: 17:13:59.919) → 差 ≈ 2.2秒
  （pcap と AT ログは同一PCだが異なるソフト → クロック差または処理遅延）
- `+KCNX_IND: 1,5,30` (AT: 17:14:50) ≒ Detach request (pcap: 17:14:51.763) → 差 ≈ 1.8秒
- 17:07:59〜17:12:59 の pcap 空白期間 = Band1 での接続失敗ループ（AT ログのリセット 9回）
- 17:12:59〜17:13:58 の RRC BCCH = Band40 セル取得フェーズ（KBNDCFG 変更後 24秒）

### Ph.6: dashboard.py（Flask + Plotly.js）
```python
# 既存の HL7900ダッシュボードアーキテクチャを流用
# タブ構成:
#   Timeline / AT Commands / Current Profile /
#   Radio Events / Chipset Log / Diagnosis
```

---

## 使い方（基本フロー）

```bash
# フルパイプライン実行（推奨）
python run_pipeline.py
```

```python
import chipset_parser, at_parser, pcap_parser, time_aligner, db_store, event_correlator

# 1. パース
chip_recs = chipset_parser.parse_file("logs/DebugView++.dblog")
at_recs   = at_parser.parse_tx_rx_pair("logs/uart1-2.log", "logs/uart1-1.log")
pcap_recs = pcap_parser.parse_file("logs/wireshark.pcapng")  # EPD自動検出

# 2. 時刻整合
time_aligner.align_chipset(chip_recs)
time_aligner.align_at_log(at_recs)

# 3. DBに格納
db = db_store.DiagDb("diag.sqlite")
db.insert_chipset(chip_recs)
db.insert_at(at_recs)
db.insert_pcap(pcap_recs)

# 4. 相関診断 (Ph.3)
results = event_correlator.correlate(db)
event_correlator.print_summary(results)
```

---

## 依存パッケージ

```
scapy          # pcapパース（必須）
pyshark        # pcapパース（オプション、tshark連携）
flask          # ダッシュボード（Ph.6）
plotly         # グラフ描画（Ph.6）
pyyaml         # rules.yaml読み込み（Ph.3）
```

```bash
pip install scapy pyshark pyyaml flask plotly
```

---

## 設計書

`LTE_MultiLog_Diagnostic_Design_v1.0.docx` を参照（別途配布）
