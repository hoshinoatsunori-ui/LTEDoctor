---
title: "LTE-Mモジュール通信障害の原因を自動特定：ATログ・pcap・消費電流の統合解析ツール"
tags:
  - Python
  - LTE
  - IoT
  - Flask
  - 組み込み
private: false
updated_at: ''
id: null
organization_url_name: null
slide: false
ignorePublish: false
---

## TL;DR

Sierra Wireless HL78xx/HL79xx（Sony ALT1250チップセット）LTE-Mモジュールの通信障害を診断するPythonツール「LTE Doctor」を作った。ATコマンドログ（TX/RX）、チップセットログ（DebugView++.dblog）、Wireshark pcapng（EPD形式）、OTII Arc消費電流CSVの4種のログを統合し、タイムスタンプを自動整合、10本の診断ルールで原因を自動特定する。FlaskのWebダッシュボードで電流波形とイベントを重ねて可視化できる。

---

## 背景

LTE-Mモジュールのフィールドトラブルで「突然切断される」「接続に時間がかかる」といった症状が出たとき、原因特定のために複数種類のログを突合する必要がある。

問題は、各ログのタイムスタンプ基準がバラバラな点だ。

- ATログはPCのシステム時刻（JST）
- チップセットログはチップ起動からの経過マイクロ秒
- Wireshark pcapはUTC絶対時刻
- OTII電流ログは測定開始からの相対時刻

手動でエクセルに貼って突合する作業が発生し、1件の解析に半日かかることもあった。LTE Doctorはこの作業を自動化するために作ったツールだ。

---

## セットアップ

### インストール

```bash
pip install scapy pyshark pyyaml flask plotly pandas
```

### フォルダ構成

```
LTEDoctor/
  logs/
    uart1-2.log          # AT TX（ホスト→モジュール送信）
    uart1-1.log          # AT RX（モジュール→ホスト受信）
    DebugView++.dblog    # チップセットログ
    wireshark.pcapng     # Wireshark キャプチャ（EPD形式）
    otii_arc.csv         # OTII Arc消費電流CSV
  at_parser.py
  chipset_parser.py
  pcap_parser.py
  otii_parser.py
  otii2csv.py
  time_aligner.py
  db_store.py
  event_correlator.py
  rules.yaml
  run_pipeline.py
  doctor.py
  diag.sqlite            # 実行後に生成
```

### ログの準備

ATコマンドログはTX（送信側）とRX（受信側）を別ファイルで用意する。UART通信をシリアルモニタで記録する場合、多くのツールが片方向のみのファイル出力に対応している。

OTII ArcのデータはOTIIアプリからCSVエクスポートするか、独自バイナリ形式の場合は付属の変換スクリプトを使う。

---

## 使い方（3ステップ）

### Step 1：電流データの変換

OTII Arcの記録形式が独自バイナリの場合は先に変換する。

```bash
python otii2csv.py --input otii_arc.otii --output logs/otii_arc.csv
```

CSVの形式は `timestamp,current_mA` の2列。タイムスタンプはISO 8601（UTC）形式を想定している。

### Step 2：フルパイプラインの実行

```bash
python run_pipeline.py
```

内部で以下が順番に実行される。

1. 4種のログをパースして構造化レコードに変換
2. アンカー内挿法でタイムスタンプをUTCに整合
3. SQLiteデータベース（`diag.sqlite`）に格納
4. `rules.yaml` の10本の診断ルールを評価
5. 検出した相関イベントをDBに書き込み
6. コンソールに診断サマリーを出力

### Step 3：WebダッシュボードでUIを開く

```bash
python doctor.py
```

ブラウザで `http://localhost:5001` を開く。3タブのUIが表示される。

- **Setup**：ログファイルパスの設定、パイプライン実行
- **Sessions**：検出されたLTEセッション一覧と診断結果サマリー
- **Timeline**：OTII電流波形（Plotly）＋イベントスキャッタープロット＋3カラム詳細ペイン

---

## 仕組みの解説

### データフロー

```
各ログファイル
    ↓ [各パーサー]
構造化レコード（Pythonリスト）
    ↓ [time_aligner.py]
UTC整合済みレコード
    ↓ [db_store.py]
SQLite（7テーブル）
    ↓ [event_correlator.py]
EVT_*イベント + ルール評価結果
    ↓ [doctor.py]
Webダッシュボード表示
```

### 4つのパーサー

**at_parser.py** はTX/RXの分離ファイルを読み込み、各行をATコマンド / レスポンス / URCに分類する。`+KSUP: 0`（モジュールリセット完了）や `+CEREG: 1`（ネットワーク登録成功）などのURCを自動抽出する。

**chipset_parser.py** はDebugView++の `.dblog` 形式（タブ区切り5列）をパースし、`LogCreator.exe` が出力するUMAC内部ログを抽出する。`ConsoleD.exe` の `findPacket() failed` 行はノイズとして自動除外する。

**pcap_parser.py** はpcapngファイルを読み込む際にリンクタイプを自動検出し、DLT=252（LINKTYPE_WIRESHARK_UPPER_PDU）のEPD形式に対応した `parse_file_epd()` を使う。NAS/RRCメッセージを構造化して取り出す。

**otii_parser.py** はCSVをpandas DataFrameとして読み込み、`DatetimeIndex` を設定してメモリキャッシュする。

### タイムスタンプ整合（アンカー内挿法）

チップセットログの `tick_us`（チップ起動からの経過マイクロ秒）をUTCに変換する例：

```python
# ブートアンカー: "Initialising the system..." が出現した行
# dbv_abs_ts: DebugView++がこの行を記録したPC絶対時刻
# tick_at_anchor: このメッセージの tick_us = 833,074

boot_time_est = dbv_abs_ts - timedelta(microseconds=tick_at_anchor)
# → 2026-04-13 17:09:25.036 UTC

# 任意のレコードのUTC推定値
utc_est = boot_time_est + timedelta(microseconds=record.tick_us)
```

複数のアンカーがある場合は線形補間（内挿）して精度を上げる。

### ルールエンジン（rules.yaml）

```yaml
- id: R-004
  description: "接続直後切断（短命セッション）"
  trigger:
    event: EVT_ATTACH
  conditions:
    - event: EVT_DETACH
      within_ms: 120000   # 2分以内に切断
  severity: medium
  diagnosis: "接続後すぐに切断。APN設定またはNW側PDN設定を確認"
```

`within_ms` で時間窓を指定し、トリガーイベントから指定時間以内に条件イベントが発生したらルールが発火する。`absent: true` を指定すれば「条件イベントが来なかった場合」にも発火できる。

---

## 診断ルールのカスタマイズ

`rules.yaml` に追記するだけで新しいルールを追加できる。

例：「Band切替後に接続成功するまでに3分以上かかった」を検出するルール

```yaml
- id: R-011
  description: "Band切替後の接続遅延"
  trigger:
    event: EVT_BAND_CHANGE
  conditions:
    - event: EVT_ATTACH
      within_ms: 180000   # 3分以内
      absent: true         # 来なかったら発火
  severity: medium
  diagnosis: "Band切替後に接続タイムアウト。セル選択パラメータを確認"
```

対応するイベント `EVT_BAND_CHANGE` を `event_correlator.py` の `_extract_events()` 関数に追加する必要があるが、パターンマッチの追加のみで対応できる。

---

## ハマりポイント

### JST/UTC混在問題

ATコマンドログはWindowsのシリアルモニタがPC時刻（JST, UTC+9）で記録するため、`at_events` テーブルの `utc_ts_est` カラムは実際にはJST時刻が格納されることがある。これを見落とすと相関時に9時間ずれる。モジュール内部の `+CCLK` 時刻もUT+9（JST）返しで、さらに約1分の遅れがある実測値が出ている。

### EPD形式のpcapng

Sierra Wireless HL78xxはWiresharkのパケットキャプチャにLINKTYPE_WIRESHARK_UPPER_PDU（DLT=252）を使う。`scapy` のデフォルトはこの形式を知らないため、`_detect_epd_linktype()` 関数でリンクタイプを確認し、EPDならバイト列をカスタムデコードする処理を書いた。

### OTII CSVのサイズ

OTII Arcは最大4000Hzでサンプリングするため、長時間計測したCSVは数百MBになる。起動時に全データをメモリにロードして `DatetimeIndex` を設定し、セッション選択時は `slice_locs` で切り出す設計にしたことで、表示速度が **15秒→0.5秒** に改善した。

---

## まとめ

LTE Doctorで実現したこと：

- 4種のログを1コマンドで統合解析
- バラバラなタイムスタンプをアンカー内挿でUTCに整合
- 10本の診断ルールで問題を自動分類（severity付き）
- Webダッシュボードで電流波形とLTEイベントを重ねて視覚的に確認

実際の2026年4月13日のログでは、Band1での9回連続リセット → Band40切替 → 接続成功 → 57秒でNW起因切断、という障害シナリオを完全に自動検出できた。

同じ課題を抱えているLTE-M/NB-IoTの開発者に参考になれば幸いだ。
