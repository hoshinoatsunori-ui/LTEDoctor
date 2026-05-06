# LTE Doctor

**Sierra Wireless HL78xx/HL79xx (Sony ALT1250)** LTE-M モジュールの複数ログを統合し、通信障害の診断・原因推定を行う Python システム。

## 概要

LTE-M モジュールの通信不良調査において、以下の複数ソースのログを時刻軸に揃えて相関分析する。

| ログ種別 | ファイル | 内容 |
|---------|---------|------|
| ATコマンド TX | `uart1-2.log` | ホスト→モジュール送信コマンド |
| ATコマンド RX | `uart1-1.log` | モジュール→ホスト応答/URC |
| チップセットログ | `DebugView++.dblog` | UMAC 内部ログ（tick_us 単位） |
| モジュール側 Wireshark | `wireshark.pcapng` | LTE RRC / NAS-EPS 内部キャプチャ |

## アーキテクチャ

```
logs/
├── uart1-2.log          AT TX
├── uart1-1.log          AT RX
├── DebugView++.dblog    チップセット UMAC
└── wireshark.pcapng     LTE RRC / NAS (EPD format)

パイプライン:
  [chipset_parser] ─┐
  [at_parser]      ─┼─> [time_aligner] ─> [db_store] ─> [event_correlator] ─> 診断レポート
  [pcap_parser]    ─┘                      (SQLite)       (rules.yaml)
```

## モジュール構成

| ファイル | フェーズ | 役割 |
|---------|---------|------|
| `chipset_parser.py` | Ph.1 | DebugView++ `.dblog` パーサー。UMAC tick_us → UTC 推定 |
| `at_parser.py` | Ph.1 | TX/RX 分離 AT ログパーサー。CEREG/KCNX セマンティクス抽出 |
| `pcap_parser.py` | Ph.1 | pcap/pcapng パーサー。**LINKTYPE_WIRESHARK_UPPER_PDU (252)** 自動検出・NAS-EPS デコード対応 |
| `time_aligner.py` | Ph.2 | アンカー内挿法によるタイムスタンプ整合。信頼度 HIGH/MEDIUM/LOW |
| `db_store.py` | Ph.2 | SQLite 中間ストア。全ソースを統一スキーマに格納 |
| `event_correlator.py` | Ph.3 | `rules.yaml` を読み込みイベント相関評価 |
| `rules.yaml` | Ph.3 | 相関ルール定義（R-001〜R-007） |
| `run_pipeline.py` | — | フルパイプライン実行スクリプト |
| `rule_builder.py` | — | Flask Web UI：ルール CRUD + リアルタイムテスト |

## DiagRule Builder（Flask Web UI）

`rules.yaml` の相関ルールをブラウザ上で **CRUD** し、現在の `diag.sqlite` に対して**リアルタイムテスト**できるツール。

### 起動

```bash
pip install flask   # 初回のみ
python rule_builder.py
# → http://localhost:5001/ を開く
```

オプション:

```bash
python rule_builder.py --db diag.sqlite --rules rules.yaml --port 5001
```

### 機能

| 画面 | 説明 |
|------|------|
| ルール一覧 | ID / 説明 / Severity バッジ / Trigger / マッチ件数（DBあり時）を表示 |
| ルール編集フォーム | 条件の動的追加・削除、YAML プレビューをリアルタイム表示 |
| テスト実行 | 保存済みルールまたはフォーム現在値を DB に対して即時評価 |
| JSON API | `GET /api/rules`・`GET /api/events` でデータ取得可能 |

> DB が不要な場合（`diag.sqlite` なし）でも起動可能。マッチ件数は「-」表示になる。

## インストール

```bash
pip install scapy pyyaml flask
# オプション: NAS 詳細解析用
# pip install pyshark   # tshark が別途必要
```

## 使い方

```bash
# ログを logs/ に配置してから実行
python run_pipeline.py
```

または Python から直接:

```python
import chipset_parser, at_parser, pcap_parser, time_aligner, db_store, event_correlator

# 1. パース
chip_recs = chipset_parser.parse_file("logs/DebugView++.dblog")
at_recs   = at_parser.parse_tx_rx_pair("logs/uart1-2.log", "logs/uart1-1.log")
pcap_recs = pcap_parser.parse_file("logs/wireshark.pcapng")   # EPD 自動検出

# 2. タイムスタンプ整合
time_aligner.align_chipset(chip_recs)
time_aligner.align_at_log(at_recs)

# 3. DB 格納
db = db_store.DiagDb("diag.sqlite")
db.insert_chipset(chip_recs)
db.insert_at(at_recs)
db.insert_pcap(pcap_recs)

# 4. イベント相関・診断
results = event_correlator.correlate(db)
event_correlator.print_summary(results)
```

## 相関ルール（rules.yaml）

| ID | 重要度 | 説明 |
|----|-------|------|
| R-001 | HIGH | 切断時に NAS Attach Accept なし（ネットワーク起因の疑い） |
| R-002 | HIGH | ATコマンドタイムアウト連続（UART 障害の疑い） |
| R-003 | HIGH | PDN 接続エラー（`+KCNX_IND` cause≠0） |
| R-004 | MEDIUM | LTE 登録成功後すぐに切断（電波不安定） |
| R-005 | CRITICAL | NAS Attach Reject 受信（EMM cause 付き） |
| R-006 | HIGH | モジュールリセット多発 |
| R-007 | MEDIUM | パケット送信後に受信なし（サーバー無応答の疑い） |

## SQLite スキーマ

```
chipset_events     UMAC ログ（utc_ts_est 付き）
at_events          AT TX/RX ログ
pcap_events        pcapng パケット（NAS msg_type / EMM cause 含む）
correlated_events  イベント相関結果（rule_id / diagnosis / evidence）
anchors            タイムスタンプ整合アンカー記録
align_log          整合オフセット・信頼度ログ
```

## pcapng フォーマット対応

Sierra Wireless HL78xx モジュール側キャプチャは **LINKTYPE_WIRESHARK_UPPER_PDU (DLT 252)** 形式。
通常の Ethernet pcap ではなく、Wireshark Exported PDU 形式でエクスポートされたプロトコル PDU を含む。

`pcap_parser.py` はこの形式を自動検出し、NAS-EPS / LTE RRC を手動デコードする。

対応プロトコル:
- `nas-eps` / `nas-eps_plain` — Attach/Detach/TAU/Auth/SecurityMode 等をデコード
- `lte_rrc.bcch_bch` / `lte_rrc.bcch_dl_sch_br` — MIB/SIB（セル取得）
- `lte_rrc.dl_dcch` / `lte_rrc.ul_dcch` — RRC 専用制御チャネル
- `lte_rrc.dl_ccch` / `lte_rrc.ul_ccch` — RRC 接続確立

## タイムスタンプ整合

| ソース | 基準 | 信頼度 |
|--------|------|--------|
| pcap | UTC 絶対時刻（Wireshark） | HIGH（基準軸） |
| AT ログ | PC 絶対時刻 | MEDIUM |
| チップセット | チップ起動からの μs (`chip_tick_us`) | MEDIUM（boot アンカー使用） |

チップ起動時刻の推定:
```
"Initialising the system..." のアンカーレコード
boot_time = dbv_abs_ts - chip_tick_us / 1e6
```

## 実サンプルで確認された現象

```
17:09〜17:13  Band1 で接続試行 → 9回リセット、全て失敗
17:12:35      AT+KBNDCFG=0,1→0,40000 で Band40 に切替
17:12:59      pcap: LTE RRC BCCH 開始（Band40 セル取得）
17:13:57      +CEREG: 1 → Band40 で LTE 登録成功
17:13:59      pcap: NAS Attach accept + Attach complete
17:14:50      +KCNX_IND: 1,5,30 → PDN 接続エラー（cause=30）
17:14:51      pcap: ネットワーク起因 NAS Detach request
17:14:54      接続断
```

**診断: Band40 に切り替え後は接続できるが PDN 確立直後にネットワーク側から切断される。cause=30 (request rejected by the serving GW or PDN GW) のためサーバー側設定の確認を推奨。**

## ライセンス

MIT
