# LTE マルチソースログ診断システム
## 企画書 / 要件定義書

**文書番号**: LTEDoctor-REQ-001  
**リビジョン**: 1.0（リバース作成）  
**作成日**: 2026-05-09  
**作成者**: Finetek 組み込みソフトウェア事業部  
**ステータス**: 実装完了（Ph.1〜Ph.3, Ph.6）

---

## 目次

1. [企画概要](#1-企画概要)
2. [背景と課題](#2-背景と課題)
3. [プロジェクト目標](#3-プロジェクト目標)
4. [スコープ](#4-スコープ)
5. [システム構成概要](#5-システム構成概要)
6. [機能要件](#6-機能要件)
7. [非機能要件](#7-非機能要件)
8. [外部インターフェース仕様](#8-外部インターフェース仕様)
9. [データモデル設計](#9-データモデル設計)
10. [診断ルール仕様](#10-診断ルール仕様)
11. [UI・画面仕様](#11-ui画面仕様)
12. [制約・前提条件](#12-制約前提条件)
13. [フェーズ計画](#13-フェーズ計画)
14. [依存ライブラリ](#14-依存ライブラリ)

---

## 1. 企画概要

### 1.1 プロジェクト名

**LTE Doctor** — Sierra Wireless LTE-M モジュール マルチソースログ統合診断システム

### 1.2 対象ハードウェア

| 項目 | 内容 |
|------|------|
| モジュール型番 | Sierra Wireless HL78xx / HL79xx |
| チップセット | Sony ALT1250 |
| 通信方式 | LTE-M (eMTC / Cat-M1) |
| ファームウェア | Sierra Wireless 独自実装（UMAC アーキテクチャ） |
| 対応 Band | Band 1, Band 40（AT+KBNDCFG で制御） |

### 1.3 利用者

- Finetek 社 組み込みソフトウェアエンジニア
- LTE-M モジュールを搭載する製品の開発・デバッグ担当者

---

## 2. 背景と課題

### 2.1 問題の所在

Sierra Wireless HL78xx/HL79xx モジュールの通信品質診断を行う際、以下の **4 種類のログを個別に収集・手動で照合**する必要があった。

| ログ種別 | ファイル | 時刻基準 | 課題 |
|---------|---------|---------|------|
| チップセット内部ログ | DebugView++.dblog | チップ起動からの経過 μs | 絶対時刻に変換できない |
| AT コマンドログ TX | uart1-2.log | PC 時計（JST） | UTC への換算が必要 |
| AT コマンドログ RX | uart1-1.log | PC 時計（JST） | 上記に同じ |
| Wireshark パケットキャプチャ | wireshark.pcapng | UTC（基準軸） | 他ログとの突合が困難 |
| OTII 消費電流データ | OTII Arc .otii3 | UTC | バイナリ形式で直接参照不可 |

### 2.2 課題の詳細

1. **時刻軸がバラバラ**: 4 ソースの時刻基準が全て異なるため、手動での時刻合わせに多大な工数が発生する
2. **ログ量の多さ**: 1 セッション当たりチップセットログ 3,800 件以上、電流データ 90 万サンプル以上
3. **パターン認識の困難さ**: 障害パターン（リセット多発、PDN エラー、Attach Reject 等）を目視で発見することは非現実的
4. **再現性の低い障害**: 断続的な接続断など、原因の絞り込みに複数のログを同時に参照する必要がある

### 2.3 実際に観測された障害事例（設計根拠）

下記は本システムの設計根拠となった実測データ（2026-04-13 採取）。



この事例では「接続成功後 57 秒で断」「原因はネットワーク側の PDN セッション拒否」という結論に至るまで、上記の全ログを手動で突合する必要があった。

---

## 3. プロジェクト目標

### 3.1 主目標

複数種類のログを統合して**自動的に障害原因を推定**し、エンジニアの調査工数を削減する。

### 3.2 KPI（目標指標）

| 指標 | 現状 | 目標 |
|------|------|------|
| 障害原因特定に要する時間 | 30〜120 分（手動突合） | 5 分以内（自動診断） |
| ログ突合ミス発生率 | 高（手作業） | ゼロ（自動整合） |
| 診断可能な障害パターン数 | 属人的知識に依存 | 10 パターン以上（rules.yaml で管理・拡張可） |

### 3.3 副目標

- 診断結果を **セッション単位で保存**し、後から参照・比較できる
- **ルールをエンジニアが自分で追加・修正**できる拡張性を持つ
- 時刻整合の信頼度を定量的に示し、**不確かな結論には免責情報を付加**する

---

## 4. スコープ

### 4.1 スコープ内

| 項目 | 詳細 |
|------|------|
| 対象機器 | Sierra Wireless HL78xx/HL79xx（Sony ALT1250 チップセット）|
| 対象ログ | ATコマンドログ（TX/RX）、チップセットログ、Wireshark pcapng、OTII 消費電流 |
| 診断方式 | ポストモーテム（ログ収集後の事後解析）|
| 出力 | CLIレポート、Web ダッシュボード、JSON、SQLite DB |
| ルール管理 | YAML 外部ファイル（rules.yaml）による設定、Web UI での編集 |

### 4.2 スコープ外

| 項目 | 理由 |
|------|------|
| リアルタイムモニタリング | 本システムはポストモーテム解析専用 |
| 複数モジュール同時解析 | 現在は 1 モジュール単位を想定 |
| サーバー側 Wireshark の解析 | 将来フェーズで対応予定（Ph.5） |
| ML による自動ルール生成 | 手動ルール定義が現フェーズのスコープ |
| ファームウェア更新機能 | 診断専用ツール |

---

## 5. システム構成概要

### 5.1 モジュール一覧

| モジュール | 役割 | 入力 | 出力 |
|-----------|------|------|------|
|  | AT コマンドログのパース | uart1-x.log x2 |  |
|  | チップセットログのパース | DebugView++.dblog |  |
|  | Wireshark pcapng のパース | wireshark.pcapng |  |
|  | 電流データのイベント検出 | OTII CSV |  |
|  | OTII バイナリ → CSV 変換 | .otii3 ファイル | CSV ファイル |
|  | タイムスタンプ整合 | 全レコードリスト | utc_ts_est 付与済みレコード |
|  | SQLite 永続化 | 全レコード | diag.sqlite |
|  | イベント抽出・ルール評価 | SQLite + rules.yaml |  |
|  | フルパイプライン実行 | logs/ フォルダ | コンソール出力 + diag.sqlite |
|  | Web ダッシュボード | SQLite + logs/ | HTTP (port 5001) |

### 5.2 データフロー




---

## 6. 機能要件

### FR-001: AT コマンドログ パース

**入力**: `uart1-2.log`（TX）、`uart1-1.log`（RX）

**処理要件**:
- タイムスタンプ形式を自動判別（絶対時刻 `[YYYY-MM-DD HH:MM:SS.mmm]` / 相対時刻 `T+<ms>ms`）
- 各行をコマンド / OK / ERROR / URC に分類
- URC 認識: `+CEREG`, `+KCNX_IND`, `+KUDP_DATA`, `+KSUP`, `+KBNDCFG` 等
- `+KSUP: 0` を `EVT_RESET` として識別
- TX コマンドに対応 OK/ERROR がない場合を `EVT_TIMEOUT` として検出

### FR-002: チップセットログ パース

**入力**: `DebugView++.dblog`（タブ区切り 5 列）

**処理要件**:
- `tick_us`: チップ起動からの経過マイクロ秒
- `ConsoleD.exe` の `findPacket() failed` 行を除外
- 起動アンカー検出: `"Initialising the system..."`
- AT 相関アンカー検出: `"AT_Entry: Rat in use = CATM"`
- FSM 状態遷移抽出: `SM_SET_NEXT_STATE(StateName, NextState)`

### FR-003: Wireshark パケットキャプチャ パース

**処理要件**:
- バックエンド自動選択: scapy → pyshark+tshark → EPD 手動パーサー
- EPD 形式（LINKTYPE_WIRESHARK_UPPER_PDU, DLT=252）を自動検出
- NAS-EPS メッセージを分類（Attach Accept/Reject, Detach, Security Mode 等）
- EMM Cause コードを数値として抽出

### FR-004: OTII 消費電流データ パース

**処理要件**:
- サンプルレートを先頭データ差分の中央値から自動推定（通常 4000 Hz）
- 4000 Hz -> 100 Hz にダウンサンプリング、ローリング中央値でノイズ除去
- 閾値エッジ検出によるイベント抽出（デバウンス: 0.05 秒）

| イベント種別 | 条件 | デフォルト閾値 |
|------------|------|--------------|
| `EVT_PEAK_CURRENT` | PEAK_MA 超の短時間パルス（< 0.1s） | 30 mA |
| `EVT_RADIO_ACTIVE` | PEAK_MA 超が 0.1s 以上継続 | 30 mA |
| `EVT_CURRENT_DROP` | SLEEP_MA を下回った瞬間 | 2 mA |

### FR-005: OTII バイナリ -> CSV 変換（otii2csv.py）

| オプション | 説明 |
|-----------|------|
| `--list` | 録画セッション一覧を表示 |
| `--recording N` | 録画番号 N だけを処理 |
| `--output FILE` | 出力ファイルパス |
| `--decimation N` | 間引き率（例: 4 で 4000Hz -> 1000Hz） |

### FR-006: タイムスタンプ整合（アンカー内挿法）

**アンカー種別**:

| アンカー | 検出方法 |
|--------|---------|
| boot | チップセット: `Initialising the system...` |
| at_corr | チップセット: `AT_Entry: Rat in use = CATM` |
| cereg | AT: `+CEREG:1` <-> pcap: NAS Attach Accept |
| cclk | AT: `+CCLK?` 応答でモジュール内部時計を取得 |

**信頼度**: HIGH（2 個以上のアンカー）/ MEDIUM（1 個）/ LOW（アンカーなし）

**既知の時刻ずれ（実測値）**:
- AT ログ（JST） vs pcap（UTC）: 差 = 9 時間（整合前）
- モジュール内部時計（+CCLK） vs PC 時計: 約 -60 秒

### FR-007: フルパイプライン実行（run_pipeline.py）

`logs/` フォルダから全ログを自動検出し、パース・整合・DB 格納・ルール評価・レポート出力を一括実行する。

---

## 7. 非機能要件

| 要件 | 目標値 |
|------|--------|
| フルパイプライン実行 | 60 秒以内 |
| OTII CSV 2 回目以降（キャッシュ） | 1 秒以内 |
| Finding クリック（Web） | 即座（クライアントサイドのみ） |
| ログ 1 件のパースエラー | スキップして継続（クラッシュなし） |
| 対応 OS | Windows / Linux |
| 外部 DB サーバー | 不要（SQLite ビルトイン） |

---

## 8. 外部インターフェース仕様（Web API）

| メソッド | エンドポイント | 説明 |
|---------|-------------|------|
| GET | `/api/detect?folder=<path>` | ログファイル検出結果 |
| POST | `/api/diagnose {"folder":"..."}` | 診断パイプライン起動、task_id を返す |
| GET | `/api/task/<task_id>` | タスク進捗（status, step, session_id） |
| GET | `/api/sessions` | 保存済みセッション一覧 |
| GET | `/api/session/<id>` | セッション詳細（findings 含む） |
| GET | `/api/timeline/<id>?center_ts=&window_s=` | 波形 + イベント + findings |

---

## 9. データモデル設計

### SQLite テーブル一覧

| テーブル | 用途 | 主要カラム |
|---------|------|---------|
| `chipset_events` | UMAC 内部ログ | chip_tick_us, message, is_boot_anchor, utc_ts_est |
| `at_events` | AT TX/RX ログ | direction, raw_text, is_command, is_urc, utc_ts_est |
| `pcap_events` | パケットキャプチャ | utc_ts, nas_msg_type, emm_cause, event_type |
| `current_events` | 電流消費イベント | utc_ts, event_type, value_ma, duration_s |
| `correlated_events` | 診断ルール評価結果 | rule_id, severity, diagnosis, trigger_ts, evidence |
| `anchors` | 時刻整合アンカー記録 | anchor_type, source, utc_ts |
| `align_log` | 整合オフセット記録 | log_type, offset_s, confidence, anchor_count |

---

## 10. 診断ルール仕様

### 実装済みルール一覧（R-001 ~ R-010）

| ID | 重要度 | トリガー | 条件 | 診断 |
|----|--------|---------|------|------|
| R-001 | HIGH | EVT_DETACH | NAS Attach Accept なし（+-5秒） | ネットワーク起因の切断 |
| R-002 | HIGH | 3xEVT_TIMEOUT / 30秒 | なし | UART 通信障害の疑い |
| R-003 | HIGH | EVT_PDN_ERROR | なし | PDN 接続エラー（cause コード確認） |
| R-004 | MEDIUM | EVT_ATTACH | 2分以内に EVT_DETACH | 接続不安定（電波/NW 問題） |
| R-005 | CRITICAL | EVT_NWREJECT | なし | ネットワーク拒否（EMM cause 確認） |
| R-006 | HIGH | 3xEVT_RESET / 5分 | なし | リセット多発（電源/FW 問題） |
| R-007 | MEDIUM | EVT_TX | 10秒以内に EVT_RX なし | サーバー無応答または中継ロス |
| R-008 | HIGH | EVT_RESET | 5秒以内に EVT_RADIO_ACTIVE | ブラウンアウト起因リセットの疑い |
| R-009 | MEDIUM | EVT_DETACH | 5秒以内に EVT_CURRENT_DROP なし | 切断後もラジオアクティブ（即時再接続の疑い） |
| R-010 | MEDIUM | EVT_RADIO_ACTIVE | 60秒以内に EVT_ATTACH なし | セル探索継続・電力消費増大 |

---

## 11. UI・画面仕様

### タブ構成

| タブ | 機能 |
|-----|------|
| ① 診断設定 | ログフォルダ選択・ファイル検出・パイプライン実行・進捗表示 |
| ② セッション一覧 | 保存済み診断セッションを JST 日時・重要度件数付きで一覧表示 |
| ③ タイムライン | 電流波形・イベント散布・所見一覧・ログパネルの統合表示 |

### タイムライン画面レイアウト

```
+---所見リスト(300px)---+------Plotlyチャート------+
|                       | 電流波形 (mA)   [1/3]    |
| [HIGH] R-001          |                          |
| 17:14:51 UTC          +------イベント散布--[1/3]-+
| 切断:NW起因           |                          |
+-----------------------------------[全幅]---[1/3]-+
| マッチ詳細(左) | PCAP(中)       | ATコマンド(右) |
+---------------+----------------+----------------+
```

**性能特性**:
- セッション開封時に全データを 1 回取得（OTII CSV はメモリキャッシュ）
- Finding クリック = Plotly.relayout() のみ（サーバー通信なし、即座）
- Plotly ズーム/パン操作 -> plotly_relayout イベント -> ログパネル自動更新

---

## 12. 制約・前提条件

- AT ログは TX/RX を別ファイルで取得すること
- pcapng は Sierra Wireless HL78xx モジュール内部キャプチャ（EPD 形式）であること
- OTII データは事前に `otii2csv.py` で CSV 変換し `logs/OTII/` に配置すること
- AT ログのタイムスタンプは JST のまま格納される場合があり、整合後の時刻に最大数分の誤差が生じる可能性がある

---

## 13. フェーズ計画

| フェーズ | 内容 | 状態 |
|---------|------|------|
| Ph.1 | AT/チップセットパーサー、タイムスタンプ整合、SQLite 格納 | 完了 |
| Ph.2 | pcap パーサー（EPD 形式対応）、統合パイプライン | 完了 |
| Ph.3 | イベント相関エンジン、rules.yaml、R-001~R-007 | 完了 |
| Ph.4 | reporter.py（CLI レポート強化） | 未着手 |
| Ph.5 | OTII 電流統合、otii_parser.py、R-008~R-010 | 完了 |
| Ph.6 | Web ダッシュボード（doctor.py）、セッション管理 | 完了 |

---

## 14. 依存ライブラリ

| ライブラリ | 用途 | 必須 |
|-----------|------|------|
| `scapy` | pcapng パース | 必須 |
| `pyyaml` | rules.yaml 読み込み | 必須 |
| `pandas` | OTII CSV 処理 | 必須 |
| `numpy` | 信号処理（ダウンサンプリング） | 必須 |
| `flask` | Web ダッシュボード | 必須（doctor.py） |
| `pyshark` | 高精度 pcap デコード（tshark 連携） | 任意 |

```bash
pip install scapy pyyaml pandas numpy flask
```

---

*本文書は実装済みコードからリバースエンジニアリングにより作成した。*
