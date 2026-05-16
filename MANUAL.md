# LTE Doctor 使い方マニュアル

Sierra Wireless HL78xx/HL79xx LTE-M モジュールの通信障害を診断する統合ログ分析ツールです。  
ATコマンドログ・チップセット内部ログ・パケットキャプチャ・電流消費データを時間軸に揃えて相関分析し、障害原因を推定します。

---

## 目次

1. [事前準備](#1-事前準備)
- [AI 診断機能（タブ④）の使い方](#ai-診断機能タブ④の使い方)
2. [ファイル配置](#2-ファイル配置)
3. [ステップ1 — OTII電流データを CSV に変換 (otii2csv.py)](#3-ステップ1--otii電流データを-csv-に変換)
4. [ステップ2 — 電流グラフを確認 (otii_viewer.py)](#4-ステップ2--電流グラフを確認)
5. [ステップ3 — フルパイプライン実行 (run_pipeline.py)](#5-ステップ3--フルパイプライン実行)
6. [診断レポートの読み方](#6-診断レポートの読み方)
7. [ルールのカスタマイズ (rule_builder.py)](#7-ルールのカスタマイズ)
8. [パラメータ調整](#8-パラメータ調整)
9. [トラブルシューティング](#9-トラブルシューティング)

---

## 1. 事前準備

### 必要な Python パッケージ

```bash
pip install scapy pyyaml flask pandas numpy plotly anthropic python-dotenv
```

| パッケージ | 用途 |
|-----------|------|
| `scapy` | pcapng ファイルのパース |
| `pyyaml` | rules.yaml の読み込み |
| `flask` | otii_viewer / rule_builder の Web UI |
| `pandas`, `numpy` | データ処理 |
| `plotly` | グラフ描画 |

### 取得が必要なログファイル

| ログ種別 | 取得ツール | ファイル名の例 |
|---------|-----------|--------------|
| チップセット内部ログ | DebugView++ | `DebugView++.dblog` |
| AT コマンド TX | UART ターミナル | `uart1-2.log` |
| AT コマンド RX | UART ターミナル | `uart1-1.log` |
| LTE RRC/NAS キャプチャ | Wireshark（モジュール側） | `wireshark.pcapng` |
| 消費電流データ | OTII Arc | `*.otii3`（+ 同フォルダの `data/` ディレクトリ） |

> **注意**: pcapng は Sierra Wireless HL78xx が出力する内部キャプチャ形式  
> (LINKTYPE_WIRESHARK_UPPER_PDU, DLT=252) に対応しています。  
> 通常の Ethernet キャプチャとは異なります。

---

## 2. ファイル配置

プロジェクトフォルダ直下に `logs/` フォルダを作成し、以下の構成に配置してください。

```
LTEDoctor/
├── run_pipeline.py
├── otii2csv.py
├── otii_viewer.py
├── rule_builder.py
├── rules.yaml
└── logs/
    ├── DebugView++.dblog      ← チップセットログ
    ├── uart1-2.log            ← AT TX ログ
    ├── uart1-1.log            ← AT RX ログ
    ├── wireshark.pcapng       ← pcap ログ
    └── OTII/
        ├── 20260413.otii3     ← OTII 測定ファイル
        └── *.csv              ← otii2csv.py 出力（自動生成）
```

> OTII ログが不要な場合は `logs/OTII/` フォルダがなくても問題ありません。

---

## 3. ステップ1 — OTII電流データを CSV に変換

OTII Arc で測定した `.otii3` ファイルを CSV に変換します。

### 基本の実行

```bash
python otii2csv.py "logs/OTII/20260413.otii3"
```

録画セッションごとに CSV が自動生成されます。

```
20260413_rec0_20260413_165917.csv
20260413_rec1_20260413_170817.csv
20260413_rec2_20260413_172251.csv
...
```

### 録画セッション一覧を確認する

```bash
python otii2csv.py "logs/OTII/20260413.otii3" --list
```

出力例:

```
録画セッション数: 4
  [0] 開始: 2026-04-13 16:59:17 JST  電流: ○  電圧算出: ○  (サンプルレート: 4000 Hz)
  [1] 開始: 2026-04-13 17:08:17 JST  電流: ○  電圧算出: ○  (サンプルレート: 4000 Hz)
  [2] 開始: 2026-04-13 17:22:51 JST  電流: ○  電圧算出: ○  (サンプルレート: 4000 Hz)
  [3] 開始: 2026-04-13 17:37:49 JST  電流: ○  電圧算出: ○  (サンプルレート: 4000 Hz)
```

### 特定の録画だけを変換する

```bash
python otii2csv.py "logs/OTII/20260413.otii3" --recording 1 --output out.csv
```

### ファイルサイズを小さくする（間引き）

4000 Hz で数分録画すると CSV が 100 MB 以上になります。  
`--decimation` で間引くと扱いやすくなります。

```bash
# 4000 Hz → 1000 Hz 相当（1/4 に間引き）
python otii2csv.py "logs/OTII/20260413.otii3" --decimation 4
```

### オプション一覧

| オプション | 説明 |
|-----------|------|
| `--list`, `-l` | 録画一覧を表示して終了 |
| `--recording N`, `-r N` | 録画番号 N だけを処理（0 始まり） |
| `--output FILE`, `-o FILE` | 出力ファイルパスを指定 |
| `--decimation N`, `-d N` | 間引き率（例: 4 で 4000 Hz → 1000 Hz） |
| `--no-power` | power_W カラムを出力しない |

### 出力 CSV のカラム

| カラム | 単位 | 説明 |
|--------|------|------|
| `timestamp_s` | s | 録画開始からの経過時間 |
| `datetime` | — | UTC 実時刻 |
| `current_A` | A | 電流値 |
| `voltage_V` | V | 電圧値（= power_W / current_A の計算値） |
| `power_W` | W | 電力値（計測データがない場合は NaN） |

---

## 4. ステップ2 — 電流グラフを確認

otii2csv.py で変換した CSV を Web ブラウザでインタラクティブに表示します。

### 起動

```bash
python otii_viewer.py
```

ブラウザで **http://localhost:5000** を開きます。

### 使い方

**① フォルダパスを入力して Enter**

```
入力例: D:\Users\hoshi\Documents\App\LTEDoctor\logs\OTII
```

左サイドバーに CSV ファイル一覧（ファイルサイズ付き）が表示されます。

**② ファイルをクリック**

電流 (mA) / 電圧 (V) / 電力 (mW) の 3 段グラフが表示されます。  
電圧・電力データがない場合は、そのパネルは非表示になります。

**③ グラフ操作**

- マウスホイール: ズーム
- ドラッグ: パン（スクロール）
- カーソルを合わせる: 各時刻の値を表示（3 チャネル統合ツールチップ）

**④ 統計バー（上部）の確認**

サンプル数・時間長・電流 min/max/平均・電圧平均・電力平均・間引き率が表示されます。

> **大ファイルの自動処理**: 50,000 サンプル超のファイルは自動間引きして表示します。  
> 数百 MB の CSV でも数秒で表示されます。

---

## 5. ステップ3 — フルパイプライン実行

全ログを一括処理し、相関診断レポートを生成します。

### 実行

```bash
python run_pipeline.py
```

### 処理フェーズと確認ポイント

```
=== [1] ログパース ===
  OTII    : logs/OTII/...csv  → 26 イベント検出     ← OTII イベント件数
  chipset : 3842 件
  AT      : 287 件
  pcap    : 93 件
  current : 106 イベント（OTII 4 ファイル）

=== [2] タイムスタンプ整合 ===
  chipset  offset=+1.234s  confidence=HIGH            ← HIGH が理想
  AT       offset=-0.002s  confidence=MEDIUM

=== [3] DB格納 ===
  chipset_events : 3842 件
  at_events      : 287 件
  pcap_events    : 93 件
  current_events : 106 件

=== [4] イベント相関 (Ph.3) ===
  ルール R-001 マッチ: ts=2026-04-13T08:14:51  ...

=== [5] 診断レポート ===
  ...
```

**`[2] タイムスタンプ整合` の `confidence` が `LOW` の場合**: 時刻がずれている可能性があります。相関結果は参考値として扱ってください。

### 出力ファイル

実行後、`diag.sqlite` が生成・更新されます。このファイルは rule_builder.py でのテストにも使用します。

---

## 6. 診断レポートの読み方

フルパイプライン実行後、以下のような診断結果が出力されます。

```
=== 相関診断レポート (7 件) ===

  [CRITICAL] R-005  2026-04-13T08:09:15  confidence=HIGH
  ネットワークから Attach Reject を受信 → EMM cause コードを確認してください
  トリガー: [pcap] Attach Reject (EMM cause: 15)

  [HIGH] R-001  2026-04-13T08:14:51  confidence=HIGH
  切断: ネットワーク起因の疑い（NAS Attach Accept なし）
  トリガー: [at] +CEREG: 0
    根拠: [pcap] Detach request (plain)

  [HIGH] R-008  2026-04-13T08:14:51  confidence=HIGH
  リセット直前にラジオアクティブ電流を検出 → 電源電圧降下によるリセットの疑い
  トリガー: [at] +KSUP: 0
    根拠: [current] radio active peak=196.4mA dur=3.87s

  [MEDIUM] R-004  2026-04-13T08:13:57  confidence=HIGH
  接続成功後 2分以内に切断 → 電波品質または通信ネットワーク不安定の疑い
  トリガー: [at] +CEREG: 1
    根拠: [at] +CEREG: 0
```

### 各フィールドの意味

| フィールド | 説明 |
|-----------|------|
| `[SEVERITY]` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` の順で重大度が高い |
| `R-XXX` | rules.yaml のルール ID |
| タイムスタンプ | トリガーイベントの UTC 時刻 |
| `confidence=HIGH` | 複数のログソースで裏付けが取れている |
| `confidence=MEDIUM` | 単一ソースのみで裏付け |
| `トリガー` | ルールを発動させたログ行 |
| `根拠` | 条件を満たした関連ログ行 |

### 標準搭載ルール一覧

| ID | Severity | 診断内容 |
|----|----------|---------|
| R-001 | HIGH | 切断時に NAS Attach Accept なし → ネットワーク起因の疑い |
| R-002 | HIGH | ATコマンド 30秒内に 3回タイムアウト → UART 通信障害の疑い |
| R-003 | HIGH | +KCNX_IND 接続エラー → PDN 設定を確認 |
| R-004 | MEDIUM | 接続成功後 2分以内に切断 → 電波品質または NW 不安定 |
| R-005 | CRITICAL | NAS Attach Reject 受信 → EMM cause コードを確認 |
| R-006 | HIGH | モジュールリセット 5分内に 3回以上 → 電源または FW 問題 |
| R-007 | MEDIUM | 送信後 10秒以内に受信なし → サーバー無応答の疑い |
| R-008 | HIGH | リセット直前にラジオアクティブ電流 → ブラウンアウト疑い |
| R-009 | MEDIUM | 切断後 5秒以内に電流降下なし → 即時再接続を試みている可能性 |
| R-010 | MEDIUM | 60秒以上ラジオアクティブで接続成功なし → セル探索継続・電力消費増大 |

---

## 7. ルールのカスタマイズ

標準ルールでカバーできない障害パターンには、ブラウザ上でルールを追加・編集できます。

### 起動

```bash
python rule_builder.py --db diag.sqlite --rules rules.yaml --port 5001
```

ブラウザで **http://localhost:5001** を開きます。

### 操作手順

1. ルール一覧を確認し、「新規追加」または既存ルールの「編集」を選択
2. **トリガー**（どのイベントが起きたとき発火するか）を設定
3. **条件**（追加で満たすべき条件）を設定
4. 「テスト実行」ボタンで `diag.sqlite` に対してリアルタイム評価
5. マッチ件数・証拠を確認し、「保存」で `rules.yaml` に書き込み
6. `run_pipeline.py` を再実行して反映確認

### rules.yaml の直接編集

```yaml
rules:
  - id: R-011                          # 一意の ID（既存と重複しないこと）
    description: "独自の診断ルール"
    trigger:
      event: EVT_DETACH                # トリガーイベント種別（下表参照）
    conditions:
      - source: current                # ソース: at / chipset / pcap / current / any
        event: EVT_RADIO_ACTIVE        # 条件イベント種別
        within_ms: 10000               # トリガー前後の時間窓 [ms]
        absent: false                  # true = "イベントがない" を条件とする
    severity: high
    diagnosis: "切断時にラジオアクティブ電流あり → 詳細調査が必要"
```

### 使用可能なイベント種別

| イベント | ソース | 発生条件 |
|---------|--------|---------|
| `EVT_ATTACH` | at / pcap | +CEREG:1/5 または NAS Attach Accept |
| `EVT_DETACH` | at / pcap | +CEREG:0/2 または NAS Detach |
| `EVT_TX` | at | AT+KUDPSND / AT+KUDPEND |
| `EVT_RX` | at | +KUDP_DATA / +KTCP_DATA |
| `EVT_PDN_ERROR` | at | +KCNX_IND state=5 |
| `EVT_NWREJECT` | pcap | NAS Attach Reject |
| `EVT_TIMEOUT` | at | AT コマンドに OK/ERR なし |
| `EVT_RESET` | at | +KSUP: 0 |
| `EVT_PEAK_CURRENT` | current | 短時間電流ピーク（< MIN_ACTIVE_S） |
| `EVT_RADIO_ACTIVE` | current | ラジオアクティブ区間（>= MIN_ACTIVE_S） |
| `EVT_CURRENT_DROP` | current | スリープ移行（閾値を下回った瞬間） |

---

## 8. パラメータ調整

### 電流イベント検出の閾値（otii_parser.py）

ファイル先頭の定数を変更してデバイスに合わせてください。

```python
PEAK_MA      = 30.0     # ラジオアクティブ判定閾値 [mA]
                        # モジュールのアクティブ電流が低い場合は下げる（例: 10.0）
SLEEP_MA     = 2.0      # スリープ判定閾値 [mA]
                        # スリープ電流が高い場合は上げる（例: 5.0）
MIN_ACTIVE_S = 0.10     # EVT_RADIO_ACTIVE の最小継続時間 [s]
DEBOUNCE_S   = 0.05     # チャタリング除去間隔 [s]
                        # eDRX で頻繁に閾値を跨ぐ場合は増やす（例: 0.5〜2.0）
```

### OTII ビューアの表示サンプル数上限（otii_viewer.py）

```python
MAX_POINTS = 50_000     # 表示サンプル数の上限
                        # 大きくするとグラフが詳細になるが描画が重くなる
```

---

## 9. トラブルシューティング

### パイプライン実行エラー

| エラーメッセージ | 原因 | 対処 |
|---------------|------|------|
| `FileNotFoundError: logs/DebugView++.dblog` | ログファイルが配置されていない | ファイル名と配置場所を確認 |
| `ModuleNotFoundError: No module named 'scapy'` | パッケージ未インストール | `pip install scapy` を実行 |
| `SyntaxError` in rules.yaml | YAML 書式エラー | rule_builder.py で検証・修正 |
| `confidence=LOW` が多い | アンカーイベントが少ない | 相関結果は参考値として扱う |

### OTII Viewer エラー

| エラーメッセージ | 原因 | 対処 |
|---------------|------|------|
| `パスが見つかりません` | パスが誤っている | エクスプローラーからパスをコピー&ペースト |
| `必須カラムがありません` | otii2csv.py 以外の CSV | otii2csv.py で変換し直す |
| グラフが表示されない | NaN JSON エラー | ブラウザをリロードして再試行 |

### OTII データが診断に反映されない

1. `logs/OTII/` フォルダに CSV ファイルが存在するか確認
2. `run_pipeline.py` の `[1] ログパース` で `OTII ... → N イベント検出` が表示されるか確認
3. イベント件数が 0 の場合は `otii_parser.py` の `PEAK_MA` / `SLEEP_MA` を調整

### タイムスタンプがずれている

- AT ログのタイムスタンプが PC のローカル時刻 (JST) の場合、pcap (UTC) との差が **+9 時間** になります
- `time_aligner.py` が自動補正しますが、アンカーが見つからない場合は補正できません
- DebugView++ ログの `"Initialising the system..."` イベントがアンカーとして使用されます

---

## AI 診断機能（タブ④）の使い方

Web ダッシュボード（doctor.py）のタブ④「AI診断」では、ロードされた診断データに対して自然言語で質問し、Claude AI が SQL クエリを実行しながら回答します。

### セットアップ：API キーの設定

**1. `.env` ファイルを編集する**

プロジェクトルートの `.env` ファイルを開き、API キーを設定します。

```
ANTHROPIC_API_KEY=sk-ant-api03-XXXXXXXXXXXXXXXX
```

API キーは https://console.anthropic.com/settings/keys から取得してください。

> **注意**: `.env` は `.gitignore` により Git に含まれません。キーを誤って公開しないよう注意してください。

**2. サーバーを起動する**

```bash
python doctor.py
```

起動時に `.env` が自動読み込みされます。

### 使い方

1. タブ②「セッション一覧」でセッションを選択
2. タブ③「タイムライン」が表示され、自動的にタブ④のチャットが初期化される
3. タブ④「AI診断」をクリックして質問を入力

**質問例:**

| 質問 | 得られる回答の例 |
|------|----------------|
| `切断直前の5秒間に何が起きていたか？` | AT/pcap/電流イベントをタイムライン順に列挙 |
| `Band1での接続試行は何回あったか？` | at_events を集計して件数と期間を回答 |
| `OTIIの電流ピークとNAS Attachのタイミングは一致しているか？` | current_events と pcap_events を時刻結合して差分を回答 |
| `この時刻周辺を見せて` | タイムラインのグラフが自動ズーム |

**発見をルール化する:**

質問の流れの中で「このパターンをルール化して」と入力すると、Claude が `rules.yaml` 形式のルールを提案します。内容を確認して「確定して追加」を押すと `rules.yaml` に自動追記されます。

**レポートを保存する:**

「レポートを保存」ボタンを押すと、Q&A 全体から構造化されたMarkdownレポートが自動生成され、`sessions/` フォルダに保存されます。

### トラブルシューティング（AI 診断）

| 症状 | 原因 | 対処 |
|------|------|------|
| `ANTHROPIC_API_KEY が設定されていません` | `.env` が未設定またはキーが不正 | `.env` を確認してサーバーを再起動 |
| チャットが応答しない | API タイムアウト | ネットワーク接続を確認して再送信 |
| ルールが生成されない | 会話コンテキストが不足 | 先に関連する質問を数回行ってから依頼 |

---

## 推奨ワークフロー（全体まとめ）

```
[測定] ハードウェアで各ログを同時取得
  ↓
[変換] otii2csv.py で .otii3 → CSV（電流データ）
  ↓
[確認] otii_viewer.py で電流波形を目視確認（任意）
  ↓
[配置] logs/ フォルダにログファイルを配置
  ↓
[実行] python run_pipeline.py
  ↓
[確認] 診断レポートで CRITICAL / HIGH から優先確認
  ↓
[調整] 必要に応じて rule_builder.py でルール追加・修正
  ↓
[再実行] run_pipeline.py を再実行して反映確認
```
