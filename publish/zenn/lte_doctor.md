---
title: "LTE-Mモジュールの通信障害を4種のログで自動診断するPythonツールを作った"
emoji: "📡"
type: "tech"
topics: ["python", "lte", "iot", "flask", "sqlite"]
published: false
---

## はじめに

IoT機器のフィールドトラブルで最も厄介なのが、LTE-Mモジュールの接続断問題だ。

症状は単純だ。「突然通信が切れる」「接続に何分もかかる」「リセットが連発する」。しかし原因を特定しようとすると、途端に地獄が始まる。

- **ATコマンドログ（TX/RX）**：ホストMCUとモジュール間のUART通信ログ。PC時刻（JST）でタイムスタンプが入っている
- **チップセットログ（DebugView++.dblog）**：Sierra Wireless HL78xxチップセット内部のデバッグログ。タイムスタンプはチップ起動からの経過マイクロ秒
- **Wireshark pcapng**：モジュール内部からキャプチャしたパケット。UTC絶対時刻付きだが、LINKTYPE_WIRESHARK_UPPER_PDU（DLT=252）というEPD独自形式
- **OTII Arc電流波形**：LTEセッション中の消費電流をミリ秒単位でCSV記録

この4種のログを**手動でエクセルに貼り付けて時刻を目視で突合する**作業は、一言で言えば地獄だ。ログのタイムゾーンがバラバラ、基準時刻がバラバラ、列フォーマットが当然バラバラ。1件の障害解析に半日かかることもある。

そこで、これらを自動統合して診断するPythonツール「LTE Doctor」を作った。

---

## システム構成

```
logs/
  uart1-2.log          ← AT TX（ホスト→モジュール）
  uart1-1.log          ← AT RX（モジュール→ホスト）
  DebugView++.dblog    ← チップセットログ
  wireshark.pcapng     ← EPD形式 pcapng
  otii_arc.csv         ← 消費電流CSV（otii2csv.py変換後）

パイプライン:
  at_parser.py        → AT TX/RX を構造化レコードに変換
  chipset_parser.py   → .dblog をパース、UMAC内部ログを抽出
  pcap_parser.py      → EPD linktype を自動検出してデコード
  otii_parser.py      → 電流CSVをDatetimeIndex付きDataFrameに変換
       ↓
  time_aligner.py     → 4ソースのタイムスタンプをUTCに整合
       ↓
  db_store.py         → SQLite（7テーブル）に格納
       ↓
  event_correlator.py → rules.yaml の10ルールを評価
       ↓
  doctor.py           → Flask Webダッシュボード（port 5001）
```

**主要モジュール一覧：**

| モジュール | 役割 |
|-----------|------|
| `at_parser.py` | TX/RX分離ファイルをパース、URC・コマンド・レスポンスを分類 |
| `chipset_parser.py` | tab区切り5列形式 → UMAC内部ログ（tick_us付き）を抽出 |
| `pcap_parser.py` | DLT=252 EPD形式を自動検出、NAS/RRCメッセージをデコード |
| `otii_parser.py` | OTII Arc CSVをmA単位でパース |
| `otii2csv.py` | OTII独自バイナリ形式→CSV変換ユーティリティ |
| `time_aligner.py` | アンカー内挿法でUTC整合 |
| `db_store.py` | SQLite 7テーブルへの読み書き |
| `event_correlator.py` | EVT_*イベント検出 + ルール評価 |
| `run_pipeline.py` | CLIフルパイプライン |
| `doctor.py` | FlaskダッシュボードWebアプリ |

---

## 核心技術①：タイムスタンプ整合（アンカー内挿法）

4種のログの時刻基準は下記の通りバラバラだ。

| ログ | タイムスタンプ | 基準 | 信頼度 |
|------|--------------|------|-------|
| pcap | UTC絶対時刻 | 高精度GPS同期 | HIGH |
| ATログ | PC絶対時刻（JST） | PCシステム時刻 | MEDIUM |
| チップセット | チップ起動からのμs（tick_us） | 内部カウンタ | LOW→HIGH |
| OTII電流 | サンプリング相対時刻 | 測定開始基点 | LOW |

**tick_us → UTC変換の方法**

チップセットログには `tick_us`（チップ起動からの経過マイクロ秒）しかない。これをUTCに変換するには「ブートアンカー」を使う。

```python
# アンカー例: "Initialising the system..." が出現した瞬間
# dbv_abs_ts: DebugView++がこの行を記録したPC絶対時刻
# tick_us:    このメッセージのチップ内時刻 = 833,074 μs
boot_time_est = dbv_abs_ts - timedelta(microseconds=tick_us)
# boot_time_est ≈ 2026-04-13 17:09:25.036 UTC

# 以降はすべての tick_us から UTC推定値を計算
utc_est = boot_time_est + timedelta(microseconds=record.tick_us)
```

**アンカーの種類と信頼度**

```
BOOT_ANCHOR    : "Initialising the system..." ← 起動直後、ドリフト大
AT_CORR_ANCHOR : "AT_Entry: Rat in use = CATM" ← ATログとの相関点
CEREG_ANCHOR   : +CEREG:1 ↔ NAS Attach Accept ← pcapとATの相関（差≈2.2秒）
```

複数アンカーが存在する場合、アンカー間で線形補間（内挿）する。これにより、ブート直後のドリフトが大きい区間でも、より近いアンカーが使われるため精度が向上する。

**JSTとUTCの混在問題**

ATコマンドログはPC時刻（JST, UTC+9）で記録されるが、pcapはUTC。`at_events` テーブルの `utc_ts_est` カラムは実際にはJSTのまま格納されているケースがあり、これが相関時に9時間のずれを生む。モジュール内部時計（`+CCLK`）も別途1分程度の遅れがある実測値も確認した。

---

## 核心技術②：診断ルールエンジン

ルールは `rules.yaml` で外部管理する。実装している診断ルールはR-001〜R-010の10本だ。

```yaml
- id: R-001
  description: "ネットワーク起因切断"
  trigger:
    event: EVT_DETACH
  conditions:
    - source: pcap
      match: "Detach request"
      within_ms: 5000
  severity: high
  diagnosis: "ネットワーク起因のDetach。NW側の問題の疑い"

- id: R-003
  description: "PDN接続エラー"
  trigger:
    event: EVT_PDN_ERROR
  conditions: []
  severity: high
  diagnosis: "+KCNX_IND cause値を確認。cause=30はNW拒否"

- id: R-008
  description: "ブラウンアウトリセット連続"
  trigger:
    event: EVT_RESET
    count: 3
    window_ms: 120000
  conditions:
    - source: otii
      match: "current_drop_before_reset"
      within_ms: 500
  severity: critical
  diagnosis: "電源電圧降下によるリセット連鎖の疑い。電源容量を確認"
```

**EVT_* イベント定義**

```python
EVT_ATTACH       # +CEREG:1 または NAS Attach Accept
EVT_DETACH       # +CEREG:0 または NAS Detach request
EVT_TX           # AT+KUDPSND / UDP送信パケット検出
EVT_RX           # +KUDP_DATA / TCPペイロード受信
EVT_PDN_ERROR    # +KCNX_IND エラーコード検出
EVT_RESET        # +KSUP:0（モジュールリセット完了）
EVT_TIMEOUT      # ATコマンド送信後N秒以内に応答なし
EVT_NWREJECT     # Attach Reject / EMM cause コード検出
```

**ルール評価ロジックの特徴：**

- `count` + `window_ms`：指定時間窓内でイベントがN回発生したら発火（リセット連発検出に使用）
- `absent` 条件：特定イベントが「来なかった」場合に発火（例：送信後60秒以内にACKなし）
- severityは `critical / high / medium / low` の4段階

---

## Webダッシュボードの性能最適化

FlaskダッシュボードはOTII電流波形（Plotly）、イベントスキャッタープロット、3カラム詳細ペイン（ルール詳細 / PCAPリスト / ATコマンドリスト）を持つ3タブ構成だ。

### 課題：電流波形の表示が遅い

OTII Arcは最大4000Hzでサンプリングする。1時間分のログだと1440万点になり、そのままPlotlyに渡すとブラウザが死ぬ。また、セッションを切り替えるたびにCSVを再読み込みしていたため、初回表示に15秒かかっていた。

### 解決策①：CSVメモリキャッシュ（DatetimeIndex）

```python
# サーバー起動時に一度だけCSV全ファイルをロードしてメモリキャッシュ
_otii_cache: dict[str, pd.DataFrame] = {}

def load_otii(path: str) -> pd.DataFrame:
    if path not in _otii_cache:
        df = pd.read_csv(path, parse_dates=["timestamp"])
        df = df.set_index("timestamp").sort_index()
        _otii_cache[path] = df
    return _otii_cache[path]

# セッション選択時は DatetimeIndex.slice_locs で瞬時に切り出し
start_loc, end_loc = df.index.slice_locs(session_start, session_end)
session_df = df.iloc[start_loc:end_loc]
```

これにより、セッション切替のレスポンスが **15秒→0.5秒** に短縮された。

### 解決策②：アダプティブデシメーション

ズームレベルに応じてダウンサンプリング係数を変える。広域表示では **4000Hz→100Hz**（40:1間引き）、詳細ズーム時は元データを使用。

### 解決策③：Plotly.relayoutによるクライアントサイドズーム

タイムラインのズーム・パン操作は、サーバーへのラウンドトリップを発生させずにクライアントJSだけで処理する。`plotly_relayout` イベントをフックして表示範囲を他グラフと同期させるだけで、サーバー通信ゼロのインタラクティブ操作を実現している。

---

## 実際の診断結果

2026年4月13日の実測ログで以下が自動検出された。

**タイムライン（17:09〜17:15 JST）**

```
17:09:25  モジュール起動（+KSUP:0 #1）               ← R-006 HIGH: リセット連発開始
17:09〜   Band1 で接続試行 → 失敗を繰り返す
          +KSUP:0 が4分間で9回発生                    ← R-006 HIGH: リセットカスケード
17:12:35  AT+KBNDCFG=0,40000 → Band40に切替
17:13:57  +CEREG: 1（接続成功！）                     ← EVT_ATTACH 検出
17:13:59  NAS Attach Accept（pcap確認）
17:14:50  +KCNX_IND: 1,5,30（PDNエラー cause=30）     ← R-003 HIGH: PDN接続エラー
17:14:51  Detach request（pcap確認）                  ← R-001 HIGH: NW起因切断
```

**接続継続時間：わずか57秒**

Band40に切り替えてやっと接続できたが、57秒でネットワーク側からDetachされた。cause=30はNW側の拒否を示す。RSRPは-109dBm→-97dBmに改善していたため、電波品質は問題なかった。NW側のPDNゲートウェイ設定またはAPN認証の問題が疑われる。

これらすべてが `run_pipeline.py` を実行するだけで自動検出される。

---

## まとめと今後

**実装済み（Ph.1〜Ph.4）**

- 4種ログパーサー（AT/チップセット/pcap EPD/OTII電流）
- アンカー内挿法によるUTC時刻整合
- SQLite 7テーブルストア
- 10本の診断ルール（rules.yaml）
- Flaskダッシュボード + Plotly波形表示

**今後やりたいこと**

- `reporter.py`：CLI向けASCIIタイムラインレポート出力
- サーバーサイドpcap：通信先Wiresharkとの相関（往復遅延、TCP再送分析）
- MLルール：過去の診断履歴から異常スコアを学習
- リアルタイムストリーミング：シリアルポートから直接ログを取り込むライブ診断モード

LTE-Mの通信障害は「原因がわからない」ことが最大の問題だった。ログを統合して可視化するだけで、これほど明確に原因が見えるとは思っていなかった。同じ課題を抱えているIoTエンジニアの参考になれば幸いだ。
