# lib/ — オフラインインストール用ホイールキャッシュ

このフォルダには LTE Doctor の Python 依存ライブラリが `.whl` 形式で保存されています。  
インターネット接続のない環境でも `pip install` できます。

## ダウンロード済みパッケージ（32個、約29 MB）

| パッケージ | 用途 |
|-----------|------|
| flask | Web ダッシュボード |
| pandas, numpy | データ処理・信号解析 |
| pyyaml | rules.yaml 読み込み |
| scapy | pcapng パース |
| anthropic | Claude API（AI診断機能） |
| python-dotenv | .env 読み込み |
| werkzeug, jinja2, click 他 | Flask の依存ライブラリ |
| httpx, httpcore, h11 他 | anthropic SDK の依存ライブラリ |

## インストール方法

### オフライン環境（このフォルダを使用）

```bash
pip install --no-index --find-links=lib -r requirements.txt
```

### オンライン環境（通常のインストール）

```bash
pip install -r requirements.txt
```

## ホイールの再ダウンロード

このフォルダの `.whl` ファイルは Git 管理外です。  
新しいマシンで使う場合はオンライン環境で以下を実行してください：

```bash
pip download -r requirements.txt --dest lib
```

## 注意

- ダウンロードされたホイールは **Windows / Python 3.14 用**です
- 別の OS や Python バージョンでは再ダウンロードが必要です
