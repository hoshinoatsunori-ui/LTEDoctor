"""OTII Arc CSV ビューア
otii2csv.py が出力した CSV ファイルを Flask + Plotly.js で可視化する。

起動方法:
    python otii_viewer.py
    ブラウザで http://localhost:5000 を開く
"""

import math
import os

import pandas as pd
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

MAX_POINTS = 50_000  # グラフ表示サンプル上限


# ── ユーティリティ ─────────────────────────────────────────────────────────────

def estimate_row_count(path: str) -> int:
    """先頭 64 KB だけ読んで平均行サイズからファイル全体の行数を推定する。"""
    file_size = os.path.getsize(path)
    with open(path, "rb") as f:
        sample = f.read(min(65536, file_size))
    nl = sample.count(b"\n")
    if nl < 2:
        return max(1, file_size // 50)
    avg = len(sample) / nl
    return max(1, int(file_size / avg) - 1)  # -1 はヘッダー分


def read_csv_decimated(path: str, dec: int) -> pd.DataFrame:
    """dec > 1 のとき skiprows で間引きながら読み込む（メモリ節約）。"""
    if dec <= 1:
        return pd.read_csv(path)
    # row 0 = ヘッダー（常に読む）、データ行は dec 行おきに読む
    return pd.read_csv(path, skiprows=lambda i: i > 0 and (i % dec) != 0)


def to_json_list(series: pd.Series, digits: int) -> list:
    """Series を JSON安全なリストに変換（NaN → null）。"""
    return [None if pd.isna(v) else round(float(v), digits) for v in series]


# ── HTML ──────────────────────────────────────────────────────────────────────

HTML = r"""
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>OTII Viewer</title>
<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', sans-serif; background: #1e1e2e; color: #cdd6f4;
       display: flex; flex-direction: column; height: 100vh; overflow: hidden; }

/* ヘッダー */
#header {
  flex-shrink: 0; padding: 9px 14px; background: #181825;
  display: flex; align-items: center; gap: 9px;
  border-bottom: 1px solid #313244;
}
#header h1 { font-size: 1rem; color: #89b4fa; white-space: nowrap; }
#path-input {
  flex: 1; background: #313244; border: 1px solid #45475a;
  color: #cdd6f4; padding: 6px 10px; border-radius: 4px;
  font-size: 0.85rem; min-width: 0;
}
#path-input:focus { outline: none; border-color: #89b4fa; }
#open-btn {
  background: #89b4fa; color: #1e1e2e; border: none;
  padding: 6px 14px; border-radius: 4px; cursor: pointer;
  font-weight: bold; white-space: nowrap; font-size: 0.88rem;
}
#open-btn:hover { background: #b4befe; }
#spinner {
  display: none; width: 16px; height: 16px;
  border: 2px solid #45475a; border-top-color: #89b4fa;
  border-radius: 50%; animation: spin 0.7s linear infinite; flex-shrink: 0;
}
@keyframes spin { to { transform: rotate(360deg); } }
#status-msg { font-size: 0.8rem; color: #f38ba8; white-space: nowrap; }

/* 統計バー */
#stats-bar {
  flex-shrink: 0; display: none; flex-wrap: wrap; gap: 0;
  background: #181825; border-bottom: 1px solid #313244; padding: 3px 6px;
}
.stat-item { display: flex; flex-direction: column; padding: 3px 12px; border-right: 1px solid #313244; }
.stat-label { color: #6c7086; font-size: 0.7rem; }
.stat-value { font-weight: bold; font-size: 0.82rem; color: #a6e3a1; }
.stat-value.blue  { color: #89b4fa; }
.stat-value.peach { color: #fab387; }

/* メインエリア */
#main { flex: 1; display: flex; overflow: hidden; }

/* ファイルブラウザサイドバー */
#sidebar {
  display: none; flex-direction: column; width: 260px; flex-shrink: 0;
  background: #181825; border-right: 1px solid #313244; overflow-y: auto;
}
#sidebar-title {
  padding: 8px 12px; font-size: 0.78rem; color: #6c7086;
  border-bottom: 1px solid #313244; background: #11111b;
}
.file-item {
  padding: 8px 12px; cursor: pointer; border-bottom: 1px solid #1e1e2e;
  transition: background 0.15s;
}
.file-item:hover { background: #313244; }
.file-item.active { background: #2a2b3d; border-left: 3px solid #89b4fa; padding-left: 9px; }
.file-name { font-size: 0.82rem; color: #cdd6f4; word-break: break-all; }
.file-size { font-size: 0.72rem; color: #6c7086; margin-top: 2px; }

/* チャート */
#chart-wrap { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
#chart { flex: 1; }
#empty-msg {
  flex: 1; display: flex; align-items: center; justify-content: center;
  color: #45475a; font-size: 0.9rem;
}
</style>
</head>
<body>

<div id="header">
  <h1>OTII Viewer</h1>
  <input id="path-input" type="text"
    placeholder="フォルダ または CSV ファイルのパスを入力して Enter">
  <button id="open-btn" onclick="onOpen()">開く</button>
  <div id="spinner"></div>
  <span id="status-msg"></span>
</div>

<div id="stats-bar">
  <div class="stat-item"><span class="stat-label">サンプル数</span><span class="stat-value blue"  id="s-n">-</span></div>
  <div class="stat-item"><span class="stat-label">時間長</span>    <span class="stat-value blue"  id="s-dur">-</span></div>
  <div class="stat-item"><span class="stat-label">電流 min</span>  <span class="stat-value"       id="s-imin">-</span></div>
  <div class="stat-item"><span class="stat-label">電流 max</span>  <span class="stat-value"       id="s-imax">-</span></div>
  <div class="stat-item"><span class="stat-label">電流 mean</span> <span class="stat-value"       id="s-imean">-</span></div>
  <div class="stat-item"><span class="stat-label">電圧 mean</span> <span class="stat-value"       id="s-vmean">-</span></div>
  <div class="stat-item"><span class="stat-label">電力 mean</span> <span class="stat-value peach" id="s-pmean">-</span></div>
  <div class="stat-item"><span class="stat-label">間引き</span>    <span class="stat-value blue"  id="s-dec">-</span></div>
</div>

<div id="main">
  <div id="sidebar">
    <div id="sidebar-title">CSV ファイル</div>
  </div>
  <div id="chart-wrap">
    <div id="empty-msg">フォルダまたは CSV ファイルのパスを入力してください</div>
    <div id="chart" style="display:none"></div>
  </div>
</div>

<script>
const PAPER = '#1e1e2e', PLOT = '#181825', GRID = '#313244', ZERO = '#45475a';
let currentFile = null;

// ── 入力ハンドラ ──────────────────────────────────────────────────────────────

function onOpen() {
  const path = document.getElementById('path-input').value.trim();
  if (!path) return;
  setStatus('');
  setLoading(true);
  fetch('/api/browse?path=' + encodeURIComponent(path))
    .then(r => r.json())
    .then(d => {
      setLoading(false);
      if (d.error) { setStatus(d.error); return; }
      if (d.type === 'dir') {
        showSidebar(d.files);
      } else {
        hideSidebar();
        loadFile(path);
      }
    })
    .catch(e => { setLoading(false); setStatus('通信エラー: ' + e); });
}

// ── サイドバー ────────────────────────────────────────────────────────────────

function showSidebar(files) {
  const sb = document.getElementById('sidebar');
  sb.style.display = 'flex';
  // 既存アイテムをクリア（タイトル以外）
  const title = document.getElementById('sidebar-title');
  sb.innerHTML = '';
  sb.appendChild(title);
  title.textContent = 'CSV ファイル (' + files.length + '件)';

  if (files.length === 0) {
    const el = document.createElement('div');
    el.className = 'file-item';
    el.innerHTML = '<div class="file-name" style="color:#6c7086">CSVファイルがありません</div>';
    sb.appendChild(el);
    return;
  }

  files.forEach(f => {
    const el = document.createElement('div');
    el.className = 'file-item';
    if (f.path === currentFile) el.classList.add('active');
    el.innerHTML =
      '<div class="file-name">' + escHtml(f.name) + '</div>' +
      '<div class="file-size">' + f.size_str + '</div>';
    el.addEventListener('click', () => {
      document.querySelectorAll('.file-item').forEach(x => x.classList.remove('active'));
      el.classList.add('active');
      loadFile(f.path);
    });
    sb.appendChild(el);
  });
}

function hideSidebar() {
  document.getElementById('sidebar').style.display = 'none';
}

// ── ファイル読み込み ──────────────────────────────────────────────────────────

function loadFile(path) {
  currentFile = path;
  setStatus('読み込み中... (大ファイルは数秒かかります)');
  setLoading(true);
  document.getElementById('empty-msg').style.display = 'none';
  document.getElementById('chart').style.display = 'none';

  fetch('/api/load?path=' + encodeURIComponent(path))
    .then(r => r.json())
    .then(d => {
      setLoading(false);
      if (d.error) { setStatus(d.error); return; }
      setStatus('');
      updateStats(d.stats);
      drawChart(d);
    })
    .catch(e => { setLoading(false); setStatus('通信エラー: ' + e); });
}

// ── 統計バー ──────────────────────────────────────────────────────────────────

function updateStats(s) {
  document.getElementById('stats-bar').style.display = 'flex';
  document.getElementById('s-n').textContent     = s.samples.toLocaleString();
  document.getElementById('s-dur').textContent   = s.duration;
  document.getElementById('s-imin').textContent  = s.i_min  ?? '-';
  document.getElementById('s-imax').textContent  = s.i_max  ?? '-';
  document.getElementById('s-imean').textContent = s.i_mean ?? '-';
  document.getElementById('s-vmean').textContent = s.v_mean ?? 'N/A';
  document.getElementById('s-pmean').textContent = s.p_mean ?? 'N/A';
  document.getElementById('s-dec').textContent   =
    s.decimation > 1 ? '1/' + s.decimation : 'なし';
}

// ── グラフ描画 ────────────────────────────────────────────────────────────────

function drawChart(d) {
  const chartEl = document.getElementById('chart');
  chartEl.style.display = 'block';

  const t = d.time;
  const hasV = d.voltage_V.some(v => v != null && !isNaN(v));
  const hasP = d.power_mW.some(v  => v != null && !isNaN(v));
  const panels = [true, hasV, hasP];
  const count  = panels.filter(Boolean).length;
  const gap    = 0.05;
  const h      = (1 - gap * (count - 1)) / count;
  let domains = [], cur = 1.0;
  for (let i = 0; i < 3; i++) {
    if (!panels[i]) { domains.push(null); continue; }
    domains.push([+(cur - h).toFixed(4), +cur.toFixed(4)]);
    cur -= h + gap;
  }

  const ax = (dom, title, unit) => dom ? {
    title: title + ' (' + unit + ')', domain: dom,
    gridcolor: GRID, zerolinecolor: ZERO, showgrid: true,
  } : { visible: false };

  const traces = [
    { x: t, y: d.current_mA, name: '電流', mode: 'lines',
      line: { color: '#89b4fa', width: 1 }, xaxis: 'x', yaxis: 'y1' },
  ];
  if (hasV) traces.push(
    { x: t, y: d.voltage_V, name: '電圧', mode: 'lines',
      line: { color: '#a6e3a1', width: 1 }, xaxis: 'x', yaxis: 'y2' }
  );
  if (hasP) traces.push(
    { x: t, y: d.power_mW, name: '電力', mode: 'lines',
      line: { color: '#fab387', width: 1 }, xaxis: 'x', yaxis: 'y3' }
  );

  Plotly.react('chart', traces, {
    paper_bgcolor: PAPER, plot_bgcolor: PLOT,
    font: { color: '#cdd6f4', size: 11 },
    margin: { l: 72, r: 16, t: 8, b: 40 },
    xaxis:  { title: '経過時間 (s)', gridcolor: GRID, zerolinecolor: ZERO },
    yaxis:  ax(domains[0], '電流', 'mA'),
    yaxis2: ax(domains[1], '電圧', 'V'),
    yaxis3: ax(domains[2], '電力', 'mW'),
    showlegend: false, hovermode: 'x unified',
    hoverlabel: { bgcolor: '#313244', bordercolor: '#45475a',
                  font: { color: '#cdd6f4' } },
  }, { responsive: true });
}

// ── ユーティリティ ────────────────────────────────────────────────────────────

function setStatus(msg) {
  document.getElementById('status-msg').textContent = msg;
}
function setLoading(on) {
  document.getElementById('spinner').style.display = on ? 'block' : 'none';
}
function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

document.getElementById('path-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') onOpen();
});
</script>
</body>
</html>
"""


# ── API ──────────────────────────────────────────────────────────────────────

def norm(path: str) -> str:
    return os.path.expandvars(path.strip())


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/browse")
def api_browse():
    """パスがディレクトリならCSVファイル一覧を、ファイルなら type='file' を返す。"""
    path = norm(request.args.get("path", ""))
    if not path:
        return jsonify({"error": "パスが指定されていません"})

    if os.path.isfile(path):
        return jsonify({"type": "file", "path": path})

    if os.path.isdir(path):
        files = []
        for name in sorted(os.listdir(path)):
            if not name.lower().endswith(".csv"):
                continue
            full = os.path.join(path, name)
            size = os.path.getsize(full)
            if size >= 1_000_000:
                size_str = f"{size / 1_000_000:.1f} MB"
            elif size >= 1_000:
                size_str = f"{size / 1_000:.1f} KB"
            else:
                size_str = f"{size} B"
            files.append({"name": name, "path": full, "size_str": size_str})
        return jsonify({"type": "dir", "files": files})

    return jsonify({"error": f"パスが見つかりません: {path}"})


@app.route("/api/load")
def api_load():
    path = norm(request.args.get("path", ""))
    if not path:
        return jsonify({"error": "パスが指定されていません"})
    if not os.path.isfile(path):
        return jsonify({"error": f"ファイルが見つかりません: {path}"})

    # 行数推定 → 間引き率決定
    estimated = estimate_row_count(path)
    dec = max(1, math.ceil(estimated / MAX_POINTS))

    try:
        df = read_csv_decimated(path, dec)
    except Exception as e:
        return jsonify({"error": f"CSV 読み込みエラー: {e}"})

    required = {"timestamp_s", "current_A"}
    missing = required - set(df.columns)
    if missing:
        return jsonify({"error": f"必須カラムがありません: {missing}"})

    # 実際の行数で統計・dec を再確認
    actual_total = int(estimated)
    actual_dec   = dec

    t          = df["timestamp_s"].round(6).tolist()
    current_mA = to_json_list(df["current_A"] * 1000, 4)
    voltage_V  = to_json_list(df["voltage_V"], 5) if "voltage_V" in df.columns else [None] * len(df)
    power_mW   = to_json_list(df["power_W"] * 1000, 4) if "power_W" in df.columns else [None] * len(df)

    i_arr      = df["current_A"] * 1000
    duration_s = float(df["timestamp_s"].iloc[-1]) - float(df["timestamp_s"].iloc[0])

    def fmv(val, unit, dp=3):
        try:
            v = float(val)
            return f"{v:.{dp}f} {unit}" if pd.notna(v) else None
        except Exception:
            return None

    stats = {
        "samples":    actual_total,
        "duration":   f"{duration_s:.2f} s",
        "decimation": actual_dec,
        "i_min":      fmv(i_arr.min(), "mA"),
        "i_max":      fmv(i_arr.max(), "mA"),
        "i_mean":     fmv(i_arr.mean(), "mA"),
        "v_mean":     fmv(df["voltage_V"].mean(), "V", 4) if "voltage_V" in df.columns else None,
        "p_mean":     fmv((df["power_W"] * 1000).mean(), "mW") if "power_W" in df.columns else None,
    }

    return jsonify({
        "time":       t,
        "current_mA": current_mA,
        "voltage_V":  voltage_V,
        "power_mW":   power_mW,
        "stats":      stats,
    })


if __name__ == "__main__":
    print("OTII Viewer 起動中... http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
