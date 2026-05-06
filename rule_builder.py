"""
rule_builder.py  v2
LTE DiagRule Builder - Flask Web UI (4タブ構成)

  ① ルール一覧  : rules/<id>.yaml を CRUD + DB テスト
  ② AI生成     : 自然言語 → Claude API → YAML
  ③ YAMLインポート: YAML 貼り付けバッチインポート
  ④ エクスポート  : 全ルールを統合 YAML として出力

使い方:
  python rule_builder.py
  python rule_builder.py --rules-dir rules/ --db diag.sqlite --port 5001
  ブラウザで http://localhost:5001 を開く

AI生成を使用するには Anthropic API キーが必要:
  set ANTHROPIC_API_KEY=sk-ant-...   (Windows)
  export ANTHROPIC_API_KEY=sk-ant-... (Linux/macOS)
  または --api-key オプションで指定
"""

import argparse
import copy
import json
import os
import sys
from pathlib import Path

import yaml
from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, url_for)

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import event_correlator
import db_store

app = Flask(__name__, template_folder=str(HERE / "templates"))
app.secret_key = os.urandom(24)

_cfg = {
    "rules_dir": str(HERE / "rules"),
    "db_path":   str(HERE / "diag.sqlite"),
    "api_key":   "",
}

EVT_TYPES = [
    "EVT_ATTACH", "EVT_DETACH", "EVT_TX", "EVT_RX",
    "EVT_PDN_ERROR", "EVT_NWREJECT", "EVT_TIMEOUT", "EVT_RESET",
]
SEVERITIES = ["critical", "high", "medium", "low", "info"]


# ── ルール I/O（個別ファイル） ────────────────────────────────────────────

def _rules_dir() -> Path:
    p = Path(_cfg["rules_dir"])
    p.mkdir(parents=True, exist_ok=True)
    return p


def _load_rules() -> list[dict]:
    """rules/*.yaml を読み込み、ファイル名順にルールリストを返す。"""
    rules = []
    for f in sorted(_rules_dir().glob("*.yaml")):
        try:
            with open(f, encoding="utf-8") as fp:
                rule = yaml.safe_load(fp)
            if isinstance(rule, dict) and rule.get("id"):
                rules.append(rule)
        except Exception:
            pass
    return rules


def _load_rule(rule_id: str) -> dict | None:
    p = _rules_dir() / f"{rule_id}.yaml"
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _save_rule(rule: dict) -> None:
    p = _rules_dir() / f"{rule['id']}.yaml"
    with open(p, "w", encoding="utf-8") as f:
        yaml.dump(rule, f, allow_unicode=True, sort_keys=False,
                  default_flow_style=False)


def _delete_rule(rule_id: str) -> bool:
    p = _rules_dir() / f"{rule_id}.yaml"
    if p.exists():
        p.unlink()
        return True
    return False


# ── DB ヘルパー ──────────────────────────────────────────────────────────

def _db_available() -> bool:
    p = _cfg["db_path"]
    return bool(p and os.path.exists(p))


def _get_match_counts() -> dict[str, int]:
    if not _db_available():
        return {}
    try:
        db = db_store.DiagDb(_cfg["db_path"])
        rows = db.query(
            "SELECT rule_id, COUNT(*) FROM correlated_events GROUP BY rule_id"
        )
        db.close()
        return {row[0]: row[1] for row in rows}
    except Exception:
        return {}


def _run_test(rule_dict: dict) -> list[dict]:
    if not _db_available():
        return []
    db = db_store.DiagDb(_cfg["db_path"])
    try:
        events = event_correlator.extract_events(db.conn)
        results = event_correlator.evaluate_rules(events, [rule_dict])
    finally:
        db.close()
    return results


# ── フォームパース / バリデーション ──────────────────────────────────────

def _form_to_rule(form) -> dict:
    rule: dict = {
        "id":          form.get("id", "").strip(),
        "description": form.get("description", "").strip(),
        "trigger": {
            "event": form.get("trigger_event", "EVT_DETACH"),
        },
        "conditions": [],
        "severity":   form.get("severity", "high"),
        "diagnosis":  form.get("diagnosis", "").strip(),
    }
    cnt = int(form.get("trigger_count") or 1)
    if cnt > 1:
        rule["trigger"]["count"] = cnt
        rule["trigger"]["window_ms"] = int(form.get("trigger_window_ms") or 0)
    mat = form.get("trigger_match_at", "").strip()
    if mat:
        rule["trigger"]["match_at"] = mat

    idx_set = set()
    for key in form.keys():
        if key.startswith("cond_") and key.endswith("_source"):
            idx_set.add(key[5:-7])
    for i in sorted(idx_set, key=lambda x: int(x) if x.isdigit() else 0):
        cond: dict = {
            "source":    form.get(f"cond_{i}_source", "any"),
            "within_ms": int(form.get(f"cond_{i}_within_ms") or 5000),
        }
        ev = form.get(f"cond_{i}_event", "").strip()
        if ev:
            cond["event"] = ev
        match = form.get(f"cond_{i}_match", "").strip()
        if match:
            cond["match"] = match
        if form.get(f"cond_{i}_absent"):
            cond["absent"] = True
        rule["conditions"].append(cond)
    return rule


def _validate_rule(rule: dict) -> list[str]:
    errors = []
    if not rule.get("id"):
        errors.append("ID は必須です")
    if not rule.get("description"):
        errors.append("説明は必須です")
    if not rule.get("trigger", {}).get("event"):
        errors.append("トリガーイベントは必須です")
    if rule.get("severity") not in SEVERITIES:
        errors.append(f"重要度は {SEVERITIES} のいずれかを選択してください")
    if not rule.get("diagnosis"):
        errors.append("診断メッセージは必須です")
    return errors


# ── HTML Routes ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    rules = _load_rules()
    return render_template("rule_builder/index.html", rules=rules)


@app.route("/rules/new")
def rule_new():
    return render_template("rule_builder/edit.html", rule=None,
                           EVT_TYPES=EVT_TYPES, SEVERITIES=SEVERITIES)


@app.route("/rules/<rule_id>/edit")
def rule_edit(rule_id: str):
    rule = _load_rule(rule_id)
    if rule is None:
        flash(f"ルール {rule_id} が見つかりません", "danger")
        return redirect(url_for("index"))
    return render_template("rule_builder/edit.html", rule=rule,
                           EVT_TYPES=EVT_TYPES, SEVERITIES=SEVERITIES)


@app.route("/rules", methods=["POST"])
def rule_create():
    rule = _form_to_rule(request.form)
    errors = _validate_rule(rule)
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template("rule_builder/edit.html", rule=rule,
                               EVT_TYPES=EVT_TYPES, SEVERITIES=SEVERITIES)
    if _load_rule(rule["id"]) is not None:
        flash(f"ID {rule['id']} は既に存在します", "danger")
        return render_template("rule_builder/edit.html", rule=rule,
                               EVT_TYPES=EVT_TYPES, SEVERITIES=SEVERITIES)
    _save_rule(rule)
    flash(f"ルール {rule['id']} を追加しました", "success")
    return redirect(url_for("index"))


@app.route("/rules/<rule_id>", methods=["POST"])
def rule_update(rule_id: str):
    new_rule = _form_to_rule(request.form)
    new_rule["id"] = rule_id
    errors = _validate_rule(new_rule)
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template("rule_builder/edit.html", rule=new_rule,
                               EVT_TYPES=EVT_TYPES, SEVERITIES=SEVERITIES)
    if _load_rule(rule_id) is None:
        flash(f"ルール {rule_id} が見つかりません", "danger")
        return redirect(url_for("index"))
    _save_rule(new_rule)
    flash(f"ルール {rule_id} を更新しました", "success")
    return redirect(url_for("index"))


@app.route("/rules/<rule_id>/delete", methods=["POST"])
def rule_delete(rule_id: str):
    if _delete_rule(rule_id):
        flash(f"ルール {rule_id} を削除しました", "success")
    else:
        flash(f"ルール {rule_id} が見つかりません", "warning")
    return redirect(url_for("index"))


@app.route("/rules/<rule_id>/test", methods=["POST"])
def rule_test(rule_id: str):
    if not _db_available():
        return jsonify({"error": f"DB が見つかりません。run_pipeline.py を先に実行してください。({_cfg['db_path']})"})
    rule = _load_rule(rule_id)
    if rule is None:
        return jsonify({"error": f"ルール {rule_id} が見つかりません"}), 404
    try:
        results = _run_test(rule)
        return jsonify({"results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rules/_preview/test", methods=["POST"])
def rule_preview_test():
    if not _db_available():
        return jsonify({"error": f"DB が見つかりません。({_cfg['db_path']})"})
    rule = request.get_json(force=True, silent=True)
    if not rule:
        return jsonify({"error": "ルール定義が取得できません"}), 400
    try:
        results = _run_test(rule)
        return jsonify({"results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AI ルール生成 ─────────────────────────────────────────────────────────

_AI_SYSTEM = """\
You are an LTE diagnostic rule generator for the LTEDoctor system.
Convert the user's natural language description into a JSON rule object.

Rule schema:
{
  "id": "R-XXX",
  "description": "...",
  "trigger": {
    "event": "EVT_ATTACH|EVT_DETACH|EVT_TX|EVT_RX|EVT_PDN_ERROR|EVT_NWREJECT|EVT_TIMEOUT|EVT_RESET",
    "count": 1,
    "window_ms": 0,
    "match_at": "..."
  },
  "conditions": [
    {
      "source": "at|pcap|chipset|any",
      "event": "EVT_*",
      "match": "...",
      "within_ms": 5000,
      "absent": false
    }
  ],
  "severity": "critical|high|medium|low|info",
  "diagnosis": "..."
}

Event types:
- EVT_ATTACH   : LTE registration success (+CEREG:1/5 or NAS Attach Accept)
- EVT_DETACH   : LTE disconnect (+CEREG:0/2 or NAS Detach)
- EVT_TX       : UDP/TCP send (AT+KUDPSND)
- EVT_RX       : UDP/TCP receive (+KUDP_DATA/+KTCP_DATA)
- EVT_PDN_ERROR: PDN connection error (+KCNX_IND state=5)
- EVT_NWREJECT : Network Attach Reject
- EVT_TIMEOUT  : AT command timeout
- EVT_RESET    : Module reset (+KSUP: 0)

Rules:
- trigger.count > 1 enables burst mode: fire when count events occur within window_ms
- condition.absent=true: condition passes when no match found in time window
- diagnosis should be written in Japanese

Respond ONLY with the JSON object. No markdown, no explanation.\
"""


@app.route("/api/ai_generate", methods=["POST"])
def api_ai_generate():
    api_key = _cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return jsonify({"error": "ANTHROPIC_API_KEY が設定されていません。環境変数または --api-key オプションを使用してください。"}), 400

    data = request.get_json(force=True, silent=True) or {}
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "prompt が空です"}), 400

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            system=_AI_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text.strip()
        # ```json ブロックがある場合も対応
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:])
            if "```" in text:
                text = text[:text.index("```")]
        rule = json.loads(text.strip())
        return jsonify({"rule": rule})
    except json.JSONDecodeError as e:
        return jsonify({"error": f"JSON パースエラー: {e}", "raw": text}), 422
    except ImportError:
        return jsonify({"error": "anthropic パッケージが見つかりません: pip install anthropic"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── YAML インポート / エクスポート ────────────────────────────────────────

@app.route("/api/import_yaml", methods=["POST"])
def api_import_yaml():
    data = request.get_json(force=True, silent=True) or {}
    yaml_text = data.get("yaml", "")
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        return jsonify({"error": f"YAML パースエラー: {e}"}), 422

    if isinstance(parsed, dict) and "rules" in parsed:
        incoming = parsed["rules"]
    elif isinstance(parsed, list):
        incoming = parsed
    elif isinstance(parsed, dict) and parsed.get("id"):
        incoming = [parsed]
    else:
        return jsonify({"error": "rules: リストまたは単一ルール dict を指定してください"}), 422

    added, skipped = [], []
    for rule in (incoming or []):
        if not isinstance(rule, dict):
            continue
        errors = _validate_rule(rule)
        if errors:
            skipped.append({"id": rule.get("id", "?"), "reason": ", ".join(errors)})
            continue
        if _load_rule(rule["id"]) is not None:
            skipped.append({"id": rule["id"], "reason": "既に存在します（スキップ）"})
            continue
        _save_rule(rule)
        added.append(rule["id"])

    return jsonify({"added": added, "skipped": skipped})


@app.route("/api/export_yaml")
def api_export_yaml():
    rules = _load_rules()
    text = yaml.dump(
        {"rules": rules},
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    return jsonify({"yaml": text, "count": len(rules)})


# ── JSON API ──────────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
def api_rules_get():
    rules = _load_rules()
    counts = _get_match_counts()
    result = []
    for r in rules:
        entry = copy.deepcopy(r)
        entry["match_count"] = counts.get(r.get("id"), 0) if _db_available() else None
        result.append(entry)
    return jsonify({
        "rules":       result,
        "db_available": _db_available(),
        "db_path":     _cfg["db_path"],
        "rules_dir":   _cfg["rules_dir"],
    })


@app.route("/api/rules", methods=["POST"])
def api_rules_add():
    """JSON ボディからルールを直接追加する（AI生成タブの「一覧に追加」で使用）。"""
    rule = request.get_json(force=True, silent=True)
    if not rule:
        return jsonify({"error": "ルール定義が取得できません"}), 400
    errors = _validate_rule(rule)
    if errors:
        return jsonify({"error": errors}), 422
    if _load_rule(rule["id"]) is not None:
        return jsonify({"error": f"ID {rule['id']} は既に存在します"}), 409
    _save_rule(rule)
    return jsonify({"ok": True, "id": rule["id"]})


@app.route("/api/events")
def api_events():
    if not _db_available():
        return jsonify({"error": "DB が見つかりません"}), 404
    try:
        db = db_store.DiagDb(_cfg["db_path"])
        events = event_correlator.extract_events(db.conn)
        db.close()
        return jsonify({
            "count": len(events),
            "events": [
                {
                    "event_type": e.event_type,
                    "utc_ts":     e.utc_ts.isoformat(),
                    "source":     e.source,
                    "raw_text":   e.raw_text,
                }
                for e in events[:200]
            ],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── エントリポイント ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="LTE DiagRule Builder v2")
    parser.add_argument("--rules-dir", default=str(HERE / "rules"),
                        help="ルールファイルディレクトリ (default: ./rules/)")
    parser.add_argument("--db",        default=str(HERE / "diag.sqlite"),
                        help="diag.sqlite パス（省略可）")
    parser.add_argument("--port",      type=int, default=5001, help="ポート番号")
    parser.add_argument("--host",      default="127.0.0.1", help="ホスト")
    parser.add_argument("--api-key",   default="",
                        help="Anthropic API key（または ANTHROPIC_API_KEY 環境変数）")
    args = parser.parse_args()

    _cfg["rules_dir"] = args.rules_dir
    _cfg["db_path"]   = args.db
    if args.api_key:
        _cfg["api_key"] = args.api_key

    ai_status = "設定済み" if (_cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY")) \
                else "未設定（AI生成タブは使用不可）"

    print("LTE DiagRule Builder v2")
    print(f"  rules dir : {_cfg['rules_dir']}")
    print(f"  db        : {_cfg['db_path']} ({'あり' if _db_available() else 'なし'})")
    print(f"  Claude API: {ai_status}")
    print(f"  URL       : http://{args.host}:{args.port}/")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
