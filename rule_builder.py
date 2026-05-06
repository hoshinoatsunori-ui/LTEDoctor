"""
rule_builder.py
LTE DiagRule Builder - Flask Web UI

rules.yaml の相関ルールをブラウザ上で CRUD し、
現在の diag.sqlite に対してリアルタイムテストできるツール。

使い方:
  python rule_builder.py
  python rule_builder.py --db diag.sqlite --rules rules.yaml --port 5001
  ブラウザで http://localhost:5001 を開く
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

# event_correlator / db_store を同ディレクトリからインポート
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import event_correlator
import db_store

app = Flask(__name__, template_folder=str(HERE / "templates"))
app.secret_key = os.urandom(24)

# ── グローバル設定（起動時に argparse で設定） ─────────────────────
_cfg = {
    "rules_path": str(HERE / "rules.yaml"),
    "db_path":    str(HERE / "diag.sqlite"),
}

EVT_TYPES = [
    "EVT_ATTACH", "EVT_DETACH", "EVT_TX", "EVT_RX",
    "EVT_PDN_ERROR", "EVT_NWREJECT", "EVT_TIMEOUT", "EVT_RESET",
]

SEVERITIES = ["critical", "high", "medium", "low", "info"]


# ── ルール I/O ──────────────────────────────────────────────────────
def _load_rules() -> list[dict]:
    path = _cfg["rules_path"]
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("rules", [])


def _save_rules(rules: list[dict]) -> None:
    path = _cfg["rules_path"]
    # コメントは消えるが順序は保持
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(
            {"rules": rules},
            f,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def _find_rule(rule_id: str) -> tuple[int, dict | None]:
    """(index, rule_dict) を返す。見つからなければ (-1, None)"""
    for i, r in enumerate(_load_rules()):
        if r.get("id") == rule_id:
            return i, r
    return -1, None


# ── DB ヘルパー ─────────────────────────────────────────────────────
def _db_available() -> bool:
    p = _cfg["db_path"]
    return bool(p and os.path.exists(p))


def _get_match_counts() -> dict[str, int]:
    """correlated_events から rule_id ごとのマッチ件数を返す"""
    if not _db_available():
        return {}
    try:
        db = db_store.DiagDb(_cfg["db_path"])
        rows = db.query("SELECT rule_id, COUNT(*) FROM correlated_events GROUP BY rule_id")
        db.close()
        return {row[0]: row[1] for row in rows}
    except Exception:
        return {}


def _run_test(rule_dict: dict) -> list[dict]:
    """rule_dict を現在の DB に対して評価し、マッチ結果リストを返す"""
    if not _db_available():
        return []
    db = db_store.DiagDb(_cfg["db_path"])
    try:
        events = event_correlator.extract_events(db.conn)
        results = event_correlator.evaluate_rules(events, [rule_dict])
    finally:
        db.close()
    return results


# ── フォームパース ───────────────────────────────────────────────────
def _form_to_rule(form) -> dict:
    """
    HTML フォームの MultiDict → ルール dict に変換する。
    conditions は cond_<idx>_<field> 形式のキーを探してまとめる。
    """
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

    # conditions: form に cond_<idx>_source があるキーを収集
    idx_set = set()
    for key in form.keys():
        if key.startswith("cond_") and key.endswith("_source"):
            idx_set.add(key[5:-7])  # "cond_" + idx + "_source"

    for i in sorted(idx_set, key=lambda x: int(x) if x.isdigit() else 0):
        cond: dict = {
            "source": form.get(f"cond_{i}_source", "any"),
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


# ── Routes ────────────────────────────────────────────────────────────

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
    _, rule = _find_rule(rule_id)
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

    rules = _load_rules()
    if any(r.get("id") == rule["id"] for r in rules):
        flash(f"ID {rule['id']} は既に存在します", "danger")
        return render_template("rule_builder/edit.html", rule=rule,
                               EVT_TYPES=EVT_TYPES, SEVERITIES=SEVERITIES)

    rules.append(rule)
    _save_rules(rules)
    flash(f"ルール {rule['id']} を追加しました", "success")
    return redirect(url_for("index"))


@app.route("/rules/<rule_id>", methods=["POST"])
def rule_update(rule_id: str):
    new_rule = _form_to_rule(request.form)
    new_rule["id"] = rule_id   # ID は変更不可
    errors = _validate_rule(new_rule)
    if errors:
        for e in errors:
            flash(e, "danger")
        return render_template("rule_builder/edit.html", rule=new_rule,
                               EVT_TYPES=EVT_TYPES, SEVERITIES=SEVERITIES)

    rules = _load_rules()
    idx, existing = _find_rule(rule_id)
    if existing is None:
        flash(f"ルール {rule_id} が見つかりません", "danger")
        return redirect(url_for("index"))

    rules[idx] = new_rule
    _save_rules(rules)
    flash(f"ルール {rule_id} を更新しました", "success")
    return redirect(url_for("index"))


@app.route("/rules/<rule_id>/delete", methods=["POST"])
def rule_delete(rule_id: str):
    rules = _load_rules()
    new_rules = [r for r in rules if r.get("id") != rule_id]
    if len(new_rules) == len(rules):
        flash(f"ルール {rule_id} が見つかりません", "warning")
    else:
        _save_rules(new_rules)
        flash(f"ルール {rule_id} を削除しました", "success")
    return redirect(url_for("index"))


@app.route("/rules/<rule_id>/test", methods=["POST"])
def rule_test(rule_id: str):
    """既存ルールを DB に対してテスト（JSON 返却）"""
    if not _db_available():
        return jsonify({"error": f"DB が見つかりません。run_pipeline.py を先に実行してください。({_cfg['db_path']})"})
    _, rule = _find_rule(rule_id)
    if rule is None:
        return jsonify({"error": f"ルール {rule_id} が見つかりません"}), 404
    try:
        results = _run_test(rule)
        return jsonify({"results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/rules/_preview/test", methods=["POST"])
def rule_preview_test():
    """フォームの現在値（JSON）を受け取り、DB に対してテスト（JSON 返却）"""
    if not _db_available():
        return jsonify({"error": f"DB が見つかりません。run_pipeline.py を先に実行してください。({_cfg['db_path']})"})
    rule = request.get_json(force=True, silent=True)
    if not rule:
        return jsonify({"error": "ルール定義が取得できません"}), 400
    try:
        results = _run_test(rule)
        return jsonify({"results": results, "count": len(results)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── JSON API ──────────────────────────────────────────────────────────

@app.route("/api/rules")
def api_rules():
    rules = _load_rules()
    counts = _get_match_counts()
    result = []
    for r in rules:
        entry = copy.deepcopy(r)
        entry["match_count"] = counts.get(r.get("id"), 0) if _db_available() else None
        result.append(entry)
    return jsonify({
        "rules": result,
        "db_available": _db_available(),
        "db_path": _cfg["db_path"],
        "rules_path": _cfg["rules_path"],
    })


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
                    "utc_ts": e.utc_ts.isoformat(),
                    "source": e.source,
                    "raw_text": e.raw_text,
                }
                for e in events[:200]   # 先頭 200 件
            ],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── エントリポイント ──────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="LTE DiagRule Builder")
    parser.add_argument("--rules", default=str(HERE / "rules.yaml"),
                        help="rules.yaml パス")
    parser.add_argument("--db",    default=str(HERE / "diag.sqlite"),
                        help="diag.sqlite パス（省略可）")
    parser.add_argument("--port",  type=int, default=5001, help="ポート番号")
    parser.add_argument("--host",  default="127.0.0.1", help="ホスト")
    args = parser.parse_args()

    _cfg["rules_path"] = args.rules
    _cfg["db_path"]    = args.db

    print(f"LTE DiagRule Builder")
    print(f"  rules : {_cfg['rules_path']}")
    print(f"  db    : {_cfg['db_path']} ({'あり' if _db_available() else 'なし'})")
    print(f"  URL   : http://{args.host}:{args.port}/")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
