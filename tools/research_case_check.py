"""未使用ケース（自律調査の評価用）の検査ツール。ケースを作った人が、評価の前に形式・漏えい・独立性を確認するために使う。

調査（エージェント）は一切実行しない。読むのは、公開側の案件ファイル・正解ファイル・被験環境のモジュールだけで、
結果（発見率など）には触れない。正解の中身は画面に出さず、構造の要約（件数・型の内外）だけを出す。

使い方:
  .venv/bin/python3 tools/research_case_check.py --case testlab/lab/blind_cases/<id>.json [--truth testlab/lab/truth/<id>.json]
終了コード: 0=問題なし（警告のみ可）/ 1=修正が必要。
"""
from __future__ import annotations
import argparse
import importlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy.lab_case import LabCaseError  # noqa: E402
from core.autonomy.research_case import load_blind_case  # noqa: E402
from core.autonomy.research_hypothesis import FAMILIES  # noqa: E402

# 公開側の文言に正解や解法を匂わせる語が入っていないか（仕様書は通常の仕様の書き方にする）
LEAK_WORDS = re.compile(r"脆弱|不備|欠陥|バグ|flaw|vuln|exploit|bypass|攻撃|IDOR|BOLA|BFLA|injection|漏えい|漏洩|bug\b", re.I)
RULE_FAMILIES = {"object_authz", "function_authz", "unauth_access", "field_exposure"}      # 調査の規則が提案する型
OTHER_FAMILIES = {"list_scope", "other"}                                                    # 規則の外（LLM提案か未対応）
TEAMDOCS = os.path.join(ROOT, "testlab", "lab", "blind_cases", "blind-docs-01.json")


def _strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def check(case_path: str, truth_path: str | None) -> tuple[list[str], list[str], list[str]]:
    """戻り値: (errors, warnings, info)。"""
    errors: list[str] = []
    warns: list[str] = []
    info: list[str] = []
    try:
        case = load_blind_case(case_path)
    except (OSError, ValueError, LabCaseError) as e:
        return [f"案件ファイルが不正です: {e}"], warns, info
    with open(case_path, encoding="utf-8") as f:
        raw = json.load(f)
    if case.split != "holdout":
        errors.append(f'splitが "{case.split}" です。未使用ケースは "holdout" にしてください（使用記録の対象にするため）')
    for p, s in _strings(raw):
        if LEAK_WORDS.search(s):
            errors.append(f"公開側の文言に正解や解法を匂わせる語があります: {p} = {s[:40]!r}。通常の仕様書の書き方にしてください")
    ops = case.operations
    n_get = sum(1 for o in ops.values() if o.method == "GET")
    kinds = sorted({o.access["kind"] for o in ops.values()})
    info += [f"操作 {len(ops)}件（GET {n_get}・その他 {len(ops) - n_get}）、アカウント {len(case.accounts)}件"
             f"（権限区分 {sorted({a.privilege for a in case.accounts.values()})}）、オブジェクト型 {sorted(case.objects)}",
             f"アクセス条件の種類: {kinds}", f"予算: リクエスト {case.budget['max_requests']}・{case.budget['max_seconds']:.0f}秒"]
    own_list_types = {o.returns.get("object") for o in ops.values() if o.access["kind"] == "own_list" and o.method == "GET" and not o.params}
    for o in ops.values():
        if o.params and o.method == "GET":
            otype = next(iter(o.params.values()))["object"]
            if otype != "user" and otype not in own_list_types:
                errors.append(f"{o.op_id}: 対象の {otype} のIDを観測する手段がありません（{otype} を返す own_list の操作が要ります。"
                              "IDを観測できないと、調査はこの操作を検査できず、欠陥があっても発見できません）")
    for o in ops.values():
        if o.method == "GET" and o.access["kind"] == "own_list":
            obj = case.objects.get(o.returns.get("object"), {})
            if obj.get("shared_field") and not o.access.get("visible_to"):
                errors.append(f"{o.op_id}: 共有先の項目(shared_field)を持つ型の一覧(own_list)には、閲覧条件 access.visible_to（owner＝所有者のみ／owner_or_shared＝所有者または共有先）を"
                              "明記してください。明記が無いと、共有された他人の要素は正常とも逸脱とも判定できず、未確定のままになります")
    if n_get < 6:
        warns.append("GET操作が6件未満です。方式の差が出にくくなります（目安: 8件以上）")
    if len(case.accounts) < 4:
        warns.append("アカウントが4件未満です（目安: 一般3＋管理者1＋期限切れ/無効1）")
    if "unspecified" not in kinds:
        warns.append("アクセス条件が『記載なし(unspecified)』の操作がありません（仕様の曖昧さの扱いを測れません）")
    if not any(o.method != "GET" for o in ops.values()):
        warns.append("GET以外の操作がありません（検証不能の扱いを測れません）")
    try:
        td = load_blind_case(TEAMDOCS)
        same = len({(o.op_id) for o in ops.values()} & {o.op_id for o in td.operations.values()})
        same_p = len({o.path for o in ops.values()} & {o.path for o in td.operations.values()})
        if same / max(1, len(ops)) > 0.4 or same_p / max(1, len(ops)) > 0.4:
            errors.append(f"開発ケース(TeamDocs)と操作名/パスが似すぎています（操作名の一致 {same}件・パスの一致 {same_p}件）。"
                          "名前や配置だけを変えたケースは独立した未知ケースと見なせません")
    except (OSError, ValueError, LabCaseError):
        pass
    if not truth_path:
        return errors, warns, info
    try:
        with open(truth_path, encoding="utf-8") as f:
            truth = json.load(f)
    except (OSError, ValueError) as e:
        return errors + [f"正解ファイルを読めません: {e}"], warns, info
    for k in ("flaws", "non_flaws", "unverifiable", "env_flaws", "app"):
        if k not in truth:
            errors.append(f"正解ファイルに '{k}' がありません")
    flaws = truth.get("flaws", [])
    ids = [f.get("flaw_id") for f in flaws]
    if len(set(ids)) != len(ids):
        errors.append("flaw_id が重複しています")
    for f in flaws:
        if f.get("op_id") not in ops:
            errors.append(f"flaw {f.get('flaw_id')}: op_id が仕様にありません")
        elif ops[f["op_id"]].method != "GET":
            errors.append(f"flaw {f['flaw_id']}: GET以外の操作は『到達可能な欠陥』にできません（unverifiableに書く）")
        if f.get("family") not in RULE_FAMILIES | OTHER_FAMILIES | set(FAMILIES):
            errors.append(f"flaw {f.get('flaw_id')}: familyが未知です: {f.get('family')}")
        if not isinstance(f.get("spec_grounded"), bool) or not isinstance(f.get("reachable"), bool):
            errors.append(f"flaw {f.get('flaw_id')}: spec_grounded/reachable は true/false で書いてください")
    for u in truth.get("unverifiable", []):
        if u.get("op_id") in ops and ops[u["op_id"]].method == "GET":
            errors.append(f"unverifiable {u['op_id']}: GET操作は検証不能にできません")
    inside = sum(1 for f in flaws if f.get("family") in RULE_FAMILIES)
    outside = sum(1 for f in flaws if f.get("family") not in RULE_FAMILIES)
    ungrounded = sum(1 for f in flaws if not f.get("spec_grounded"))
    info.append(f"欠陥 {len(flaws)}件（調査の規則の型の内側 {inside}・外側 {outside}・仕様に根拠なし {ungrounded}）、"
                f"正常な紛らわしい挙動の記載 {len(truth.get('non_flaws', []))}件")
    if flaws and outside == 0:
        warns.append("欠陥が全て規則の型の内側です。型の外の欠陥を含めないと、仮説生成の価値を測れません")
    if len(flaws) < 3:
        warns.append("欠陥が3件未満です（目安: 3〜5件）")
    if ungrounded == 0 and flaws:
        warns.append("仕様に根拠のない欠陥（期待値が推定になるもの）がありません")
    app = truth.get("app") or {}
    try:
        mod = importlib.import_module(app["module"])
        cls = getattr(mod, app["class"])
    except (KeyError, ImportError, AttributeError) as e:
        return errors + [f"被験環境を読み込めません（truth.app の module/class）: {type(e).__name__}: {e}"], warns, info
    try:
        from testlab.lab.apps import CanaryServer, LabApp
        if not issubclass(cls, LabApp):
            errors.append("被験環境は testlab.lab.apps.LabApp を継承してください（リクエスト記録・トークン・起動を共通化するため）")
        else:
            roles = set(getattr(cls, "roles", ()))
            missing = sorted(set(case.accounts) - roles)
            if missing:
                errors.append(f"被験環境の roles に案件のアカウント名がありません: {missing}")
            else:
                with cls(canary=None, flaws=frozenset(truth.get("env_flaws", [])), seed=0) as app_:
                    creds = app_.credentials()
                    absent = sorted(a.ref for a in case.accounts.values() if a.ref not in creds)
                    if absent:
                        errors.append(f"credentials() に案件の参照名がありません: {absent}")
                    import urllib.error
                    import urllib.request
                    try:
                        with urllib.request.urlopen(app_.base_url + "/__check__", timeout=5):
                            pass
                    except urllib.error.HTTPError as e:         # 404/401等のHTTPエラーは正常（起動して応答できればよい）
                        e.close()
                        if e.code >= 500:
                            errors.append(f"存在しないパスで{e.code}を返します（routeの例外を握りつぶして404等にしてください）")
                    except Exception as e:      # noqa: BLE001
                        errors.append(f"被験環境が応答しません: {type(e).__name__}")
    except TypeError as e:
        errors.append(f"被験環境のコンストラクタは (canary=None, flaws=frozenset(), seed=None) を受け取る必要があります: {e}")
    return errors, warns, info


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--truth")
    a = ap.parse_args()
    errors, warns, info = check(a.case, a.truth)
    for line in info:
        print("情報:", line)
    for w in warns:
        print("警告:", w)
    for e in errors:
        print("エラー:", e)
    print(("→ 修正が必要です" if errors else "→ 形式上の問題はありません（警告は設計の参考です）"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
