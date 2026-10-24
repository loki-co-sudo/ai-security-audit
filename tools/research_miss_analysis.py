"""開発者の事後分析ツール: 評価済みケースの『見逃し』を、保存した実行記録（ジャーナル・証拠）と、正解・被験環境の差分から分類する。

**調査システム（core/autonomy/research_*）はこのツールを読まず、正解も入力として渡さない。** 評価済み（使用済み）のケースにだけ使う。
やること:
  1. 欠陥が成立する役割（flaw-effective roles）の特定: 同じ seed で、その欠陥を有効にした環境と無効にした環境に、同じ GET を同じ役割で送り、
     応答が変わる役割を数える（人が正解のメモから推測しない。対象は『パスパラメータの無い GET』）。
  2. 実行ごと（欠陥×実行）の分類: 保存したジャーナルから、LLMが提案した（操作, 検査型, 役割）・登録した仮説とその状態・LLM呼出しの失敗・
     確認枠・予算の終了理由を読み、下の分類のどれかにする。『同じ操作の別ロールを試した』を『欠陥が成立する条件で検証した』と扱わない。
  3. 参照（ジャーナルのseq・実行ディレクトリ・証拠ID）を付ける。事実（記録で確認）／コード解析で分かること／推測を分ける。

分類（上から最初に当てはまるもの）:
  found / hypothesis_state:<状態>（成立する役割の仮説を登録したが、確定しなかった：未選択・予算不足・確認枠不足・対照や確認が未完了・判定不能・
  証拠不足・必要な条件で実験したが逸脱を観測できない）／ rejected_at_concretization・rejected_by_validator（成立する役割の提案が却下）／
  parse_failure（LLM応答を解析できず、取り込めなかった提案の内容は不明）／ only_other_roles（別の役割の仮説だけ）／ no_proposal（その操作の提案なし）／
  unclassifiable（記録不足）
使い方: .venv/bin/python3 tools/research_miss_analysis.py --results <結果>.json --records-dir <記録先> --family list_scope --out <出力>.json
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy.journal import replay  # noqa: E402
from core.autonomy.research_case import load_blind_case  # noqa: E402
from testlab.lab.apps import CanaryServer  # noqa: E402
from tools.research_eval import CASES_DIR, TRUTH_DIR, make_app  # noqa: E402


def _get(app, case, op_id: str, role: str) -> tuple[int, str]:
    op = case.operations[op_id]
    token = app.credentials().get(case.accounts[role].ref)
    req = urllib.request.Request(app.base_url.rstrip("/") + op.path_for({}), headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        e.close()
        return e.code, body


def effective_roles(case, truth: dict, flaw: dict, seed: int) -> dict:
    """同じ seed の環境で、欠陥を有効／無効にして同じ GET を送り、応答が変わる役割を返す。戻り値: {role: {"flawed": 本文, "clean": 本文}}。"""
    if case.operations[flaw["op_id"]].params:
        return {}
    clean_truth = dict(truth, env_flaws=[f for f in truth.get("env_flaws", []) if f != flaw["flaw_id"]])
    out = {}
    canary = CanaryServer().start()
    try:
        with make_app(truth, canary, seed) as a, make_app(clean_truth, canary, seed) as b:
            for role in sorted(case.accounts):
                s1, t1 = _get(a, case, flaw["op_id"], role)
                s2, t2 = _get(b, case, flaw["op_id"], role)
                if (s1, t1) != (s2, t2):
                    out[role] = {"flawed": t1, "clean": t2}
    finally:
        canary.stop()
    return out


def classify_run(flaw: dict, eff: dict, ev: list, found: bool, end_reason: str) -> dict:
    """1実行・1欠陥の分類。ev はその実行のジャーナルイベント。"""
    op, fam = flaw["op_id"], flaw["family"]
    check = {"list_scope": "list_visibility", "field_exposure": "fields_subset"}.get(fam, "deny_expected")
    hyp_roles: dict = {}
    for e in ev:
        if e["type"] == "hypothesis_registered" and e["family"] == fam and e["op_id"] == op:
            hyp_roles[e["probe_role"]] = {"hypothesis_id": e["hypothesis_id"], "registered_seq": e["seq"], "source": e.get("source"),
                                          "probe": e["probe"]["exp_id"] if e.get("probe") else None, "state": "registered", "reason": "",
                                          "state_seq": None, "prior_probe": e.get("prior_probe"), "confirm_blocked": e.get("confirm_blocked")}
    for e in ev:
        if e["type"] == "hypothesis_updated" and e["hypothesis_id"] in {h["hypothesis_id"] for h in hyp_roles.values()}:
            h = next(h for h in hyp_roles.values() if h["hypothesis_id"] == e["hypothesis_id"])
            h["state"], h["reason"], h["state_seq"] = e["to_state"], e["reason"], e["seq"]
    llm_events = [e for e in ev if e["type"] == "llm_proposals"]
    failed = [{"phase": e["phase"], "seq": e["seq"], "why": e.get("parse_error") or e.get("error") or "skipped"}
              for e in llm_events if e.get("parse_error") or e.get("error") or e.get("skipped")]
    props = [{"phase": e["phase"], "seq": e["seq"], "role": x["probe_role"], "status": x["status"], "reason": x["reason"]}
             for e in llm_events if not (e.get("parse_error") or e.get("error") or e.get("skipped"))
             for x in e["results"] if x["op_id"] == op and x["check"] == check]
    needed = sorted(eff)
    tested = sorted(hyp_roles)
    tested_needed = [r for r in tested if r in eff]
    ref = {"hypotheses": {r: hyp_roles[r] for r in tested}, "proposals_for_op": props, "failed_llm_phases": failed,
           "needed_roles": needed, "tested_roles": tested, "run_end_reason": end_reason}
    if found:
        return {"category": "found", "factors": [], **ref}
    factors = []
    if failed:
        factors.append("parse_failure_in_" + ",".join(f["phase"] for f in failed))
    if tested_needed:
        h = hyp_roles[tested_needed[0]]
        return {"category": f"hypothesis_state:{h['state']}:{h['reason']}", "factors": factors, **ref}
    rej = [p for p in props if p["role"] in eff and p["status"] == "rejected"]
    if rej:
        return {"category": "rejected_by_validator" if rej[0]["reason"].startswith("validator:") else "rejected_at_concretization",
                "factors": factors + [rej[0]["reason"]], **ref}
    if failed:
        return {"category": "parse_failure", "factors": factors + (["other_roles_only"] if tested else ["no_proposal_for_op"]), **ref}
    if tested:
        return {"category": "only_other_roles", "factors": factors, **ref}
    if not props:
        return {"category": "no_proposal", "factors": factors, **ref}
    return {"category": "unclassifiable", "factors": factors, **ref}


def analyze(results_path: str, records_dir: str, family: str = "list_scope", method: str = "llm") -> dict:
    with open(results_path, encoding="utf-8") as f:
        res = json.load(f)
    rows, eff_cache = [], {}
    for r in res["runs_compact"]:
        if r["method"] != method or not r.get("records"):
            continue
        case = load_blind_case(os.path.join(CASES_DIR, f"{r['case_id']}.json"))
        with open(os.path.join(TRUTH_DIR, f"{r['case_id']}.json"), encoding="utf-8") as f:
            truth = json.load(f)
        sub = os.path.join(records_dir, os.path.basename(r["records"]["dir"]))
        ev = replay(r["run_id"], os.path.join(sub, "j")).events
        for flaw in truth["flaws"]:
            if flaw["family"] != family or not flaw["reachable"] or not flaw["spec_grounded"]:
                continue
            key = (r["case_id"], flaw["flaw_id"], r["seed"])
            if key not in eff_cache:
                eff_cache[key] = effective_roles(case, truth, flaw, r["seed"])
            eff = eff_cache[key]
            d = r["diagnosis"][flaw["flaw_id"]]
            c = classify_run(flaw, eff, ev, d["category"].startswith("found_"), r.get("trace", {}).get("run_end_reason", ""))
            # 探索時の観測（同じ GET）に、成立する役割で逸脱が既に含まれていたか（証拠で確認）
            disc = {}
            for role in eff:
                exp = f"x:{flaw['op_id']}:{role}"
                evid = next((e.get("evidence_id") for e in ev if e["type"] == "observation_ingested" and e["exp_id"] == exp), None)
                body = None
                if evid:
                    for p in os.listdir(os.path.join(sub, "e")):
                        fp = os.path.join(sub, "e", p, f"{evid}.json")
                        if os.path.exists(fp):
                            with open(fp, encoding="utf-8") as f:
                                body = json.load(f)["body_excerpt"]
                disc[role] = {"evidence_id": evid, "contains_deviation": (body == eff[role]["flawed"]) if body is not None else None}
            rows.append({"case_id": r["case_id"], "flaw_id": flaw["flaw_id"], "seed": r["seed"], "repeat": r["repeat"], "run_id": r["run_id"],
                         "records_dir": r["records"]["dir"], "discovery_observation": disc, **c})
    summary: dict = {}
    for x in rows:
        k = (x["case_id"], x["category"])
        summary[f"{x['case_id']}|{x['category']}"] = summary.get(f"{x['case_id']}|{x['category']}", 0) + 1
    return {"results": os.path.basename(results_path), "family": family, "method": method, "n": len(rows), "summary": summary, "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--records-dir", required=True)
    ap.add_argument("--family", default="list_scope")
    ap.add_argument("--method", default="llm")
    ap.add_argument("--out")
    a = ap.parse_args()
    out = analyze(a.results, a.records_dir, a.family, a.method)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
            f.write("\n")
    print(json.dumps({k: out[k] for k in ("n", "summary")}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
