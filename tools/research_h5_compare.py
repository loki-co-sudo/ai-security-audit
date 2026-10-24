"""H5: 規則に list_scope を足した評価定義の比較（docs/AUTONOMOUS_DISCOVERY_STAGE1.md §19.5）。LLM呼出し0・決定論。

同じ入力・案件・予算・シードで、規則のみ（従来）と規則＋list_scope（rules_ls）を走らせ、再現率・偽陽性・過剰確定・境界逸脱・候補・
確認枠・リクエスト数・終了理由・重複確認を比べる。結果は評価定義の比較で、`rules` の過去の数値は変えない。
使い方: .venv/bin/python3 tools/research_h5_compare.py --out testlab/baselines/research_h5_compare_<日付>.json
"""
from __future__ import annotations
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

CASES = ("blind-docs-01,blind-docs-02,blind-docs-03,blind-docs-clean,unseen-cobalt-17,unseen-cobalt-42,unseen-cobalt-68,"
         "unseen-amber-23,unseen-amber-51,unseen-amber-86")


def _row(r: dict) -> dict:
    g, M = r["grade"], r["metrics"]
    d = r["diagnosis"]
    return {"recall": g["recall"], "false_positive_units": g["false_positive_units"], "ungrounded_overclaim": len(g["ungrounded_overclaim"]),
            "boundary_violations": g["boundary"]["violations"], "requests": g["requests_env"], "end_reason": g["end_reason"],
            "redundant": g["redundant_confirmations"], "supported": M["supported"], "candidates": M["unverified_deviation"], "refuted": M["refuted"],
            "undetermined": M["undetermined"], "confirmation_slots_used": M["confirmation_slots_used"], "confirmed_supported": M["confirmed_supported"],
            "found": sum(1 for x in d.values() if x["category"].startswith("found_") and x["reachable"] and x["spec_grounded"]),
            "list_scope_found": sum(1 for x in d.values() if x["family"] == "list_scope" and x["category"].startswith("found_") and x["reachable"] and x["spec_grounded"]),
            "list_scope_total": sum(1 for x in d.values() if x["family"] == "list_scope" and x["reachable"] and x["spec_grounded"]),
            "prereg_violations": len(M["prereg_violations"])}


def compare(cases: list, seeds: list) -> dict:
    from tools.research_eval import run_one
    rows = []
    for cid in cases:
        for seed in seeds:
            a = _row(run_one(cid, seed))
            b = _row(run_one(cid, seed, rules_list_scope=True))
            rows.append({"case_id": cid, "seed": seed, "rules": a, "rules_ls": b})
    tot = {}
    for arm in ("rules", "rules_ls"):
        t = {k: sum(r[arm][k] for r in rows) for k in ("false_positive_units", "ungrounded_overclaim", "boundary_violations", "requests", "redundant",
                                                      "supported", "candidates", "refuted", "undetermined", "confirmation_slots_used", "confirmed_supported",
                                                      "found", "list_scope_found", "list_scope_total", "prereg_violations")}
        rec = [r[arm]["recall"] for r in rows if r[arm]["recall"] is not None]
        t["recall_mean"] = round(sum(rec) / len(rec), 4) if rec else None
        t["end_reasons"] = {}
        for r in rows:
            t["end_reasons"][r[arm]["end_reason"]] = t["end_reasons"].get(r[arm]["end_reason"], 0) + 1
        tot[arm] = t
    per_case = {}
    for r in rows:
        c = per_case.setdefault(r["case_id"], {"rules": {"found": 0, "list_scope_found": 0, "candidates": 0}, "rules_ls": {"found": 0, "list_scope_found": 0, "candidates": 0}, "runs": 0})
        c["runs"] += 1
        for arm in ("rules", "rules_ls"):
            for k in ("found", "list_scope_found", "candidates"):
                c[arm][k] += r[arm][k]
    safety_worse = any(tot["rules_ls"][k] > tot["rules"][k] for k in ("false_positive_units", "ungrounded_overclaim", "boundary_violations")) or \
        any(r["rules_ls"][k] > r["rules"][k] for r in rows for k in ("false_positive_units", "ungrounded_overclaim", "boundary_violations")) or \
        tot["rules_ls"]["requests"] > tot["rules"]["requests"]
    return {"n_runs_per_arm": len(rows), "totals": tot, "per_case": per_case, "safety_or_cost_worse": safety_worse, "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=CASES)
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    doc = {"note": "H5: 規則のみ対 規則＋list_scope（評価定義の比較。LLM呼出し0）。docs §19.5。`rules` の過去の数値は変更しない。",
           "doc": compare(a.cases.split(","), [int(x) for x in a.seeds.split(",")])}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    d = doc["doc"]
    print(json.dumps({"n_runs_per_arm": d["n_runs_per_arm"], "totals": d["totals"], "per_case": d["per_case"], "safety_or_cost_worse": d["safety_or_cost_worse"]},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
