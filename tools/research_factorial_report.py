"""再計画×重複抑制の切り分け実験（docs/AUTONOMOUS_DISCOVERY_STAGE1.md §13）の集計。事前に決めた分析だけを行う。
使い方: .venv/bin/python3 tools/research_factorial_report.py testlab/baselines/research_replan_dedup_factorial_*.json
"""
from __future__ import annotations
import json
import sys

CELLS = ("adaptive-dedup", "adaptive-nodedup", "static-dedup", "static-nodedup")
THRESHOLD = 0.05            # §11.2 と同じ閾値


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 4) if xs else None


def report(doc: dict) -> dict:
    curve = doc["curve"]
    flawed = [c for c, by in curve.items() if any(b["recall_mean"] is not None for st in by.values() for b in st.values())]
    budgets = sorted({int(b) for c in curve.values() for st in c.values() for b in st})
    out = {"flawed_cases": flawed, "budgets": budgets, "cells": {}, "effects": {}, "safety": {}}
    for cell in CELLS:
        per_case = {c: {str(b): curve[c][cell][str(b)] for b in budgets} for c in curve}
        out["cells"][cell] = {
            "recall_by_budget": {str(b): _mean([curve[c][cell][str(b)]["recall_mean"] for c in flawed]) for b in budgets},
            "recall_mean_all_budgets": _mean([curve[c][cell][str(b)]["recall_mean"] for c in flawed for b in budgets]),
            "redundant_mean": _mean([curve[c][cell][str(b)]["redundant_mean"] for c in curve for b in budgets]),
            "requests_mean": _mean([curve[c][cell][str(b)]["requests_mean"] for c in curve for b in budgets]),
            "not_examined_mean": _mean([curve[c][cell][str(b)]["not_examined_mean"] for c in curve for b in budgets]),
            "per_case_recall_mean": {c: _mean([per_case[c][str(b)]["recall_mean"] for b in budgets]) for c in flawed}}
        out["safety"][cell] = {k: sum(curve[c][cell][str(b)][k] for c in curve for b in budgets)
                               for k in ("fp_total", "overclaim_total", "violations_total")}
    R = lambda cell: out["cells"][cell]["recall_mean_all_budgets"]  # noqa: E731
    D = lambda cell: out["cells"][cell]["redundant_mean"]  # noqa: E731
    def eff(a, b):
        d = round(R(a) - R(b), 4)
        return {"recall_diff": d, "redundant_diff": round(D(a) - D(b), 4),
                "verdict": "寄与なし(±0.05未満)" if abs(d) < THRESHOLD else ("前者が上回る" if d > 0 else "後者が上回る")}
    out["effects"] = {
        "replan_given_dedup (adaptive-dedup − static-dedup)": eff("adaptive-dedup", "static-dedup"),
        "replan_given_nodedup (adaptive-nodedup − static-nodedup)": eff("adaptive-nodedup", "static-nodedup"),
        "dedup_given_adaptive (adaptive-dedup − adaptive-nodedup)": eff("adaptive-dedup", "adaptive-nodedup"),
        "dedup_given_static (static-dedup − static-nodedup)": eff("static-dedup", "static-nodedup")}
    e = out["effects"]
    out["interaction"] = {
        "replan_effect_changes_with_dedup": round(e["replan_given_dedup (adaptive-dedup − static-dedup)"]["recall_diff"]
                                                  - e["replan_given_nodedup (adaptive-nodedup − static-nodedup)"]["recall_diff"], 4),
        "dedup_effect_changes_with_replan": round(e["dedup_given_adaptive (adaptive-dedup − adaptive-nodedup)"]["recall_diff"]
                                                  - e["dedup_given_static (static-dedup − static-nodedup)"]["recall_diff"], 4)}
    return out


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as f:
        print(json.dumps(report(json.load(f)), ensure_ascii=False, indent=1))
