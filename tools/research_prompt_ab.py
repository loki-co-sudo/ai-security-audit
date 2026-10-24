"""プロンプト版の A/B（開発・回帰ケース。docs/AUTONOMOUS_DISCOVERY_STAGE1.md §19.3 の事前登録どおり）。

同じコミット・同じモデル・同じ予算・同じ（案件, シード, 反復）の対で、2つのプロンプト版を**交互の順序で**走らせる
（提供側の変動が両腕に同じように入る）。主指標は『成立する役割の仮説を登録した実行の割合』（list_scope 欠陥のある実行）。
採用基準は事前登録した値を機械的に計算して出す（結果を見てからの調整はしない）。
正解は testlab/lab/truth を読む（開発者側の事後分析。調査システムには渡さない）。出力に操作名・欠陥IDは含めない。
費用上限は `--max-spend-usd`（次の対の最悪値を実測の累計に足して超えるなら始めない）。上限に達したら完全な対だけを集計する。

使い方: .venv/bin/python3 tools/research_prompt_ab.py --protocol <frozen.json> --model z-ai/glm-5.3-flash --approve-real-llm \\
          --max-spend-usd 0.10 --records-dir reports/stage2_records/<名前> --out <出力>.json
"""
from __future__ import annotations
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

ARMS = ("research-propose/1", "research-propose/2")
REGRESSION = "unseen-cobalt-17,unseen-cobalt-42,unseen-cobalt-68,unseen-amber-23,unseen-amber-51,unseen-amber-86"
DEV = "blind-docs-01,blind-docs-02,blind-docs-03,blind-docs-clean"
# 採用基準（事前登録。docs §19.3）
CRITERIA = {"primary_gain_min": 0.20, "unparsed_rate_increase_max": 0.10, "input_token_ratio_max": 1.6}


def run_arm(case_id: str, seed: int, version: str, llm, max_tokens: int, records_dir: str | None, max_llm_calls: int) -> dict:
    """1実行。run_one の結果に、list_scope 欠陥の『成立する役割の仮説を登録したか』の分類（開発者側）を足す。"""
    from core.autonomy.journal import replay
    from core.autonomy.research_case import load_blind_case
    from tools.research_eval import CASES_DIR, TRUTH_DIR, run_one
    from tools.research_miss_analysis import classify_run, effective_roles
    sub = os.path.join(records_dir, f"{version.split('/')[-1]}", f"{case_id}_s{seed}") if records_dir else None
    r = run_one(case_id, seed, llm=llm, budget_override={"max_llm_calls": max_llm_calls}, records_dir=sub, prompt_version=version)
    misses = []
    if sub:
        case = load_blind_case(os.path.join(CASES_DIR, f"{case_id}.json"))
        with open(os.path.join(TRUTH_DIR, f"{case_id}.json"), encoding="utf-8") as f:
            truth = json.load(f)
        events = replay(r["run_id"], sub + "/j").events
        for flaw in truth["flaws"]:
            if flaw["family"] != "list_scope" or not flaw["reachable"] or not flaw["spec_grounded"]:
                continue
            eff = effective_roles(case, truth, flaw, seed)
            m = classify_run(flaw, eff, events, r["diagnosis"][flaw["flaw_id"]]["category"].startswith("found_"), r["grade"].get("end_reason", ""))
            misses.append({"category": m["category"].split(":")[0], "found": m["category"] == "found",
                           "registered_for_needed_role": bool([x for x in m["tested_roles"] if x in m["needed_roles"]])})
    g, L, M = r["grade"], r["llm"], r["metrics"]
    usage = [u for u in (L.get("usage") or []) if u]
    return {"case_id": case_id, "seed": seed, "version": version, "list_scope": misses,
            "recall": g["recall"], "false_positive_units": g["false_positive_units"], "ungrounded_overclaim": len(g["ungrounded_overclaim"]),
            "boundary_violations": g["boundary"]["violations"], "redundant": g["redundant_confirmations"], "requests": g["requests_env"],
            "end_reason": g["end_reason"], "supported": M["supported"], "candidates": M["unverified_deviation"], "refuted": M["refuted"],
            "undetermined": M["undetermined"], "confirmations_planned": M["confirmations_planned"], "confirmations_run": M["confirmations_run"],
            "confirmed_supported": M["confirmed_supported"], "confirmation_not_run": M["confirmation_not_run"],
            "llm_calls": L["calls"], "llm_skipped": L["skipped"], "parse_failures": L["parse_failures"], "salvaged_replies": L["salvaged_replies"],
            "proposals": L["proposals"], "new_registered": L["new_registered"], "input_tokens": sum(u.get("input_tokens", 0) for u in usage),
            "output_tokens": sum(u.get("output_tokens", 0) for u in usage),
            "at_token_cap": sum(1 for u in usage if u.get("output_tokens", 0) >= max_tokens),
            "input_too_large": sum(1 for c in L["calls_detail"] if c.get("reason") == "budget.llm_input_too_large")}


def summarize(runs: list) -> dict:
    n = len(runs)
    fr = [m for r in runs for m in r["list_scope"]]
    s = lambda k: sum(r[k] for r in runs)   # noqa: E731
    recalls = [r["recall"] for r in runs if r["recall"] is not None]
    return {"runs": n, "list_scope_flaw_runs": len(fr), "registered_for_needed_role": sum(1 for m in fr if m["registered_for_needed_role"]),
            "list_scope_found": sum(1 for m in fr if m["found"]),
            "list_scope_miss_classes": _count(m["category"] for m in fr),
            "recall_mean": round(sum(recalls) / len(recalls), 4) if recalls else None,
            "false_positive_units": s("false_positive_units"), "ungrounded_overclaim": s("ungrounded_overclaim"), "boundary_violations": s("boundary_violations"),
            "redundant": s("redundant"), "requests": s("requests"), "end_reasons": _count(r["end_reason"] for r in runs),
            "supported": s("supported"), "candidates": s("candidates"), "refuted": s("refuted"), "undetermined": s("undetermined"),
            "confirmations": {k: s(k) for k in ("confirmations_planned", "confirmations_run", "confirmed_supported", "confirmation_not_run")},
            "llm": {k: s(k) for k in ("llm_calls", "llm_skipped", "parse_failures", "salvaged_replies", "proposals", "new_registered",
                                      "input_tokens", "output_tokens", "at_token_cap", "input_too_large")}}


def _count(it) -> dict:
    d: dict = {}
    for x in it:
        d[x] = d.get(x, 0) + 1
    return d


def decide(a: dict, b: dict, dev_a: dict, dev_b: dict) -> dict:
    """事前登録した採用基準を機械的に当てる。a=/1, b=/2（回帰ケース）、dev_*=開発ケース。"""
    def share(x):
        return x["registered_for_needed_role"] / x["list_scope_flaw_runs"] if x["list_scope_flaw_runs"] else None
    pa, pb = share(a), share(b)
    gain = None if pa is None or pb is None else round(pb - pa, 4)
    calls_a, calls_b = a["llm"]["llm_calls"], b["llm"]["llm_calls"]
    unp = lambda x: (x["llm"]["parse_failures"] / x["llm"]["llm_calls"]) if x["llm"]["llm_calls"] else 0.0   # noqa: E731
    tok_ratio = (b["llm"]["input_tokens"] / a["llm"]["input_tokens"]) if a["llm"]["input_tokens"] else None
    checks = {
        "primary_gain": {"p1_share": pa, "p2_share": pb, "gain": gain, "threshold": CRITERIA["primary_gain_min"],
                         "met": gain is not None and gain >= CRITERIA["primary_gain_min"]},
        "no_safety_regression": {"met": all(b[k] <= a[k] for k in ("false_positive_units", "ungrounded_overclaim", "boundary_violations"))
                                 and all(dev_b[k] <= dev_a[k] for k in ("false_positive_units", "ungrounded_overclaim", "boundary_violations"))},
        "no_input_too_large": {"p2": b["llm"]["input_too_large"] + dev_b["llm"]["input_too_large"], "met": b["llm"]["input_too_large"] + dev_b["llm"]["input_too_large"] == 0},
        "unparsed_rate": {"p1": round(unp(a), 4), "p2": round(unp(b), 4), "met": unp(b) - unp(a) <= CRITERIA["unparsed_rate_increase_max"]},
        "input_token_ratio": {"ratio": None if tok_ratio is None else round(tok_ratio, 3), "met": tok_ratio is not None and tok_ratio <= CRITERIA["input_token_ratio_max"]},
        "dev_recall_not_lower": {"p1": dev_a["recall_mean"], "p2": dev_b["recall_mean"],
                                 "met": (dev_b["recall_mean"] or 0) >= (dev_a["recall_mean"] or 0)},
    }
    return {"criteria": CRITERIA, "checks": checks, "adopt": all(c["met"] for c in checks.values())}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=REGRESSION + "," + DEV)
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--protocol", required=True, help="LLM設定（モデル・max_tokens・推論の強さ）を読むだけ")
    ap.add_argument("--model")
    ap.add_argument("--approve-real-llm", action="store_true")
    ap.add_argument("--max-spend-usd", type=float, required=True)
    ap.add_argument("--records-dir", required=True, help="実行ごとのジャーナル・証拠の保存先（git管理外）。主指標の分類に必要")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not a.approve_real_llm:
        print("実LLMには --approve-real-llm が必要です（未承認のため中止）。", file=sys.stderr)
        return 2
    cfg = json.load(open(a.protocol, encoding="utf-8"))["methods"]["llm"]
    if a.model != cfg["model"]:
        print(f"--model はプロトコルのモデル（{cfg['model']}）と同じにしてください", file=sys.stderr)
        return 2
    from tools.lab_eval import TimedLLM, openrouter_usage
    from tools.research_eval import _Capped
    from tools.research_llm_failures import SpendGuard, model_price
    price = model_price(a.model)
    if price is None:
        print("モデルの単価を取得できないため中止（費用上限を強制できない）。", file=sys.stderr)
        return 2
    u0 = openrouter_usage()
    timed = TimedLLM(a.model)
    llm = _Capped(timed, cfg["max_tokens"], {"reasoning": {"effort": cfg["reasoning_effort"]}})
    guard = SpendGuard(timed, a.max_spend_usd, price[0], price[1], cfg["max_tokens"], cfg["max_llm_calls"])
    cases = a.cases.split(",")
    regression = set(REGRESSION.split(","))
    units = [(c, s, r) for c in cases for s in [int(x) for x in a.seeds.split(",")] for r in range(a.repeats)]
    pairs = []
    for i, (cid, seed, rep) in enumerate(units):
        if not guard.may_start_run(2):                   # 対は両腕とも走らせる（片方だけ走らせない）
            break
        order = ARMS if i % 2 == 0 else ARMS[::-1]
        out = {}
        for v in order:
            out[v] = run_arm(cid, seed, v, llm, cfg["max_tokens"], os.path.join(a.records_dir, f"r{rep}"), cfg["max_llm_calls"])
        pairs.append({"case_id": cid, "seed": seed, "repeat": rep, "order": [x.split("/")[-1] for x in order], "runs": out})
    u1 = openrouter_usage()
    reg = [p for p in pairs if p["case_id"] in regression]
    dev = [p for p in pairs if p["case_id"] not in regression]
    S = {v: summarize([p["runs"][v] for p in reg]) for v in ARMS}
    D = {v: summarize([p["runs"][v] for p in dev]) for v in ARMS}
    doc = {"note": "プロンプト版のA/B（開発・回帰ケース。事前登録: docs §19.3）。回帰ケースは分析に使った in-sample。採用しても未使用ケースでの効果確認ではない。",
           "model": a.model, "settings": {k: cfg[k] for k in ("max_tokens", "reasoning_effort", "max_llm_calls")}, "arms": list(ARMS),
           "pairs_complete": len(pairs), "pairs_planned": len(units), "stopped_by_cap": guard.stopped, "spend_cap_usd": a.max_spend_usd,
           "estimated_spend_usd": round(guard.spent(), 5), "spend_usd": None if u0 is None or u1 is None else round(u1 - u0, 4),
           "regression": S, "dev": D, "decision": decide(S[ARMS[0]], S[ARMS[1]], D[ARMS[0]], D[ARMS[1]]),
           "pairs": [{"case_id": p["case_id"], "seed": p["seed"], "repeat": p["repeat"], "order": p["order"],
                      **{v.split("/")[-1]: {"list_scope": p["runs"][v]["list_scope"], "recall": p["runs"][v]["recall"], "supported": p["runs"][v]["supported"],
                                            "parse_failures": p["runs"][v]["parse_failures"], "input_tokens": p["runs"][v]["input_tokens"]} for v in ARMS}}
                     for p in pairs]}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(json.dumps({k: doc[k] for k in ("pairs_complete", "pairs_planned", "stopped_by_cap", "estimated_spend_usd", "spend_usd", "regression", "dev", "decision")},
                     ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
