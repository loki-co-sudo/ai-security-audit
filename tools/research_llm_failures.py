"""LLM方式の失敗箇所の事後分析（採用基準・採点には使わない。正解の欠陥ごとに『どこで止まったか』を分類する）。

実行ごとのジャーナル（llm_proposals イベント）と結果から、正解の欠陥1件×1実行を次のどれかに入れる（上から最初に当てはまるもの）:
  仮説が存在した場合（diagnose と同じ分類）: found_* / candidate_only / control_incomplete / examined_no_deviation / registered_not_examined / unverifiable
  仮説が存在しなかった場合:
    llm_not_used                  LLMを使わない実行
    llm_budget_denied             LLM呼出が予算で拒否された
    llm_call_failed               呼出が例外で失敗した
    llm_reply_unparsed            返答を解析できなかった（理由コードは別集計。トークン上限到達の数も別に数える）
    llm_no_proposal_for_op        返答は解析できたが、その操作についての提案が無かった
    llm_proposed_other_check_only その操作の提案はあるが、欠陥の型に合わない検査型だけだった
    rejected_at_concretization    提案が仮説の具体化（build_list_scope/規則との照合）で却下された（理由コードは別集計）
    rejected_by_validator         具体化は通ったが、検証器（有効な仮説の定義）で却下された
    family_outside_system         欠陥の型が調査システムの語彙に無い
『LLMの提案能力』と『提案を受け取るパイプラインの能力』は別。後者は tools/research_proposal_oracle.py（LLM不要）で分ける。
正解ファイルは分類にだけ使い、出力には操作名・欠陥IDを含めない（型×分類の件数のみ）。
事後分析で、評価済みの実行の分解ではなく新しいサンプル。LLMの呼出は凍結プロトコル(r2)と同じ設定。

使い方: .venv/bin/python3 tools/research_llm_failures.py --cases a,b --seeds 0,1,2 --repeats 2 --protocol <frozen.json> --model z-ai/glm-5.3-flash --approve-real-llm --out f.json
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from testlab.lab.blind_grader import diagnose  # noqa: E402

CHECK_FAMILIES = {"list_visibility": {"list_scope"}, "fields_subset": {"field_exposure"},
                  "deny_expected": {"object_authz", "function_authz", "unauth_access", "mutation_authz"}}
HYPOTHESIS_EXISTS = {"found_evidence_complete", "found_evidence_incomplete", "overclaimed", "candidate_only", "control_incomplete",
                     "examined_no_deviation", "registered_not_examined", "unverifiable", "registered_no_outcome"}


def llm_summary(events: list) -> dict:
    """ジャーナルの llm_proposals イベントを、呼出単位に要約する。"""
    calls = []
    for e in events:
        if e.get("type") != "llm_proposals":
            continue
        if e.get("skipped"):
            calls.append({"outcome": "budget_denied", "reason": e.get("reason", "")})
        elif e.get("error"):
            calls.append({"outcome": "call_failed", "reason": e["error"]})
        elif e.get("parse_error"):
            calls.append({"outcome": "unparsed", "reason": e["parse_error"]})
        else:
            calls.append({"outcome": "parsed", "results": list(e.get("results") or [])})
    return {"calls": calls}


def classify(result: dict, events: list, truth: dict, *, llm_enabled: bool = True) -> dict:
    """flaw_id -> {category, detail, family}。detail は理由コード（なければ空）。"""
    base = diagnose(result, truth)
    calls = llm_summary(events)["calls"]
    out = {}
    for f in truth["flaws"]:
        d = base[f["flaw_id"]]
        cat, detail = d["category"], ""
        if cat in ("candidate_only", "control_incomplete"):                  # 仮説はあるが確定しなかった理由コード（例: probe_preexisting）
            pool = result["candidates"] if cat == "candidate_only" else result["undetermined"]
            hid = next((h["hypothesis_id"] for h in result["hypotheses"] if (h["family"], h["op_id"]) == (f["family"], f["op_id"])
                        and any(x["hypothesis_id"] == h["hypothesis_id"] for x in pool)), None)
            detail = next((str(x.get("reason", ""))[:60] for x in pool if x["hypothesis_id"] == hid), "")
        if cat in HYPOTHESIS_EXISTS or cat == "family_outside_system":
            out[f["flaw_id"]] = {"category": cat, "detail": detail, "family": f["family"], "reachable": f["reachable"], "spec_grounded": f["spec_grounded"]}
            continue
        if not llm_enabled or not calls:
            cat = "llm_not_used"
        elif all(c["outcome"] == "budget_denied" for c in calls):
            cat = "llm_budget_denied"
        else:
            parsed = [c for c in calls if c["outcome"] == "parsed"]
            if not parsed:
                bad = [c for c in calls if c["outcome"] in ("unparsed", "call_failed")]
                cat = "llm_call_failed" if all(c["outcome"] == "call_failed" for c in bad) else "llm_reply_unparsed"
                detail = bad[0]["reason"] if bad else ""
            else:
                about = [r for c in parsed for r in c["results"] if r.get("op_id") == f["op_id"]]
                fits = [r for r in about if f["family"] in CHECK_FAMILIES.get(r.get("check"), set())]
                if not about:
                    cat = "llm_no_proposal_for_op"
                    # 同じ実行に解析失敗の呼出しがあれば区別する（提案しなかったのか、解析失敗で提案を失った可能性があるのか）
                    detail = "with_unparsed_call" if any(c["outcome"] == "unparsed" for c in calls) else ""
                elif not fits:
                    cat = "llm_proposed_other_check_only"
                else:
                    rej = [r for r in fits if r.get("status") == "rejected"]
                    r0 = rej[0] if rej else fits[0]
                    reason = r0.get("reason", "")
                    cat = "rejected_by_validator" if reason.startswith("validator:") else "rejected_at_concretization"
                    detail = reason[:60]
        out[f["flaw_id"]] = {"category": cat, "detail": detail, "family": f["family"], "reachable": f["reachable"],
                             "spec_grounded": f["spec_grounded"]}
    return out


def aggregate(rows: list) -> dict:
    """rows: 実行ごとの {case_id, classes, llm}。型×分類の件数と、LLM呼出の内訳（操作名・欠陥IDは含めない）。"""
    cats: dict = {}
    reasons: dict = {}
    calls = {"runs": 0, "calls": 0, "budget_denied": 0, "call_failed": 0, "unparsed": 0, "unparsed_reasons": {},
             "at_token_cap": 0, "proposals": 0, "new_registered": 0, "rejected_reasons": {}}
    for r in rows:
        for fid, c in r["classes"].items():
            if not c["reachable"]:
                continue
            cell = cats.setdefault(r["case_id"], {}).setdefault(c["family"] if c["spec_grounded"] else "ungrounded:" + c["family"], {})
            cell[c["category"]] = cell.get(c["category"], 0) + 1
            if c["detail"]:
                key = f"{c['category']}:{c['detail']}"
                reasons[key] = reasons.get(key, 0) + 1
        L = r["llm"]
        calls["runs"] += 1
        for c in L["calls"]:
            calls["calls"] += 1
            if c["outcome"] in ("budget_denied", "call_failed", "unparsed"):
                calls[c["outcome"]] += 1
            if c["outcome"] == "unparsed":
                calls["unparsed_reasons"][c["reason"]] = calls["unparsed_reasons"].get(c["reason"], 0) + 1
        calls["at_token_cap"] += L["at_token_cap"]
        calls["proposals"] += L["proposals"]
        calls["new_registered"] += L["new_registered"]
        for k, v in L["rejected"].items():
            calls["rejected_reasons"][k] = calls["rejected_reasons"].get(k, 0) + v
    return {"by_case_family": cats, "reasons": reasons, "llm_calls": calls}


def run_samples(cases: list, seeds: list, repeats: int, llm, max_tokens: int, max_llm_calls: int = 2) -> list:
    from core.autonomy.journal import replay
    from core.autonomy.research_case import load_blind_case
    from core.autonomy.research_loop import run_research_case
    from testlab.lab.apps import CanaryServer
    from tools.research_eval import CASES_DIR, TRUTH_DIR, make_app
    rows = []
    for cid in cases:
        case = load_blind_case(os.path.join(CASES_DIR, f"{cid}.json"))
        with open(os.path.join(TRUTH_DIR, f"{cid}.json"), encoding="utf-8") as f:
            truth = json.load(f)
        for seed in seeds:
            for rep in range(repeats):
                canary = CanaryServer().start()
                try:
                    with tempfile.TemporaryDirectory() as td, make_app(truth, canary, seed) as app:
                        res = run_research_case(case, app.base_url, app.credentials(), journal_root=td + "/j", evidence_root=td + "/e",
                                                budget_override={"max_llm_calls": max_llm_calls}, llm=llm).to_dict()
                        events = replay(res["run_id"], td + "/j").events
                finally:
                    canary.stop()
                usage = [u for u in (res["llm"].get("usage") or []) if u]
                rows.append({"case_id": cid, "seed": seed, "repeat": rep, "classes": classify(res, events, truth),
                             "llm": {"calls": llm_summary(events)["calls"],
                                     "at_token_cap": sum(1 for u in usage if u.get("output_tokens", 0) >= max_tokens),
                                     "proposals": res["llm"]["proposals"], "new_registered": res["llm"]["new_registered"],
                                     "rejected": res["llm"]["rejected"]}})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--protocol", required=True, help="LLM設定（モデル・max_tokens・推論の強さ）を読むだけ。凍結の検証はしない")
    ap.add_argument("--model")
    ap.add_argument("--approve-real-llm", action="store_true")
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
    u0 = openrouter_usage()
    llm = _Capped(TimedLLM(a.model), cfg["max_tokens"], {"reasoning": {"effort": cfg["reasoning_effort"]}})
    rows = run_samples(a.cases.split(","), [int(x) for x in a.seeds.split(",")], a.repeats, llm, cfg["max_tokens"], cfg["max_llm_calls"])
    u1 = openrouter_usage()
    doc = {"note": "事後分析（新しいサンプル。評価済みの実行の分解ではない）。採用基準・採点には使わない。", "model": a.model,
           "settings": {k: cfg[k] for k in ("max_tokens", "reasoning_effort", "max_llm_calls", "prompt_version")},
           "n_runs": len(rows), "spend_usd": None if u0 is None or u1 is None else round(u1 - u0, 4),
           "aggregate": aggregate(rows)}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(json.dumps(doc, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
