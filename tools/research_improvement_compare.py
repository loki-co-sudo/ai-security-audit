"""改善の変更前後の比較（開発・回帰ケース。LLM呼出し0。モック提案とローカル環境の閉ループ）。

変更前の実装は、同じコード上で旧い挙動に差し替えて再現する（①返答の解析＝救済なし ②空の一覧＝正常→棄却）。同じ入力・同じ案件・同じ予算・同じシード。
提案役はモック（実LLMではない）。LLMが変更後の観測に対してどう提案するかは実証しない。
提案役: truncated／late_truncated（出力上限で切れた返答）・good／late（従来のモック）・all_roles（案件の一覧操作×全アカウントを提案する中立なモック。
特定の役割を優先しない。パイプライン（具体化・登録・実験・確認・判定）が提案を受け取れるかを見るための道具で、LLMの代わりではない）。
使い方: .venv/bin/python3 tools/research_improvement_compare.py --out <結果>.json
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy import research_hypothesis as rh  # noqa: E402
from core.autonomy import research_llm as rl  # noqa: E402
from core.autonomy.research_case import load_blind_case  # noqa: E402
from tools.research_eval import CASES_DIR, MockProposer, run_one  # noqa: E402

CASES = ["blind-docs-01", "blind-docs-02", "blind-docs-03", "blind-docs-clean", "unseen-cobalt-17", "unseen-cobalt-42",
         "unseen-cobalt-68", "unseen-amber-23", "unseen-amber-51", "unseen-amber-86"]
KEYS = ["supported", "unverified_deviation", "refuted", "undetermined", "not_examined", "requests_used", "confirmations_planned",
        "confirmation_slots_used", "confirmed_supported"]


class AllRoles:
    """案件の一覧操作(own_list)×全アカウントに list_visibility を提案する中立なモック（観測後の段階だけ。特定の役割を優先しない）。"""

    def __init__(self, case):
        self.ops = [(o.op_id, o.access["clause"]) for o in case.operations.values() if o.method == "GET" and not o.params and o.access["kind"] == "own_list"]
        self.roles = sorted(case.accounts)
        self.calls = 0

    def complete(self, messages, max_tokens=None, usage_out=None):
        self.calls += 1
        if usage_out is not None:
            usage_out.update({"input_tokens": 10, "output_tokens": 10})
        if "まだ無い" in messages[-1]["content"]:
            return json.dumps({"proposals": []})
        props = [{"check": "list_visibility", "op_id": op, "probe_role": r, "basis_clause": cl, "rationale": "mock"} for op, cl in self.ops for r in self.roles]
        return json.dumps({"proposals": props[:rl.MAX_PROPOSALS]})


def legacy_parse(text):
    t = (text or "").strip()
    if not t:
        return None, "empty_reply"
    m = rl._FENCE.search(t)
    if m:
        t = m.group(1).strip()
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j < i:
        k, l_ = t.find("["), t.rfind("]")
        if k < 0 or l_ < k:
            return None, "no_json"
        i, j = k, l_
    try:
        doc = json.loads(t[i:j + 1])
    except ValueError:
        return None, "invalid_json"
    items = doc.get("proposals") if isinstance(doc, dict) else doc
    return (items[:rl.MAX_PROPOSALS], "") if isinstance(items, list) else (None, "proposals_not_a_list")


_new_eval = rh._eval_list_visibility


def legacy_eval(check, res, model):
    if res.status_code == 200 and isinstance(res.json, list) and not [x for x in res.json if isinstance(x, dict)] and res.body_complete \
            and model is not None and check["role"] in model.identity:
        return rh.CONFORMS, "empty_list_visible_only", []
    return _new_eval(check, res, model)


def arm(before: bool):
    """before=True: 変更前の挙動に差し替える。"""
    rl.parse_reply = legacy_parse if before else _NEW_PARSE
    rh._eval_list_visibility = legacy_eval if before else _new_eval


_NEW_PARSE = rl.parse_reply


def run(mode: str, cid: str, seed: int) -> dict:
    case = load_blind_case(os.path.join(CASES_DIR, f"{cid}.json"))
    llm = AllRoles(case) if mode == "all_roles" else MockProposer(mode)
    r = run_one(cid, seed, llm=llm, budget_override={"max_llm_calls": 2})
    m, g = r["metrics"], r["grade"]
    return {**{k: m.get(k) for k in KEYS}, "tp_units": g["true_positive_units"], "recall": g["recall"], "fp": g["false_positive_units"],
            "overclaim": len(g["ungrounded_overclaim"]), "boundary": g["boundary"]["violations"], "end": g["end_reason"] if "end_reason" in g else r["grade"]["end_reason"],
            "parse_failures": r["llm"]["parse_failures"], "salvaged": r["llm"].get("salvaged_replies", 0), "llm_calls": r["llm"]["calls"],
            "new_registered": r["llm"]["new_registered"], "prereg_violations": len(m["prereg_violations"])}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--modes", default="truncated,late_truncated,good,late,all_roles")
    a = ap.parse_args()
    rows = []
    try:
        for mode in a.modes.split(","):
            for cid in CASES:
                for seed in (int(x) for x in a.seeds.split(",")):
                    arm(True)
                    old = run(mode, cid, seed)
                    arm(False)
                    new = run(mode, cid, seed)
                    rows.append({"mode": mode, "case_id": cid, "seed": seed, "before": old, "after": new})
    finally:
        arm(False)
    summ: dict = {}
    for r in rows:
        k = r["mode"]
        s = summ.setdefault(k, {"runs": 0, "changed": 0, "deltas": {}, "safety_violations_after": 0, "requests_changed": 0, "end_changed": 0})
        s["runs"] += 1
        diff = {f: (r["before"][f], r["after"][f]) for f in r["before"] if r["before"][f] != r["after"][f]}
        if diff:
            s["changed"] += 1
        for f, (b, af) in diff.items():
            if isinstance(b, (int, float)) and isinstance(af, (int, float)):
                s["deltas"][f] = round(s["deltas"].get(f, 0) + (af - b), 4)
        s["requests_changed"] += 1 if r["before"]["requests_used"] != r["after"]["requests_used"] else 0
        s["end_changed"] += 1 if r["before"]["end"] != r["after"]["end"] else 0
        s["safety_violations_after"] += r["after"]["fp"] + r["after"]["overclaim"] + r["after"]["boundary"] + r["after"]["prereg_violations"]
    out = {"note": "モック提案・ローカル環境・LLM呼出し0。変更前＝旧い挙動に差し替え。LLMの実挙動は実証しない。",
           "cases": CASES, "seeds": a.seeds, "summary": summ, "rows": rows}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(json.dumps(summ, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
