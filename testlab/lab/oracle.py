"""案件が方式間の差を出せる設計かを、正解ファイルと環境の応答だけから検査する(評価側の道具・ワークフローは使わない戦略)。

各テストを1回ずつ全件実行して「どのテストが逸脱するか」を確定し、予算内で到達できる範囲を数える。
  best    予算内で見つけられる不備数の上限(解除条件の祖先も予算に含めて最適に選んだ場合)
  random  順序ランダム(fixed_random相当・解除条件は無視)の期待値(予算分の部分集合を全列挙)
  worst   予算内で見つかる不備数の下限
best == worst の案件は方式間の差を示せない。**戦略を走らせる前**に確認するための検査で、結果は戦略へ戻さない。
"""
from __future__ import annotations
import itertools
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from core.autonomy import lab_workflow as lw  # noqa: E402
from core.autonomy.lab_case import load_case  # noqa: E402
from testlab.lab import grader  # noqa: E402
from testlab.lab.apps import APPS  # noqa: E402

CASES = os.path.join(ROOT, "testlab", "lab", "cases")


def outcomes(case) -> dict:
    tmp = tempfile.mkdtemp(prefix="oracle_")
    with APPS[case.case_id]() as app:
        with grader.sealed():
            res = lw.run_lab_case(case, app.base_url, app.credentials(), strategy="fixed",
                                  journal_root=os.path.join(tmp, "runs"), evidence_root=os.path.join(tmp, "ev"),
                                  budget_override={"max_requests": len(case.tests), "max_llm_calls": 0})
    return {tid: t["outcome"] for tid, t in res.to_dict()["tests"].items()}


def _ancestors(case, tid) -> set:
    out, cur = set(), case.tests[tid]
    while cur.unlocked_by:
        out.add(cur.unlocked_by["test_id"])
        cur = case.tests[cur.unlocked_by["test_id"]]
    return out


def analyze(case_id: str) -> dict:
    case = load_case(os.path.join(CASES, case_id + ".json"))
    truth = grader.load_truth(case_id)
    out = outcomes(case)
    budget = int(case.budget["max_requests"])
    flaws = {f["hypothesis_id"] for f in truth["flaws"] if f.get("reachable", True)}
    non = {f["hypothesis_id"] for f in truth["non_flaws"]}
    dev = {h: {t.test_id for t in case.tests.values() if t.hypothesis == h and t.kind == "probe" and out[t.test_id] == "deviates"}
           for h in case.hypotheses}
    found = lambda S: {h for h in flaws if dev[h] & S}                       # noqa: E731
    ids = list(case.tests)
    # random: 全部分集合(解除条件を無視)
    counts = [len(found(set(S))) for S in itertools.combinations(ids, min(budget, len(ids)))]
    # best: 各不備の最小実行集合(逸脱テスト+祖先)を最適に組合せる
    best = 0
    for k in range(len(flaws) + 1):
        for hs in itertools.combinations(sorted(flaws), k):
            need = set()
            ok = True
            for h in hs:
                opts = [{t} | _ancestors(case, t) for t in dev[h]]
                if not opts:
                    ok = False
                    break
                need |= min(opts, key=len)
            if ok and len(need) <= budget:
                best = max(best, k)
    chains = [set(c["members"]) for c in truth.get("chains", [])]
    chain_found = lambda S: sum(1 for m in chains if all(dev[h] & S for h in m))      # noqa: E731
    subsets = [set(S) for S in itertools.combinations(ids, min(budget, len(ids)))]
    closed = [S for S in subsets if all(_ancestors(case, t) <= S for t in S)]
    ch = {} if not chains else {
        "chains_expected": len(chains), "chains_best": max(chain_found(S) for S in closed),
        "chains_worst": min(chain_found(S) for S in subsets),
        "chains_random_expected": round(sum(chain_found(S) for S in subsets) / len(subsets), 3)}
    return {**ch, "case_id": case_id, "split": case.split, "tests": len(ids), "budget": budget,
            "reachable_flaws": len(flaws), "findable_by_some_probe": sorted(h for h in flaws if dev[h]),
            "never_deviates": sorted(h for h in flaws if not dev[h]),
            "potential_false_positives": sorted(h for h in non if dev[h]),
            "best": best, "worst": min(counts), "random_expected": round(sum(counts) / len(counts), 3),
            "can_discriminate": best != min(counts)}


if __name__ == "__main__":
    ids = sys.argv[1:] or sorted(f[:-5] for f in os.listdir(CASES) if f.endswith(".json") and "holdout" not in f)  # 保留は明示指定のみ
    print(json.dumps([analyze(c) for c in ids], ensure_ascii=False, indent=1))
