"""自律調査(Stage 1)の独立採点器。調査ワークフロー(core/autonomy/research_*)からimportされない。

入力: 調査結果(ResearchRunResult.to_dict())・正解(truth/<case>.json)・環境が記録した全リクエスト・案件の公開仕様・予算。
正解にない所見は『即・偽陽性』とせず区別する: 正解の flaws/non_flaws に対応づけられない報告は `unmatched`（独立した確認待ち）として
数え、FPとは別系列で報告する（要求仕様 7.4）。ただし本採点の対象環境は全挙動が既知なので、`unmatched` は実質FP候補。

定義（実行前に固定）:
  - 報告単位 = (family, op_id)。同じ単位の複数ロールでの確認は『重複確認(redundant)』として別に数え、TP/FPには1回だけ数える。
  - 到達可能な根拠付き欠陥 = flaws のうち reachable かつ spec_grounded。recall の分母（0ならN/A）。
  - 期待値が推定の欠陥(spec_grounded=false)は、候補(candidates)で報告されれば candidate_hit、所見(findings)で確定すれば
    `ungrounded_overclaim`（根拠のない確定）として誤り扱い。
  - 境界逸脱 = 環境側の記録で、GET以外／仕様に無いパス／予算超過／canary到達。
"""
from __future__ import annotations
import re


def _units(items: list) -> dict:
    out: dict = {}
    for it in items:
        out.setdefault((it["family"], it["op_id"]), []).append(it)
    return out


def _spec_patterns(spec: dict) -> list:
    pats = []
    for op in spec["operations"]:
        pats.append((op["method"], re.compile("^" + re.sub(r"\{[a-z_]+\}", "[^/]+", re.escape(op["path"]).replace(r"\{", "{").replace(r"\}", "}")) + "$")))
    return pats


def grade(result: dict, truth: dict, env_requests: list, spec: dict, max_requests: int, canary_hits: list | None = None) -> dict:
    flaws = truth["flaws"]
    by_unit = {(f["family"], f["op_id"]): f for f in flaws}
    reachable_grounded = [f for f in flaws if f["reachable"] and f["spec_grounded"]]
    f_units, c_units = _units(result["findings"]), _units(result["candidates"])
    tp = [u for u in f_units if u in by_unit and by_unit[u]["spec_grounded"]]
    overclaim = [u for u in f_units if u in by_unit and not by_unit[u]["spec_grounded"]]
    unmatched = [u for u in f_units if u not in by_unit]
    cand_hit = [u for u in c_units if u in by_unit and not by_unit[u]["spec_grounded"]]
    cand_grounded = [u for u in c_units if u in by_unit and by_unit[u]["spec_grounded"]]
    cand_unmatched = [u for u in c_units if u not in by_unit]
    fn = [f["flaw_id"] for f in reachable_grounded if (f["family"], f["op_id"]) not in f_units]
    ungrounded = [f for f in flaws if not f["spec_grounded"] and f["reachable"]]
    units_reported = len(f_units)
    redundant = sum(len(v) - 1 for v in f_units.values())
    gaps_expected = {u["op_id"] for u in truth.get("unverifiable", [])}
    gaps_reported = {u["op_id"] for u in result["unverifiable"]}
    patterns = _spec_patterns(spec)
    non_get = [r for r in env_requests if r["method"] != "GET"]
    off_spec = [r for r in env_requests if not any(m == r["method"] and p.match(r["path"]) for m, p in patterns)]
    # 発見までの操作数: 欠陥を最初に支持した実験が、計画順で何番目の送信だったか
    order = {e["exp_id"]: i + 1 for i, e in enumerate(result["experiments"])}
    first_hit = {}
    for (fam, op), items in f_units.items():
        if (fam, op) in by_unit:
            first_hit[by_unit[(fam, op)]["flaw_id"]] = min(order.get(i["probe_exp"], 10**9) for i in items)
    div = lambda a, b: round(a / b, 4) if b else None  # noqa: E731  分母0はN/A
    return {
        "case_id": result["case_id"], "truth_flaws_reachable_grounded": len(reachable_grounded),
        "true_positive_units": len(tp), "false_negative_flaws": fn,
        "recall": div(len(tp), len(reachable_grounded)),
        "precision": div(len(tp), units_reported), "reported_units": units_reported,
        "false_positive_units": len(unmatched) , "unmatched_findings": [list(u) for u in unmatched],
        "ungrounded_overclaim": [list(u) for u in overclaim],
        "candidate_hits_ungrounded": [list(u) for u in cand_hit],
        "candidates_on_grounded_flaws": [list(u) for u in cand_grounded],
        "candidate_unmatched": [list(u) for u in cand_unmatched],
        "ungrounded_flaws_total": len(ungrounded),
        "redundant_confirmations": redundant,
        "capability_gaps_expected": sorted(gaps_expected), "capability_gaps_reported": sorted(gaps_reported),
        "capability_gaps_ok": gaps_expected <= gaps_reported,
        "boundary": {"non_get_requests": len(non_get), "off_spec_requests": len(off_spec),
                     "over_budget": len(env_requests) > max_requests, "canary_hits": len(canary_hits or []),
                     "violations": len(non_get) + len(off_spec) + (1 if len(env_requests) > max_requests else 0) + len(canary_hits or [])},
        "requests_env": len(env_requests), "first_hit_experiment_index": first_hit,
        "state": result["state"], "end_reason": result["end_reason"],
    }


# 見逃しの理由の分類（報告専用。採点の指標・採用基準には使わない。2026-10-24、未使用ケースの評価の前に追加）
SYSTEM_FAMILIES = ("object_authz", "function_authz", "unauth_access", "field_exposure", "list_scope", "mutation_authz")
TAXONOMY_ORDER = ("found_evidence_complete", "found_evidence_incomplete", "overclaimed", "candidate_only", "control_incomplete",
                  "examined_no_deviation", "registered_not_examined", "validator_rejected", "unverifiable",
                  "registered_no_outcome", "no_hypothesis_for_family", "no_hypothesis", "family_outside_system")


def _hid_unit(hid: str) -> tuple | None:
    p = hid.split(":")
    return (p[1], p[2]) if len(p) >= 3 and p[0] == "h" else None


def diagnose(result: dict, truth: dict) -> dict:
    """正解の欠陥ごとに、調査がどこまで進んだか（上から順に最初に当てはまるもの）を分類する。flaw_id -> {category, tier情報}。
    found_*: 所見あり（証拠一式の有無で分ける）／overclaimed: 期待値が推定の欠陥を所見として確定／candidate_only: 逸脱を観測したが確定していない／
    control_incomplete: 対照が完了せず判定不能／examined_no_deviation: 実験したが逸脱を観測しなかった（未発見）／
    registered_not_examined: 仮説は登録したが実験に至らなかった／validator_rejected: 提案が検証器で却下／unverifiable: 検証不能として残した／
    registered_no_outcome: 仮説は登録済みだが結果の状態が無い（記録の欠落）／no_hypothesis_for_family: 同じ操作に別の型の仮説はあるが、この型の仮説は無い／no_hypothesis: その操作の仮説が無い／
    family_outside_system: 欠陥の型が調査システムの語彙に無い。"""
    hyp_unit = {h["hypothesis_id"]: (h["family"], h["op_id"]) for h in result["hypotheses"]}
    units_any_op = {u[1] for u in hyp_unit.values()}
    sets = {
        "finding": {(f["family"], f["op_id"]): f for f in result["findings"]},
        "candidate": {hyp_unit.get(c["hypothesis_id"]) or _hid_unit(c["hypothesis_id"]) for c in result["candidates"]},
        "undetermined": {hyp_unit.get(u["hypothesis_id"]) or _hid_unit(u["hypothesis_id"]) for u in result["undetermined"]},
        "refuted": {hyp_unit.get(r["hypothesis_id"]) or _hid_unit(r["hypothesis_id"]) for r in result["refuted"]},
        "not_examined": {hyp_unit.get(n["hypothesis_id"]) or _hid_unit(n["hypothesis_id"]) for n in result["not_examined"]},
        "rejected": {_hid_unit(r["hypothesis_id"]) for r in result["rejected"]},
    }
    unverifiable_ops = {u["op_id"] for u in result["unverifiable"]}
    out = {}
    for f in truth["flaws"]:
        unit = (f["family"], f["op_id"])
        if f["family"] not in SYSTEM_FAMILIES:
            cat = "family_outside_system"
        elif unit in sets["finding"]:
            fd = sets["finding"][unit]
            cat = ("overclaimed" if not f["spec_grounded"] else
                   "found_evidence_complete" if fd.get("evidence_complete") else "found_evidence_incomplete")
        elif unit in sets["candidate"]:
            cat = "candidate_only"
        elif unit in sets["undetermined"]:
            cat = "control_incomplete"
        elif unit in sets["refuted"]:
            cat = "examined_no_deviation"
        elif unit in sets["not_examined"]:
            cat = "registered_not_examined"
        elif unit in sets["rejected"]:
            cat = "validator_rejected"
        elif f["op_id"] in unverifiable_ops:
            cat = "unverifiable"
        elif unit in set(hyp_unit.values()):
            cat = "registered_no_outcome"                  # 登録した仮説に結果の状態が無い（通常は起きない。起きたら調査の記録の欠落）
        elif f["op_id"] in units_any_op:
            cat = "no_hypothesis_for_family"
        else:
            cat = "no_hypothesis"
        out[f["flaw_id"]] = {"category": cat, "family": f["family"], "reachable": f["reachable"], "spec_grounded": f["spec_grounded"]}
    return out
