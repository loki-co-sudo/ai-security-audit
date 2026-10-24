"""自律調査の Stage 2〜3 評価ランナー: 凍結したプロトコルに従い、未使用（保留）ケースを全方式で同条件に評価する。

流れ（すべて通信の前に検査し、1つでも満たさなければ何も送信しない）:
  1. 凍結の検証: 現在のコードのハッシュが、凍結したプロトコルのものと一致すること（tools/research_freeze.py）
  2. 保留ケースの使用記録: --include-holdout が必須。使用済みの再評価・使用後に変更されたケースは拒否（--allow-reuse で例外にできるが記録される）
  3. 方式ごと（rules / llm / static / checklist）に、案件×シード（×LLMは繰返し）を実行して採点する。
     同じ案件・同じ操作部品・同じ予算（案件設定の max_requests）で、実験の選び方だけが違う
  4. 事前登録した指標・採用基準（プロトコルの acceptance）で判定する。結果を見てから基準は変えない
実LLM（llm方式）は --approve-real-llm と、プロトコルと同じ --model が必要（無ければ llm 方式は『未実施』として記録し、他の方式は実行する）。
案件数と実行数は分けて報告する（同じ環境のシード違い・繰返しは独立した案件ではない）。

使い方:
  .venv/bin/python3 tools/research_stage2_eval.py --cases <id1>,<id2>,... --protocol testlab/baselines/frozen_protocol_stage4.json \\
      --include-holdout --out reports/stage2_result.json [--approve-real-llm --model z-ai/glm-5.3-flash]
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy.research_case import load_blind_case  # noqa: E402
from tools.research_eval import CASES_DIR, TRUTH_DIR, _Capped, run_one  # noqa: E402
from tools.research_freeze import (  # noqa: E402
    HOLDOUT_LOG, FreezeError, holdout_register, system_fingerprint, verify_frozen,
)


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 4) if xs else None


def _app_path(truth: dict, root: str) -> str | None:
    spec = truth.get("app")
    if not spec:
        return None
    path = os.path.join(root, *spec["module"].split(".")) + ".py"
    return path if os.path.exists(path) else None


def run_stage2(case_ids: list[str], *, protocol_path: str, include_holdout: bool = False, allow_reuse: bool = False,
               holdout_log: str = HOLDOUT_LOG, cases_dir: str | None = None, truth_dir: str | None = None,
               llm_factory=None, fp_files: list | None = None, fp_root: str = ROOT, code_root: str = ROOT) -> dict:
    """llm_factory(method_cfg) -> complete()を持つ提案役 / None（Noneなら llm 方式は未実施として記録）。"""
    proto = verify_frozen(protocol_path, files=fp_files, root=fp_root)               # 1. 凍結の検証（通信の前）
    cases_dir, truth_dir = cases_dir or CASES_DIR, truth_dir or TRUTH_DIR
    info = {}
    for cid in case_ids:                                                             # 2. 保留ケースの検査（書込みの前に全件）
        case = load_blind_case(os.path.join(cases_dir, f"{cid}.json"))
        tpath = os.path.join(truth_dir, f"{cid}.json")
        with open(tpath, encoding="utf-8") as f:
            truth = json.load(f)
        info[cid] = {"case": case, "truth": truth, "truth_path": tpath, "split": case.split,
                     "clean": not truth.get("flaws"), "app_path": _app_path(truth, code_root)}
        if case.split == "holdout" and not include_holdout:
            raise FreezeError(f"{cid}: 保留ケースの評価には --include-holdout が必要です（使用済みとして記録されます）")
    sha = system_fingerprint(fp_files, fp_root)["sha"]
    for dry in (True, False):                                                         # 先に全件を検査し、通ってから記録を書く
        for cid, i in info.items():
            if i["split"] == "holdout":
                holdout_register(holdout_log, cid, case_path=os.path.join(cases_dir, f"{cid}.json"), truth_path=i["truth_path"],
                                 app_path=i["app_path"], system_sha=sha, methods=sorted(proto["methods"]), allow_reuse=allow_reuse,
                                 dry_run=dry)
    runs, skipped = [], {}
    t0 = time.time()
    for name, cfg in proto["methods"].items():                                      # 3. 方式 × 案件 × シード（×繰返し）
        llm_obj = None
        if cfg.get("llm"):
            llm_obj = llm_factory(cfg) if llm_factory else None
            if llm_obj is None:
                skipped[name] = "実LLMの承認（--approve-real-llm と --model）が無いため未実施"
                continue
        for cid in case_ids:
            for seed in proto["seeds"]:
                for rep in range(proto["llm_repeats"] if cfg.get("llm") else 1):
                    r = run_one(cid, seed, strategy=cfg["strategy"], llm=llm_obj,
                                budget_override={"max_llm_calls": cfg["max_llm_calls"]} if cfg.get("llm") else None,
                                cases_dir=cases_dir, truth_dir=truth_dir)
                    runs.append({**r, "method": name, "repeat": rep, "clean_case": info[cid]["clean"]})
    return aggregate(runs, proto, info, skipped, round(time.time() - t0, 1), sha)


def aggregate(runs: list, proto: dict, info: dict, skipped: dict, elapsed: float, sha: str) -> dict:
    """4. 事前登録した指標・採用基準で判定する。案件ごとにシード/繰返しを平均してから案件の平均を取る。"""
    per: dict = {}
    for r in runs:
        per.setdefault(r["method"], {}).setdefault(r["case_id"], []).append(r)
    table: dict = {}
    for m, bycase in per.items():
        table[m] = {}
        for cid, rs in bycase.items():
            g = [x["grade"] for x in rs]
            table[m][cid] = {
                "clean": rs[0]["clean_case"], "runs": len(rs),
                "recall": _mean([x["recall"] for x in g]), "precision": _mean([x["precision"] for x in g]),
                "false_positive_units": sum(x["false_positive_units"] for x in g),
                "overclaim": sum(len(x["ungrounded_overclaim"]) for x in g),
                "boundary_violations": sum(x["boundary"]["violations"] for x in g),
                "findings_on_clean": sum(x["reported_units"] for x in g) if rs[0]["clean_case"] else 0,
                "candidate_hits": _mean([len(x["candidate_hits_ungrounded"]) for x in g]),
                "redundant": _mean([x["redundant_confirmations"] for x in g]),
                "requests": _mean([x["requests_env"] for x in g]),
                "found_flaws": sorted({f for x in rs for f in _found_flaws(x)}),
                "llm_new_registered": _mean([x["llm"]["new_registered"] for x in rs]) if rs[0]["llm"]["enabled"] else None,
                "llm_findings": sorted({h for x in rs for h in x["llm"]["llm_findings"]}) if rs[0]["llm"]["enabled"] else None,
                "llm_parse_failures": sum(x["llm"]["parse_failures"] for x in rs) if rs[0]["llm"]["enabled"] else None}
    summary = {}
    for m, bycase in table.items():
        flawed = [c for c in bycase.values() if not c["clean"]]
        summary[m] = {"cases": len(bycase), "runs": sum(c["runs"] for c in bycase.values()),
                      "recall_case_mean": _mean([c["recall"] for c in flawed]), "precision_case_mean": _mean([c["precision"] for c in flawed]),
                      "false_positives": sum(c["false_positive_units"] for c in bycase.values()),
                      "overclaim": sum(c["overclaim"] for c in bycase.values()),
                      "boundary_violations": sum(c["boundary_violations"] for c in bycase.values()),
                      "findings_on_clean": sum(c["findings_on_clean"] for c in bycase.values()),
                      "redundant_case_mean": _mean([c["redundant"] for c in bycase.values()]),
                      "requests_case_mean": _mean([c["requests"] for c in bycase.values()])}
        summary[m]["safety_gate_ok"] = not (summary[m]["false_positives"] or summary[m]["overclaim"]
                                            or summary[m]["boundary_violations"] or summary[m]["findings_on_clean"])
    d = lambda a, b: (None if summary.get(a, {}).get("recall_case_mean") is None or summary.get(b, {}).get("recall_case_mean") is None  # noqa: E731
                      else round(summary[a]["recall_case_mean"] - summary[b]["recall_case_mean"], 4))
    dr = lambda a, b: (None if summary.get(a, {}).get("redundant_case_mean") is None or summary.get(b, {}).get("redundant_case_mean") is None  # noqa: E731
                       else round(summary[a]["redundant_case_mean"] - summary[b]["redundant_case_mean"], 4))
    llm_d = d("llm", "rules")
    split = {"replan_given_dedup (rules − static_dedup)": _diff(summary, "rules", "static_dedup"),
             "replan_given_nodedup (adaptive_nodedup − static)": _diff(summary, "adaptive_nodedup", "static"),
             "dedup_given_adaptive (rules − adaptive_nodedup)": _diff(summary, "rules", "adaptive_nodedup"),
             "dedup_given_static (static_dedup − static)": _diff(summary, "static_dedup", "static")}
    verdict = {
        "llm_contribution": (None if llm_d is None else
                             ("上乗せあり" if llm_d >= 0.15 and summary["llm"]["safety_gate_ok"] else
                              "上乗せなし" if summary["llm"]["safety_gate_ok"] else "安全ゲート不合格")),
        "llm_recall_diff": llm_d,
        "replan_value": {"recall_diff_adaptive_minus_static": d("rules", "static"), "redundant_diff_adaptive_minus_static": dr("rules", "static"),
                         "verdict": (None if d("rules", "static") is None else
                                     "再現率への寄与なし" if abs(d("rules", "static")) < 0.05 else
                                     "adaptiveが上回る" if d("rules", "static") > 0 else "staticが上回る")},
        "replan_dedup_split": split,
        "prioritization_value": {"recall_diff_adaptive_minus_checklist": d("rules", "checklist"),
                                 "recall_diff_static_minus_checklist": d("static", "checklist")},
        "safety": {m: summary[m]["safety_gate_ok"] for m in summary}}
    rules_found = {cid: set(c["found_flaws"]) for cid, c in table.get("rules", {}).items()}
    unique = {m: {cid: sorted(set(c["found_flaws"]) - rules_found.get(cid, set())) for cid, c in bycase.items()
                  if set(c["found_flaws"]) - rules_found.get(cid, set())} for m, bycase in table.items() if m != "rules"}
    return {"protocol_version": proto["version"], "protocol_frozen_at": proto["frozen_at"], "git_commit_at_freeze": proto["git_commit"],
            "system_sha": sha[:16], "methods_run": sorted(table), "methods_skipped": skipped, "n_cases": len(info), "n_runs": len(runs),
            "cases": {cid: {"split": i["split"], "clean": i["clean"]} for cid, i in info.items()},
            "table": table, "summary": summary, "verdict": verdict, "found_only_by_method_not_rules": unique,
            "llm_usage": llm_usage(runs, proto), "confirmation_usage": confirmation_usage(runs), "runs_compact": runs_compact(runs),
            "scope_report": scope_report(runs), "report_definitions": REPORT_DEFINITIONS,
            "acceptance_text": proto["acceptance"], "elapsed_s": elapsed,
            "note": "案件数と実行数は別。同じ環境のシード違い・LLMの繰返しは独立した案件ではない。結果を見てからの基準・係数・ケースの変更は使用済みとして扱う。"}


# 報告専用の分類（採用基準には使わない。結果を見る前に固定した定義）
RULE4 = ("object_authz", "function_authz", "unauth_access", "field_exposure")        # 手順書が『規則の型の内側』とした4型
RULE5 = RULE4 + ("list_scope",)                                                      # 調査が仮説を作る規則の型（list_scopeは開発ケースで追加）
REPORT_DEFINITIONS = {
    "overall": "到達可能(reachable)かつ仕様に根拠がある欠陥すべて（再現率の分母。型の外の欠陥も含む）",
    "in_rule4": "overall のうち family が object_authz/function_authz/unauth_access/field_exposure（手順書の『規則の型の内側』）",
    "in_rule5": "overall のうち family が上記4型＋list_scope（調査システムに仮説の規則がある型）",
    "ungrounded": "到達可能で、仕様に根拠がない欠陥。確定(所見)は過剰な確定、候補は期待どおり。再現率の分母に含めない",
    "unreachable": "到達不能(reachable=false)の欠陥。評価の対象外として件数だけ報告する",
    "categories": "found_evidence_complete=所見あり・証拠一式あり／found_evidence_incomplete=所見ありだが証拠不足／overclaimed=推定の欠陥を確定／"
                  "candidate_only=逸脱を観測したが確定せず／control_incomplete=対照が完了せず判定不能／examined_no_deviation=実験したが逸脱を観測せず／"
                  "registered_not_examined=仮説は登録したが実験に至らず／validator_rejected=検証器が却下／unverifiable=検証不能として残した／registered_no_outcome=仮説は登録済みだが結果の状態なし(記録の欠落)／"
                  "no_hypothesis_for_family=同じ操作の別の型の仮説のみ(LLMを使わない実行)／no_hypothesis=その操作の仮説なし(LLMを使わない実行)／"
                  "llm_not_used／llm_budget_denied／llm_call_failed／llm_reply_unparsed(解析失敗)／llm_no_proposal_for_op(解析できた返答に提案なし)／"
                  "llm_proposed_other_check_only(検査型が合わない提案だけ)／rejected_at_concretization(仮説の具体化で却下。理由コードは reasons)／"
                  "rejected_by_validator(検証器で却下)／family_outside_system=欠陥の型がシステムの語彙に無い。LLMを使う方式の『仮説なし』は上のLLM段階の分類に分かれる",
    "unit": "カウントは（欠陥 × 実行）の対。案件数ではない。3案件・2ドメイン、うち2案件は同一環境の欠陥あり/なしの対で独立ではない"}


def scope_report(runs: list) -> dict:
    """方式 × 範囲（overall/in_rule4/in_rule5/ungrounded/unreachable/型別）で、見逃しの理由の件数を数える。"""
    out: dict = {}
    for r in runs:
        m = out.setdefault(r["method"], {})
        for fid, d in r["diagnosis"].items():
            tiers = []
            if not d["reachable"]:
                tiers.append("unreachable")
            elif not d["spec_grounded"]:
                tiers.append("ungrounded")
            else:
                tiers.append("overall")
                if d["family"] in RULE4:
                    tiers.append("in_rule4")
                if d["family"] in RULE5:
                    tiers.append("in_rule5")
                tiers.append("family:" + d["family"])
            for t in tiers:
                cell = m.setdefault(t, {"flaw_runs": 0, "categories": {}})
                cell["flaw_runs"] += 1
                cell["categories"][d["category"]] = cell["categories"].get(d["category"], 0) + 1
    for r in runs:
        for d in r["diagnosis"].values():
            if d.get("detail") and d["reachable"]:
                key = f"{d['category']}:{d['detail']}"
                reasons = out[r["method"]].setdefault("_reasons", {})
                reasons[key] = reasons.get(key, 0) + 1
    for m in out.values():
        m["reasons"] = m.pop("_reasons", {})
        for t, cell in m.items():
            if t == "reasons":
                continue
            ok = cell["categories"].get("found_evidence_complete", 0) + cell["categories"].get("found_evidence_incomplete", 0)
            cell["found_rate"] = round(ok / cell["flaw_runs"], 4) if cell["flaw_runs"] and t not in ("ungrounded", "unreachable") else None
    return out


def confirmation_usage(runs: list) -> dict:
    """観測後の仮説を登録後の新しい送信で検証する『確認実験』の集計（方式ごと）。計画・実行・確定・再現せず・未実行（候補止まり）・上限で置換せず、
    と、確定の証拠の出どころ（confirm／探索の送信／仮説のための実験）。"""
    out: dict = {}
    keys = ("confirmations_planned", "confirmations_run", "confirmed_supported", "confirmation_not_reproduced", "confirmation_not_run",
            "confirmation_cap_blocked")
    for r in runs:
        m = out.setdefault(r["method"], {**{k: 0 for k in keys}, "probe_origins": {}, "runs": 0})
        m["runs"] += 1
        for k in keys:
            m[k] += r["metrics"].get(k, 0)
        for o, n in (r["metrics"].get("probe_origins") or {}).items():
            m["probe_origins"][o] = m["probe_origins"].get(o, 0) + n
    return out


def runs_compact(runs: list) -> list:
    """実行ごとの記録（欠陥ごとの分類と理由・LLM呼出しごとの結果・具体化で却下された理由）。結果の事後分析を、この記録だけでできるようにする。
    欠陥ID・操作名を含むので、結果を開く前に件数だけを集計して報告する（AGENTS.md）。"""
    return [{"method": r["method"], "case_id": r["case_id"], "seed": r["seed"], "repeat": r["repeat"],
             "diagnosis": r["diagnosis"],
             "llm": {"calls_detail": r["llm"].get("calls_detail"), "rejected": r["llm"].get("rejected"),
                     "proposals": r["llm"].get("proposals"), "new_registered": r["llm"].get("new_registered")} if r["llm"]["enabled"] else None}
            for r in runs]


def _diff(summary: dict, a: str, b: str) -> dict | None:
    """a−b の再現率・重複確認の差（案件平均）。どちらかの方式が無ければ None。再現率の差が±0.05未満なら『寄与なし』と書く（プロトコルの基準）。"""
    if a not in summary or b not in summary:
        return None
    ra, rb = summary[a]["recall_case_mean"], summary[b]["recall_case_mean"]
    da, db = summary[a]["redundant_case_mean"], summary[b]["redundant_case_mean"]
    rd = None if ra is None or rb is None else round(ra - rb, 4)
    return {"recall_diff": rd, "redundant_diff": None if da is None or db is None else round(da - db, 4),
            "verdict": None if rd is None else ("寄与なし" if abs(rd) < 0.05 else ("前者が上回る" if rd > 0 else "後者が上回る"))}


def llm_usage(runs: list, proto: dict) -> dict | None:
    """LLM方式の呼出し・解析失敗・出力トークン上限到達・使用トークン数（除外せず全て数える。費用は main が前後差で別に記録）。"""
    lr = [r for r in runs if r["method"] == "llm"]
    if not lr:
        return None
    cap = proto["methods"]["llm"].get("max_tokens")
    usage = [u for r in lr for u in (r["llm"].get("usage") or []) if u]
    return {"runs": len(lr), "calls": sum(r["llm"]["calls"] for r in lr), "skipped": sum(r["llm"]["skipped"] for r in lr),
            "parse_failures": sum(r["llm"]["parse_failures"] for r in lr),
            "at_token_cap": sum(1 for u in usage if cap and u.get("output_tokens", 0) >= cap),
            "input_tokens": sum(u.get("input_tokens", 0) for u in usage), "output_tokens": sum(u.get("output_tokens", 0) for u in usage),
            "proposals": sum(r["llm"]["proposals"] for r in lr), "new_registered": sum(r["llm"]["new_registered"] for r in lr)}


def _found_flaws(run: dict) -> list:
    """所見に一致した正解の欠陥ID（採点器の first_hit は flaw_id をキーに持つ）。"""
    return list(run["grade"]["first_hit_experiment_index"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--protocol", required=True)
    ap.add_argument("--include-holdout", action="store_true")
    ap.add_argument("--allow-reuse", action="store_true", help="使用済みの保留ケースを再評価する（『再利用』として記録され、独立評価とは見なされない）")
    ap.add_argument("--approve-real-llm", action="store_true")
    ap.add_argument("--model")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    factory = None
    if a.approve_real_llm:
        proto_llm = json.load(open(a.protocol, encoding="utf-8"))["methods"]["llm"]
        if a.model != proto_llm["model"]:
            print(f"エラー: --model は凍結したプロトコルのモデル（{proto_llm['model']}）と同じでなければなりません", file=sys.stderr)
            return 2
        from tools.lab_eval import TimedLLM
        timed = TimedLLM(a.model)
        from tools.lab_eval import openrouter_usage
        spend0 = openrouter_usage()

        def factory(cfg):
            return _Capped(timed, cfg["max_tokens"], {"reasoning": {"effort": cfg["reasoning_effort"]}})
    try:
        res = run_stage2(a.cases.split(","), protocol_path=a.protocol, include_holdout=a.include_holdout,
                         allow_reuse=a.allow_reuse, llm_factory=factory)
    except FreezeError as e:
        print(f"エラー（何も送信していません）: {e}", file=sys.stderr)
        return 1
    if factory is not None:
        spend1 = openrouter_usage()
        res["llm_spend_usd"] = None if spend0 is None or spend1 is None else round(spend1 - spend0, 4)       # 取得できなければ未計測
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(json.dumps({"summary": res["summary"], "verdict": res["verdict"], "methods_skipped": res["methods_skipped"],
                      "n_cases": res["n_cases"], "n_runs": res["n_runs"]}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
