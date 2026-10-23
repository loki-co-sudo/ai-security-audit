#!/usr/bin/env python3
"""ローカル模擬診断案件の評価ハーネス(docs/LOCAL_LAB_EVAL.md)。

案件×方式(fixed / fixed_random / deterministic / llm)を同じ予算・同じ初期状態で実行し、独立採点器
(testlab/lab/grader.py)で採点して比較する。診断ワークフローの実行中は正解ディレクトリを権限000で封印する。
実LLMは `--llm real` と明示承認フラグ(`--approve-real-llm`)がない限り使わない。モックは「実LLM評価」ではない。

  python tools/lab_eval.py run --split dev --strategies fixed,fixed_random,deterministic,llm --llm mock-first
  python tools/lab_eval.py run --split holdout --include-holdout   # 保留ケース(実行すると使用済みとして記録)
  python tools/lab_eval.py run --split dev --strategies llm --llm real --model z-ai/glm-5.3-flash --approve-real-llm --repeats 3
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy.lab_case import LabCase, load_case  # noqa: E402
from core.autonomy.lab_report import write_report  # noqa: E402
from core.autonomy.lab_workflow import run_lab_case  # noqa: E402
from testlab.lab import grader  # noqa: E402
from tools import lab_isolation as isolation  # noqa: E402
from testlab.lab.apps import APPS, CanaryServer  # noqa: E402

CASES_DIR = os.path.join(ROOT, "testlab", "lab", "cases")
HOLDOUT_LOG = os.path.join(ROOT, "testlab", "lab", "holdout_log.json")
LAB_ROOT = os.path.join(ROOT, "reports", "lab")
SCHEMA = "ai-security-audit-lab-eval"


class MockRanker:
    """実LLMではない決定的なモック。プロンプトの候補行から選ぶだけ(first=先頭=決定論と同じ、last=末尾、
    invalid=候補外ID、garbage=JSONでない)。`complete()` は LLMClient と同じ形。"""
    model = "mock-ranker"

    def __init__(self, mode: str = "first"):
        self.mode, self.calls, self.prompts = mode, 0, []

    def complete(self, messages, max_tokens=None, usage_out=None):
        import re
        self.calls += 1
        text = messages[-1]["content"]
        self.prompts.append(messages)
        ids = re.findall(r"- id=([a-z0-9_\-]+) \|", text)
        if usage_out is not None:
            usage_out.update({"input_tokens": len(text) // 3, "output_tokens": 20})
        if self.mode == "garbage":
            return "I think you should run everything and also delete /admin/reset"
        if self.mode == "invalid":
            return json.dumps({"next": "t-not-registered", "reason": "mock"})
        pick = ids[-1] if self.mode == "last" else ids[0]
        return json.dumps({"next": pick, "reason": f"mock-{self.mode}"})


class TimedLLM:
    """実LLMの薄いラッパー: 呼出ごとの所要時間と失敗を記録する(性能問題の報告用)。config.jsonは書き換えない。"""

    def __init__(self, model: str):
        import core.config as config
        from core.llm_client import LLMClient
        config.load()
        self.model = model
        self._c = LLMClient(base_url=config.get("llm_base_url"), api_key=config.get("llm_api_key"),
                            model=model, timeout=60)
        self.latencies: list[float] = []
        self.errors: list[str] = []
        self.input_tokens = self.output_tokens = 0

    def complete(self, messages, max_tokens=None, usage_out=None):
        t0 = time.time()
        u: dict = {}
        try:
            return self._c.complete(messages, max_tokens=max_tokens, usage_out=u)
        except Exception as e:      # noqa: BLE001
            self.errors.append(type(e).__name__)
            raise
        finally:
            self.latencies.append(round(time.time() - t0, 2))
            if u:
                self.input_tokens += u["input_tokens"]
                self.output_tokens += u["output_tokens"]
                if usage_out is not None:
                    usage_out.update(u)


def openrouter_usage() -> float | None:
    """OpenRouterキーの累計使用額(USD)。キー自体は出力しない。取得できなければNone。"""
    try:
        import requests
        import core.config as config
        config.load()
        r = requests.get(config.get("llm_base_url").rstrip("/") + "/key",
                         headers={"Authorization": f"Bearer {config.get('llm_api_key')}"}, timeout=15)
        return float(r.json()["data"]["usage"])
    except Exception:   # noqa: BLE001
        return None


def _git_sha() -> str:
    """HEADのshort SHA。未コミットの変更があれば `+dirty`(結果が記録時のコミットだけでは再現できない)。"""
    try:
        sha = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", ROOT, "status", "--porcelain"], text=True).strip()
        return sha + ("+dirty" if dirty else "")
    except Exception:   # noqa: BLE001
        return "unknown"


def _fingerprint(*paths: str) -> str:
    h = hashlib.sha256()
    for p in paths:
        with open(p, "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:16]


def list_cases(split: str) -> list[LabCase]:
    out = []
    for fn in sorted(os.listdir(CASES_DIR)):
        if fn.endswith(".json"):
            c = load_case(os.path.join(CASES_DIR, fn))
            if split == "all" or c.split == split:
                out.append(c)
    return out


def load_holdout_log() -> dict:
    try:
        with open(HOLDOUT_LOG, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"evaluations": []}


def holdout_status(case: LabCase) -> str:
    """unused / evaluated(記録時と同一内容) / consumed(評価後に案件設定または正解が変更された=開発に使われた)。"""
    log = [e for e in load_holdout_log()["evaluations"] if e["case_id"] == case.case_id]
    if not log:
        return "unused"
    cur = _fingerprint(os.path.join(CASES_DIR, case.case_id + ".json"),
                       os.path.join(grader.TRUTH_DIR, case.case_id + ".json"))
    return "evaluated" if cur == log[-1]["fingerprint"] else "consumed"


def _record_holdout(case: LabCase, strategies: list[str]) -> None:
    log = load_holdout_log()
    log["evaluations"].append({
        "case_id": case.case_id, "commit": _git_sha(), "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "strategies": strategies,
        "fingerprint": _fingerprint(os.path.join(CASES_DIR, case.case_id + ".json"),
                                    os.path.join(grader.TRUTH_DIR, case.case_id + ".json"))})
    with open(HOLDOUT_LOG, "w", encoding="utf-8") as f:
        json.dump(log, f, ensure_ascii=False, indent=1)
        f.write("\n")


def run_one(case: LabCase, strategy: str, *, seed: int, llm, out_dir: str, replay: bool = True, tag: str = "",
            llm_max_tokens: int = 200, isolate_truth: bool = False, retry_transient: int = 0) -> dict:
    run_dir = os.path.join(out_dir, f"{case.case_id}_{strategy}" + (f"_s{seed}" if strategy == "fixed_random" else "")
                           + (f"_{tag}" if tag else ""))
    canary = CanaryServer().start()
    try:
        with APPS[case.case_id](canary) as app:
            with grader.sealed():                                  # 実行中は正解を読めない
                if isolate_truth:                                  # 別プロセス+正解ディレクトリを空のtmpfsで覆う
                    if llm is not None and not isinstance(llm, MockRanker):
                        raise SystemExit("プロセス隔離はモックLLMまでの対応です(実LLMは未対応)")
                    res = isolation.run_worker({
                        "case_path": os.path.join(CASES_DIR, case.case_id + ".json"), "base_url": app.base_url,
                        "creds": app.credentials(), "strategy": strategy, "seed": seed, "llm_max_tokens": llm_max_tokens,
                        "journal_root": os.path.join(run_dir, "runs"), "evidence_root": os.path.join(run_dir, "evidence"),
                        "truth_dir": grader.TRUTH_DIR, "mock": llm.mode if llm is not None else None,
                        "retry_transient": retry_transient}, grader.TRUTH_DIR)
                else:
                    res = run_lab_case(case, app.base_url, app.credentials(), strategy=strategy, llm=llm, llm_max_tokens=llm_max_tokens,
                                       seed=seed, journal_root=os.path.join(run_dir, "runs"),
                                       evidence_root=os.path.join(run_dir, "evidence"),
                                       retry_transient=retry_transient).to_dict()
            env_requests = list(app.requests)
        truth = grader.load_truth(case.case_id)
        reproduced = _replay(case, res, run_dir) if replay else None
        report = write_report(case, res, run_dir, evidence_root=os.path.join(run_dir, "evidence"))
        g = grader.grade(case, truth, res, env_requests, canary.hits, reproduced=reproduced)
    finally:
        canary.stop()
    with open(os.path.join(run_dir, "result.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    return {"grade": g, "report": os.path.relpath(report, ROOT), "run_id": res["run_id"],
            "selection_log": res["selection_log"], "worker_checks": res.get("worker_checks")}


def _replay(case: LabCase, res: dict, run_dir: str) -> dict:
    """初期化した別インスタンスで、所見の根拠テストだけを固定順に再実行し、同じ逸脱が出るか確認する。"""
    want = {f["hypothesis_id"]: f for f in res["findings"]}
    if not want:
        return {}
    ids = sorted({t for f in want.values() for t in f["test_ids"] + f["control_test_ids"]},
                 key=case.test_order().index)
    with APPS[case.case_id]() as app2:
        r2 = run_lab_case(case, app2.base_url, app2.credentials(), strategy="fixed", only_tests=ids,
                          journal_root=os.path.join(run_dir, "replay_runs"),
                          evidence_root=os.path.join(run_dir, "replay_evidence"),
                          budget_override={"max_requests": len(ids), "max_llm_calls": 0})
    return {h: all(r2.tests[t]["outcome"] == "deviates" for t in f["test_ids"]) for h, f in want.items()}


def aggregate(rows: list[dict]) -> dict:
    """方式ごとの集計。同じ(案件,方式)の複数回(fixed_randomのseed)は先に平均し、案件を合計する。"""
    by = {}
    for r in rows:
        by.setdefault(r["grade"]["strategy"], {}).setdefault(r["grade"]["case_id"], []).append(r["grade"])
    out = {}
    for strat, cases in by.items():
        def mean(key):
            vals = [sum(float(g[key]) for g in gs) / len(gs) for gs in cases.values()]
            return round(sum(vals), 4)
        tp, fp, reach = mean("unique_confirmed_with_evidence"), mean("false_positives"), mean("reachable_flaws")
        und = [g["undetermined_rate"] for gs in cases.values() for g in gs if g["undetermined_rate"] != "N/A"]
        out[strat] = {
            "cases": len(cases), "runs": sum(len(g) for g in cases.values()),
            "workflow_completion_rate": round(sum(1 for gs in cases.values() for g in gs if g["workflow_completed"])
                                              / sum(len(g) for g in cases.values()), 4),
            "unique_confirmed_with_evidence": tp, "false_positives": fp, "false_negatives": mean("false_negatives"),
            "reachable_flaws": reach,
            "candidate_recall": grader.NA if reach == 0 else round(mean("candidate_found") / reach, 4),
            "candidate_false": mean("candidate_false"), "unverified_deviations": mean("unverified_deviations"),
            "chains_expected": mean("chains_expected"), "chains_true": mean("chains_true"),
            "chains_false": mean("chains_false"),
            "chain_recall": grader.NA if mean("chains_expected") == 0 else round(mean("chains_true") / mean("chains_expected"), 4),
            "precision": grader.NA if tp + fp == 0 else round(tp / (tp + fp), 4),
            "recall": grader.NA if reach == 0 else round(tp / reach, 4),
            "undetermined_rate_mean": grader.NA if not und else round(sum(und) / len(und), 4),
            "tests_executed": mean("tests_executed"), "elapsed_seconds": mean("elapsed_seconds"),
            "llm_calls": mean("llm_calls"), "llm_cost": "unknown" if mean("llm_calls") else 0,
            "human_interventions": mean("human_interventions"), "refused_operations": mean("refused_operations"),
            "budget_denied": mean("budget_denied"),
            "boundary_violations": sum(g["boundary_violations"] for gs in cases.values() for g in gs),
            "evidence_sufficiency_mean": _mean_na([g["evidence_sufficiency"] for gs in cases.values() for g in gs]),
            "reproduction_rate": _repro(cases)}
    return out


def record_to_ledger(res: dict, engagement_id: str, root: str | None = None) -> dict:
    """lab結果のScanResultを案件別の所見台帳へ記録する(同じscan_idは冪等)。モードLABは不在の根拠にしないため、
    差分で『観測されなくなった』所見は NOT_OBSERVED ではなく UNVERIFIED になる。"""
    from core.findings_ledger import Ledger
    led = Ledger(engagement_id, **({"root": root} if root else {}))
    return led.record_scan(res["scan_result"])


def _lat(v):
    if not v:
        return None
    v = sorted(v)
    return {"n": len(v), "mean": round(sum(v) / len(v), 2), "p50": v[len(v) // 2], "max": v[-1]}


def _mean_na(vals):
    v = [x for x in vals if x != "N/A"]
    return grader.NA if not v else round(sum(v) / len(v), 4)


def _repro(cases):
    a = r = 0
    for gs in cases.values():
        for g in gs:
            if g["reproduction"]:
                a += g["reproduction"]["attempted"]
                r += g["reproduction"]["reproduced"]
    return grader.NA if a == 0 else round(r / a, 4)


def run_matrix(split: str, strategies: list[str], *, seeds: int, llm_mode: str, out_dir: str,
               include_holdout: bool = False, model: str = "", repeats: int = 1,
               llm_max_tokens: int = 200, isolate_truth: bool = False, retry_transient: int = 0) -> dict:
    cases = list_cases(split)
    if any(c.split == "holdout" for c in cases) and not include_holdout:
        raise SystemExit("保留ケースの評価には --include-holdout が必要です(実行すると使用済みとして記録されます)")
    for c in cases:
        if c.split == "holdout" and holdout_status(c) == "consumed":
            print(f"警告: {c.case_id} は評価後に変更されており、もう未使用の保留ケースではありません", file=sys.stderr)
    rows = []
    real_clients: list = []
    for c in cases:
        for s in strategies:
            n = seeds if s == "fixed_random" else (repeats if (s == "llm" and llm_mode == "real") else 1)
            for seed in range(n):
                llm = MockRanker(llm_mode.replace("mock-", "")) if (s == "llm" and llm_mode.startswith("mock-")) else None
                if s == "llm" and llm_mode == "real":
                    llm = TimedLLM(model)
                    real_clients.append(llm)
                if s == "llm" and llm is None:
                    continue                      # llmが無い方式は実行しない(未実施として扱う)
                rows.append(run_one(c, s, seed=seed, llm=llm, out_dir=out_dir, tag=f"r{seed}" if llm_mode == "real" and s == "llm" else "",
                                    llm_max_tokens=llm_max_tokens, isolate_truth=isolate_truth,
                                    retry_transient=retry_transient))
        if c.split == "holdout":
            _record_holdout(c, strategies)
    checks = [r["worker_checks"] for r in rows if r.get("worker_checks")]
    return {"schema": SCHEMA, "schema_version": "1", "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "isolation": {"network": isolation.network_state(), "truth_process_isolation": isolate_truth, "retry_transient": retry_transient,
                          "worker_runs": len(checks),
                          "truth_entries_visible_in_workers": sorted({c["truth_entries_visible"] for c in checks}),
                          "workers_loopback_only": all(c["network"]["loopback_only"] for c in checks) if checks else None},
            "split": split, "strategies": strategies, "llm_mode": llm_mode,
            "llm_is_mock": llm_mode.startswith("mock-"), "real_llm_used": bool(real_clients),
            "versions": {"commit": _git_sha(), "python": platform.python_version(), "platform": platform.platform(),
                         "cases": {c.case_id: _fingerprint(os.path.join(CASES_DIR, c.case_id + ".json")) for c in cases},
                         "prompt": "lab-rank/1", "fixed_random_seeds": seeds, "llm_max_tokens": llm_max_tokens},
            "real_llm": ({"model": model, "calls": sum(len(c.latencies) for c in real_clients),
                          "errors": [e for c in real_clients for e in c.errors],
                          "latency_s": _lat([x for c in real_clients for x in c.latencies]),
                          "input_tokens": sum(c.input_tokens for c in real_clients),
                          "output_tokens": sum(c.output_tokens for c in real_clients)} if real_clients else None),
            "runs": [r["grade"] for r in rows], "selections": {r["run_id"]: r["selection_log"] for r in rows}, "reports": [r["report"] for r in rows],
            "aggregate": aggregate(rows)}


def render_table(doc: dict) -> str:
    keys = ["workflow_completion_rate", "unique_confirmed_with_evidence", "false_positives", "false_negatives",
            "precision", "recall", "candidate_recall", "candidate_false", "undetermined_rate_mean", "tests_executed", "llm_calls", "refused_operations", "budget_denied",
            "boundary_violations", "evidence_sufficiency_mean", "reproduction_rate"]
    strat = list(doc["aggregate"])
    lines = ["| 指標 | " + " | ".join(strat) + " |", "|---|" + "---|" * len(strat)]
    for k in keys:
        lines.append(f"| {k} | " + " | ".join(str(doc["aggregate"][s][k]) for s in strat) + " |")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--split", default="dev", choices=["dev", "holdout", "all"])
    r.add_argument("--include-holdout", action="store_true")
    r.add_argument("--strategies", default="fixed,fixed_random,deterministic")
    r.add_argument("--seeds", type=int, default=10, help="fixed_randomのシード数")
    r.add_argument("--llm", default="none", help="none | mock-first | mock-last | real")
    r.add_argument("--approve-real-llm", action="store_true")
    r.add_argument("--model", default="")
    r.add_argument("--llm-max-tokens", type=int, default=200, help="助言1回の最大出力トークン(推論モデルは小さいと本文が空になる)")
    r.add_argument("--repeats", type=int, default=1, help="実LLM方式の繰り返し回数")
    r.add_argument("--max-llm-calls-total", type=int, default=100)
    r.add_argument("--out", default=None)
    r.add_argument("--save-baseline", default=None)
    r.add_argument("--retry-transient", type=int, default=0, choices=[0, 1], help="一時的な失敗(503等)を理由付きで1回だけ再試行する(deterministic/llmのみ)")
    r.add_argument("--isolate-net", action="store_true", help="外部へ到達できないネットワーク名前空間(loopbackのみ)の中で実行する(bwrap)")
    r.add_argument("--isolate-truth", action="store_true", help="ワークフローを別プロセスで実行し、正解ディレクトリを空のtmpfsで覆う(bwrap)")
    a = ap.parse_args()
    if a.isolate_net:
        if a.llm == "real":
            print("実LLMはネットワークが必要なため --isolate-net と併用できません。", file=sys.stderr)
            return 2
        isolation.reexec_without_network([os.path.abspath(__file__)] + [x for x in sys.argv[1:]])
    if a.llm == "real":
        if not a.approve_real_llm or not a.model:
            print("実LLMには承認フラグ(--approve-real-llm)とモデル指定(--model)が必要です(未承認のため中止)。", file=sys.stderr)
            return 2
        if a.repeats * 4 * 8 > a.max_llm_calls_total:
            print("計画した最大呼出数が --max-llm-calls-total を超えます", file=sys.stderr)
            return 2
    out = a.out or os.path.join(LAB_ROOT, "eval_" + time.strftime("%Y%m%d_%H%M%S"))
    u0 = openrouter_usage() if a.llm == "real" else None
    doc = run_matrix(a.split, a.strategies.split(","), seeds=a.seeds, llm_mode=a.llm, out_dir=out,
                     include_holdout=a.include_holdout, model=a.model, repeats=a.repeats,
                     llm_max_tokens=a.llm_max_tokens, isolate_truth=a.isolate_truth,
                     retry_transient=a.retry_transient)
    if a.llm == "real":
        u1 = openrouter_usage()
        doc["real_llm"]["spend_usd"] = None if (u0 is None or u1 is None) else round(u1 - u0, 5)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "eval.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    if a.save_baseline:
        with open(a.save_baseline, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
            f.write("\n")
    print(render_table(doc))
    print(f"\n出力: {os.path.relpath(out, ROOT)}/eval.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
