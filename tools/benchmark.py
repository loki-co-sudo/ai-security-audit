#!/usr/bin/env python3
"""WEB FUZZ 検出品質のベンチマーク(PRACTICAL_ROADMAP P2.1・detector固定評価モード)。

LLM・CLIに依存せず、検出器(WebFuzzer)をローカルfixtureに直接当てて、正解データ
(testlab/benchmark/ground_truth_web_fuzz.json)と照合する。実LLMを含む評価は別モードで、本モジュールの対象外。

  - 照合キーは (rule_id, location)。LLMのタイトル文字列では照合しない。同じキーの重複検出は1件として数える。
  - 指標: クラス別 TP/FP/FN、Precision、Recall、未検査率、所要時間、HTTP試行数。分母0は "N/A"。
    LLM使用量は detector 固定モードでは "n/a"(取得できない場合は 0 ではなく unknown と区別する)。
  - **未検査を正常例の正解に数えない**: 検査単位が完了していないケースは、脆弱なら FN(かつ fn_unexamined)、
    正常なら TN に数えず unexamined_negative とする。
  - 基準値(改修前)は testlab/baselines/web_fuzz_detector.json。P2.2の改修はこれとの比較で判断する。

  python tools/benchmark.py web-fuzz [--runs 3] [--save-baseline PATH] [--compare PATH]
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime
from urllib.parse import urlsplit

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.engagement import parse_idor_expectations  # noqa: E402

TRUTH_PATH = os.path.join(ROOT, "testlab", "benchmark", "ground_truth_web_fuzz.json")
BASELINE_PATH = os.path.join(ROOT, "testlab", "baselines", "web_fuzz_detector.json")
DEFENSE_TRUTH_PATH = os.path.join(ROOT, "testlab", "benchmark", "ground_truth_defense.json")
DEFENSE_BASELINE_PATH = os.path.join(ROOT, "testlab", "baselines", "defense_signatures.json")
SCHEMA = "ai-security-audit-benchmark"
SCHEMA_VERSION = "1"
NA = "N/A"


def load_truth(path: str = TRUTH_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    ids = [c["case_id"] for c in doc["cases"]]
    if len(ids) != len(set(ids)):
        raise ValueError("case_idが重複しています")
    keys = [(c["rule_id"], c["location"]) for c in doc["cases"]]
    if len(keys) != len(set(keys)):
        raise ValueError("(rule_id, location) が重複しています")
    for c in doc["cases"]:
        if c["expected"] not in ("vulnerable", "not_vulnerable"):
            raise ValueError(f"expectedが不正です: {c['case_id']}")
    return doc


def location_of(method: str, url: str, param: str) -> str:
    return f"{method.upper()} {urlsplit(url).path} {param}"


def _ratio(num: int, den: int):
    return NA if den == 0 else round(num / den, 4)


def evaluate(cases: list[dict], detections: set[tuple[str, str]], examined: set[tuple[str, str]]) -> dict:
    """正解データと検出集合を照合してクラス別の指標を返す(純粋関数。手計算で検証できる)。

    detections / examined は (rule_id, location) の集合(重複は集合化で1件になる)。
    examined は検査単位が実際に完了したケース。正解データに無い検出は unlisted として FP に数える。
    """
    by_rule: dict[str, dict] = {}
    listed = set()
    for c in cases:
        key = (c["rule_id"], c["location"])
        listed.add(key)
        r = by_rule.setdefault(c["rule_id"], {"tp": 0, "fp": 0, "fn": 0, "fn_unexamined": 0, "tn": 0,
                                              "unexamined_negative": 0, "cases": 0, "unexamined": 0,
                                              "unlisted": []})
        r["cases"] += 1
        hit, seen = key in detections, key in examined
        if c["expected"] == "vulnerable":
            if hit:
                r["tp"] += 1
            else:
                r["fn"] += 1
                if not seen:
                    r["fn_unexamined"] += 1
        else:
            if hit:
                r["fp"] += 1
            elif seen:
                r["tn"] += 1
            else:
                r["unexamined_negative"] += 1
        if not seen and not hit:
            r["unexamined"] += 1
    for rule, loc in sorted(detections - listed):
        r = by_rule.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0, "fn_unexamined": 0, "tn": 0,
                                      "unexamined_negative": 0, "cases": 0, "unexamined": 0, "unlisted": []})
        r["fp"] += 1
        r["unlisted"].append(loc)
    total = {k: sum(r[k] for r in by_rule.values())
             for k in ("tp", "fp", "fn", "fn_unexamined", "tn", "unexamined_negative", "cases", "unexamined")}
    for r in [*by_rule.values(), total]:
        r["precision"] = _ratio(r["tp"], r["tp"] + r["fp"])
        r["recall"] = _ratio(r["tp"], r["tp"] + r["fn"])
        r["unexamined_rate"] = _ratio(r["unexamined"], r["cases"])
    return {"per_rule": dict(sorted(by_rule.items())), "total": total}


def run_web_fuzz_detector(max_requests: int = 3000, expectations: list | None = None) -> dict:
    """fixtureへ検出器を直接当てて、検出集合・実施済み集合・HTTP試行数・所要時間を返す。"""
    from testlab.fixtures.web_benchmark import BenchmarkServer, TOKENS
    from tools.web_fuzzer import DEFAULT_PROBES, WebFuzzer, _OBJ_ID_RE

    t0 = time.time()
    with BenchmarkServer() as srv:
        f = WebFuzzer(profile="aggressive", max_pages=40, max_requests=max_requests, target=srv.base_url,
                      auth={"cookie": "sid=" + TOKENS["alice"]}, auth_b={"cookie": "sid=" + TOKENS["bob"]},
                      tls_verify=False, tls_ca_bundle="")
        f.idor_expectations = expectations or []
        f._rng = random.Random(20261022)    # SSTI追加確認の式を固定(同じ入力で同じ結果)
        f.authenticate()
        f.authenticate_b()
        points = f.crawl(srv.base_url)["injection_points"]
        anomalies = f.fuzz(points, DEFAULT_PROBES)
        idor = f._detect_idor(points)
        budget_ok = f._budget_left()
        detections = {(a["category"], location_of(a["method"], a["url"], a["param"])) for a in anomalies}
        detections |= {("IDOR", location_of(i["method"], i["url"], i["param"])) for i in idor}
        examined = {(u["category"], location_of(u["method"], u["url"], u["param"]))
                    for u in f.fuzz_log if u["status"] == "completed"}
        if budget_ok:   # IDOR比較は予算内で最後まで実行できた場合だけ「実施済み」にする(保守的)
            examined |= {("IDOR", location_of(p["method"], p["url"], p["param"])) for p in points
                         if p["method"] == "GET" and _OBJ_ID_RE.match(str(p.get("fields", {}).get(p["param"], "")))}
        return {"detections": detections, "examined": examined, "requests": f._req_count,
                "elapsed_sec": round(time.time() - t0, 3), "points": len(points)}


def run_defense_detector(truth: dict | None = None) -> dict:
    """DEFENSEのシグネチャ検知(MonitorAgent._pattern_match=実コードパス)を正解データの各行へ直接当てる。LLM・通信なし。"""
    from agents.monitor_agent import MonitorAgent
    truth = truth or load_truth(DEFENSE_TRUTH_PATH)
    t0 = time.time()
    lines = {c["location"]: c["line"] for c in truth["cases"]}
    detections = {(pat, lid) for lid, line in lines.items() for pat in MonitorAgent._pattern_match(None, line)}
    # 正規表現は全行に決定的に適用されるので、全ケースが検査済み(中断・予算切れの概念がない)
    examined = {(c["rule_id"], c["location"]) for c in truth["cases"]}
    return {"detections": detections, "examined": examined, "requests": 0, "elapsed_sec": round(time.time() - t0, 3),
            "lines": len(lines)}


def benchmark_defense(runs: int = 1) -> dict:
    truth = load_truth(DEFENSE_TRUTH_PATH)
    outs = [run_defense_detector(truth) for _ in range(max(1, runs))]
    stable = all(o["detections"] == outs[0]["detections"] for o in outs)
    first = outs[0]
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "kind": "defense_signatures",
        "created_at": datetime.now().isoformat(timespec="seconds"), "git": _git(),
        "fixture_sha256": "n/a (正解データ内の行を直接評価)", "truth_sha256": _sha256(DEFENSE_TRUTH_PATH),
        "runs": len(outs), "stable": stable, "http_requests": [0] * len(outs),
        "elapsed_sec": [o["elapsed_sec"] for o in outs], "llm_usage": "n/a (signature mode)",
        "metrics": evaluate(truth["cases"], first["detections"], first["examined"]),
        "detections": sorted([list(d) for d in first["detections"]]),
    }


def _git() -> dict:
    def run(*a):
        try:
            return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    return {"commit": run("rev-parse", "HEAD") or "unknown", "dirty": bool(run("status", "--porcelain"))}


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def expectations_from_truth(truth: dict) -> list[dict]:
    """正解データの期待権限(expected_access)を、利用者が入力する期待権限表の形に変換する(表あり評価用)。"""
    rows = []
    for c in truth["cases"]:
        if c["rule_id"] == "IDOR" and "expected_access" in c:
            _, path, param = c["location"].split(" ")
            rows.append({"path": path, "param": param, "a": c["expected_access"]["alice"],
                         "b": c["expected_access"]["bob"]})
    return parse_idor_expectations(rows)


def benchmark_web_fuzz(runs: int = 1, with_expectations: bool = False) -> dict:
    """runs回実行して結果をまとめる。回ごとの検出集合が一致しなければ stable=False(分散を隠さない)。"""
    truth = load_truth()
    exp = expectations_from_truth(truth) if with_expectations else None
    outs = [run_web_fuzz_detector(expectations=exp) for _ in range(max(1, runs))]
    stable = all(o["detections"] == outs[0]["detections"] and o["examined"] == outs[0]["examined"] for o in outs)
    first = outs[0]
    metrics = evaluate(truth["cases"], first["detections"], first["examined"])
    return {
        "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "kind": "web_fuzz_detector_with_expectations" if with_expectations else "web_fuzz_detector",
        "created_at": datetime.now().isoformat(timespec="seconds"), "git": _git(),
        "fixture_sha256": _sha256(os.path.join(ROOT, "testlab", "fixtures", "web_benchmark.py")),
        "truth_sha256": _sha256(TRUTH_PATH), "runs": len(outs), "stable": stable,
        "http_requests": [o["requests"] for o in outs], "elapsed_sec": [o["elapsed_sec"] for o in outs],
        "llm_usage": "n/a (detector mode)", "metrics": metrics,
        "detections": sorted([list(d) for d in first["detections"]]),
    }


def compare(baseline: dict, current: dict) -> dict:
    """基準値との差(クラス別の指標の差と、増減した検出)。検出数の増減だけで良し悪しを判定しない。"""
    out = {"per_rule": {}, "added_detections": [], "removed_detections": []}
    for rule in sorted(set(baseline["metrics"]["per_rule"]) | set(current["metrics"]["per_rule"])):
        b = baseline["metrics"]["per_rule"].get(rule, {})
        c = current["metrics"]["per_rule"].get(rule, {})
        diff = {k: [b.get(k), c.get(k)] for k in ("tp", "fp", "fn", "tn", "precision", "recall", "unexamined_rate")
                if b.get(k) != c.get(k)}
        if diff:
            out["per_rule"][rule] = diff
    bset = {tuple(d) for d in baseline["detections"]}
    cset = {tuple(d) for d in current["detections"]}
    out["added_detections"] = sorted(map(list, cset - bset))
    out["removed_detections"] = sorted(map(list, bset - cset))
    return out


def format_table(report: dict) -> str:
    m = report["metrics"]
    lines = [f"{'rule':<10}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}{'unexam':>8}{'precision':>11}{'recall':>9}"]
    for rule, r in [*m["per_rule"].items(), ("TOTAL", m["total"])]:
        lines.append(f"{rule:<10}{r['tp']:>4}{r['fp']:>4}{r['fn']:>4}{r['tn']:>4}"
                     f"{str(r['unexamined_rate']):>8}{str(r['precision']):>11}{str(r['recall']):>9}")
    lines.append(f"runs={report['runs']} stable={report['stable']} http={report['http_requests']} "
                 f"elapsed={report['elapsed_sec']} llm={report['llm_usage']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("web-fuzz")
    w.add_argument("--runs", type=int, default=1)
    w.add_argument("--save-baseline", metavar="PATH")
    w.add_argument("--compare", metavar="PATH", nargs="?", const=BASELINE_PATH)
    w.add_argument("--with-expectations", action="store_true", help="IDOR期待権限表あり(正解データのexpected_accessを入力として与える)")
    w.add_argument("--json", action="store_true")
    d = sub.add_parser("defense", help="DEFENSEシグネチャ検知(ATTACK_PATTERNS)の固定評価")
    d.add_argument("--runs", type=int, default=1)
    d.add_argument("--save-baseline", metavar="PATH")
    d.add_argument("--compare", metavar="PATH", nargs="?", const=DEFENSE_BASELINE_PATH)
    d.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd == "defense":
        report = benchmark_defense(args.runs)
        args.with_expectations = False
    else:
        report = benchmark_web_fuzz(args.runs, args.with_expectations)
    if args.save_baseline:
        os.makedirs(os.path.dirname(os.path.abspath(args.save_baseline)), exist_ok=True)
        with open(args.save_baseline, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.write("\n")
    print(json.dumps(report, ensure_ascii=False, indent=1) if args.json else format_table(report))
    if args.compare:
        with open(args.compare, encoding="utf-8") as f:
            print(json.dumps(compare(json.load(f), report), ensure_ascii=False, indent=1))
    return 0 if report["stable"] else 2


if __name__ == "__main__":
    sys.exit(main())
