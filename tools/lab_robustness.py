#!/usr/bin/env python3
"""決定論方式が、作者の置いた係数(事前重要度・情報価値)と宣言順にどれだけ依存するかを調べる(docs/LOCAL_LAB_EVAL.md §9 ステップ2)。

開発ケースだけを対象にする(保留は対象外)。係数を乗法ノイズで摂動、または全て同値に潰し、決定論の再現率(到達可能な不備の検出率)を
順序ランダム方式(係数を使わない)と比べる。摂動は評価側で案件設定を書き換えるだけで、ワークフローとgraderは変えない。
  python tools/lab_robustness.py --draws 20 --sigmas 0.25,0.5,1.0 --out /path/to/out.json
"""
from __future__ import annotations
import argparse
import copy
import json
import math
import os
import random
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from core.autonomy.lab_case import parse_case  # noqa: E402
from tools import lab_eval  # noqa: E402


def _clip(v: float) -> float:
    return round(min(1.0, max(0.05, v)), 4)


def perturb(doc: dict, mode: str, sigma: float, rng: random.Random) -> dict:
    d = copy.deepcopy(doc)
    if mode == "noise":
        for h in d["hypotheses"]:
            h["prior_value"] = _clip(h["prior_value"] * math.exp(rng.gauss(0, sigma)))
        for t in d["tests"]:
            t["info_value"] = _clip(t["info_value"] * math.exp(rng.gauss(0, sigma)))
    elif mode == "flat":                       # 係数の情報を消す(全て同値)
        for h in d["hypotheses"]:
            h["prior_value"] = 0.5
        for t in d["tests"]:
            t["info_value"] = 0.5
    elif mode == "shuffle_order":              # 宣言順だけを入れ替える(同点の決め方に効く)
        rng.shuffle(d["tests"])
    else:
        raise ValueError(mode)
    return d


def recall(case, strategy: str, seed: int, out: str) -> float:
    r = lab_eval.run_one(case, strategy, seed=seed, llm=None, out_dir=out, replay=False)
    g = r["grade"]
    return g["unique_confirmed_with_evidence"], g["reachable_flaws"], g["false_positives"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--draws", type=int, default=20)
    ap.add_argument("--sigmas", default="0.25,0.5,1.0")
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--out", default="")
    a = ap.parse_args(argv)
    tmp = tempfile.mkdtemp(prefix="labrob_")
    cases = lab_eval.list_cases("dev")                 # 保留は含めない
    conds = [("noise", float(s)) for s in a.sigmas.split(",")] + [("flat", 0.0), ("shuffle_order", 0.0)]
    result = {"cases": {}, "overall": {}}
    try:
        base = {}
        for c in cases:
            rnd = [recall(c, "fixed_random", s, tmp) for s in range(a.seeds)]
            base[c.case_id] = {"random_tp": sum(x[0] for x in rnd) / len(rnd), "reach": rnd[0][1],
                               "fixed_tp": recall(c, "fixed", 0, tmp)[0], "det_orig_tp": recall(c, "deterministic", 0, tmp)[0]}
        tot = {k: {"det": 0.0, "wins": 0, "ties": 0, "losses": 0, "n": 0, "fp": 0.0} for k in [f"{m}:{s}" for m, s in conds]}
        for c in cases:
            doc = c.public_dict()
            row = {"reachable": base[c.case_id]["reach"], "random_mean": round(base[c.case_id]["random_tp"], 3),
                   "fixed": base[c.case_id]["fixed_tp"], "deterministic_original": base[c.case_id]["det_orig_tp"], "conditions": {}}
            for mode, sigma in conds:
                n_draw = 1 if mode == "flat" else a.draws
                tps, fps = [], []
                for i in range(n_draw):
                    rng = random.Random(f"{c.case_id}|{mode}|{sigma}|{i}")
                    pc = parse_case(perturb(doc, mode, sigma, rng))
                    tp, _, fp = recall(pc, "deterministic", 0, tmp)
                    tps.append(tp)
                    fps.append(fp)
                key = f"{mode}:{sigma}"
                m = sum(tps) / len(tps)
                row["conditions"][key] = {"det_mean": round(m, 3), "det_min": min(tps), "det_max": max(tps),
                                          "draws_better_than_random": sum(1 for x in tps if x > base[c.case_id]["random_tp"] + 1e-9),
                                          "draws_worse_than_random": sum(1 for x in tps if x < base[c.case_id]["random_tp"] - 1e-9),
                                          "draws": len(tps), "fp_mean": round(sum(fps) / len(fps), 3)}
                t = tot[key]
                t["det"] += sum(tps)
                t["n"] += len(tps)
                t["wins"] += row["conditions"][key]["draws_better_than_random"]
                t["losses"] += row["conditions"][key]["draws_worse_than_random"]
                t["fp"] += sum(fps)
            result["cases"][c.case_id] = row
        reach = sum(b["reach"] for b in base.values())
        result["overall"] = {
            "reachable_total": reach, "random_total_mean": round(sum(b["random_tp"] for b in base.values()), 3),
            "fixed_total": sum(b["fixed_tp"] for b in base.values()),
            "deterministic_original_total": sum(b["det_orig_tp"] for b in base.values()),
            "conditions": {k: {"det_total_mean": round(v["det"] / (v["n"] / len(cases)), 3),
                               "case_draws_better_than_random": v["wins"], "case_draws_worse_than_random": v["losses"],
                               "case_draws": v["n"], "fp_total_mean": round(v["fp"] / (v["n"] / len(cases)), 3)} for k, v in tot.items()}}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    text = json.dumps(result, ensure_ascii=False, indent=1)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(json.dumps(result["overall"], ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
