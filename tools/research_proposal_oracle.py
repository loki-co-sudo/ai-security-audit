"""LLMを使わない検査（正解・被験環境は読まない。公開仕様だけ）: 一覧操作(own_list)×全アカウントについて、
『理想的な list_visibility の提案』が具体化(build_list_scope)と検証器(validate_hypothesis)を通るかを調べる。
LLMの提案能力と、提案を受け取るパイプラインの能力（通せるか）を分けるための事後分析。
使い方: .venv/bin/python3 tools/research_proposal_oracle.py --cases a,b,c [--out file.json]
"""
from __future__ import annotations
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy.research_case import load_blind_case  # noqa: E402
from core.autonomy.research_hypothesis import validate_hypothesis  # noqa: E402
from core.autonomy.research_llm import process_proposal  # noqa: E402
from core.autonomy.research_model import TargetModel  # noqa: E402

CASES_DIR = os.path.join(ROOT, "testlab", "lab", "blind_cases")


def check_case(case_id: str, cases_dir: str = CASES_DIR) -> list:
    case = load_blind_case(os.path.join(cases_dir, f"{case_id}.json"))
    model = TargetModel(case)
    rows = []
    for op in case.operations.values():
        if op.method != "GET" or op.params or op.access["kind"] != "own_list":
            continue
        otype = op.returns.get("object")
        obj = case.objects.get(otype, {})
        for role in sorted(case.accounts):
            status, reason, h = process_proposal(case, model, {"check": "list_visibility", "op_id": op.op_id, "probe_role": role,
                                                              "basis_clause": op.access["clause"], "path_params": {}, "rationale": "oracle"})
            problems = validate_hypothesis(h, model) if h is not None else []
            rows.append({"case_id": case_id, "op_id": op.op_id, "role": role, "object": otype,
                         "has_owner_field": bool(obj.get("owner_field")), "has_shared_field": bool(obj.get("shared_field")),
                         "status": status if not problems else "rejected", "reason": reason or ("validator:" + ",".join(problems) if problems else "")})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    rows = [r for c in a.cases.split(",") for r in check_case(c)]
    for r in rows:
        print(f"{r['case_id']:20s} {r['op_id']:18s} {r['role']:14s} owner={int(r['has_owner_field'])} shared={int(r['has_shared_field'])} -> {r['status']} {r['reason']}")
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump({"note": "事後分析。公開仕様だけを使い、正解・被験環境は読まない。LLM呼出0。", "rows": rows}, f, ensure_ascii=False, indent=1)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
