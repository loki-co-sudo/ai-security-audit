"""自律調査の強制終了(os._exit)を再現する試験用の子プロセス（tools/test_research.py から起動）。ローカルの被験環境にだけ接続する。

引数は JSON(1つ): {"case_path","base_url","creds","journal_root","evidence_root","crash":"<point>:<exp_id>","budget"(任意),
"llm"(任意: MockProposerのmode。使うときは budget に max_llm_calls が必要)}
point は before_send / after_send（いずれも送信の前後。ストアへのcommit前）。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy.research_case import load_blind_case  # noqa: E402
from core.autonomy.research_loop import run_research_case  # noqa: E402

a = json.loads(sys.argv[1])
point, _, exp_id = a["crash"].partition(":")


def hook(p, e):
    if p == point and e == exp_id:
        os._exit(137)


llm = None
if a.get("llm"):
    from tools.research_eval import MockProposer  # noqa: E402
    llm = MockProposer(a["llm"])

run_research_case(load_blind_case(a["case_path"]), a["base_url"], a["creds"], journal_root=a["journal_root"],
                  evidence_root=a["evidence_root"], budget_override=a.get("budget"), fault_hook=hook, llm=llm)
