"""強制終了(os._exit)を再現する試験用の子プロセス(tools/test_lab.py から起動)。ローカル模擬環境にだけ接続する。

引数は JSON(1つ): {"case_path","base_url","creds","strategy","journal_root","evidence_root","crash":"<point>:<test_id>"}
point は before_send / after_send(いずれも送信の前後。ストアへのcommit前)。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy.lab_case import load_case  # noqa: E402
from core.autonomy.lab_workflow import run_lab_case  # noqa: E402

a = json.loads(sys.argv[1])
point, tid = a["crash"].split(":")


def hook(p, t):
    if p == point and t == tid:
        os._exit(137)


run_lab_case(load_case(a["case_path"]), a["base_url"], a["creds"], strategy=a["strategy"],
             journal_root=a["journal_root"], evidence_root=a["evidence_root"], fault_hook=hook)
