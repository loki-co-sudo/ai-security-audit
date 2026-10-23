"""強制終了(os._exit)を再現する試験用の子プロセス(tools/test_lab.py から起動)。ローカル模擬環境にだけ接続する。

引数は JSON(1つ): {"case_path","base_url","creds","strategy","journal_root","evidence_root","crash":"<point>:<test_id>",
"cuts":[[URLに含まれる文字列, 認証トークン|null, 残すバイト数, 理由], ...](任意。該当する応答の本文を途中で切った扱いにする)}
"engine_version"(任意): 旧版のRunを作る試験用にLAB_ENGINE_VERSIONを差し替える。
point は before_send / after_send(いずれも送信の前後。ストアへのcommit前)。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.autonomy.lab_case import load_case  # noqa: E402
from core.autonomy import lab_workflow as _lw  # noqa: E402
from core.autonomy.lab_workflow import run_lab_case  # noqa: E402

a = json.loads(sys.argv[1])
point, tid = a["crash"].split(":")


if a.get("engine_version"):
    _lw.LAB_ENGINE_VERSION = a["engine_version"]

if a.get("cuts"):
    _orig = _lw.HttpTransport._cap_response_body

    def _patched(tself, resp):
        _orig(tself, resp)
        url = resp.request.url or ""
        auth = (resp.request.headers.get("Authorization") or "").removeprefix("Bearer ")
        for part, token, keep, reason in a["cuts"]:
            if part in url and (token is None or token == auth):
                resp._content = resp._content[:keep]
                resp.fz_truncated, resp.fz_incomplete_reason, resp.fz_bytes_read = True, reason, keep
                return
    _lw.HttpTransport._cap_response_body = _patched


def hook(p, t):
    if p == point and t == tid:
        os._exit(137)


run_lab_case(load_case(a["case_path"]), a["base_url"], a["creds"], strategy=a["strategy"],
             journal_root=a["journal_root"], evidence_root=a["evidence_root"], fault_hook=hook)
