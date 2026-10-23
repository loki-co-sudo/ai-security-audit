"""診断ワークフローを1回だけ実行して結果JSONを標準出力へ返す隔離ワーカー(tools/lab_isolation.py経由で起動)。

親プロセスが渡す標準入力のJSON: case_path / base_url / creds / strategy / seed / journal_root / evidence_root /
llm_max_tokens / truth_dir / mock(null|first|last|invalid|garbage)。正解ディレクトリの中身は読まない(見える件数だけ数える)。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main() -> int:
    p = json.load(sys.stdin)
    from core.autonomy.lab_case import load_case
    from core.autonomy.lab_workflow import run_lab_case
    from tools.lab_isolation import network_state
    llm = None
    if p.get("mock"):
        from tools.lab_eval import MockRanker
        llm = MockRanker(p["mock"])
    try:
        visible = len(os.listdir(p["truth_dir"]))
    except OSError:
        visible = -1
    res = run_lab_case(load_case(p["case_path"]), p["base_url"], p["creds"], strategy=p["strategy"], llm=llm,
                       seed=p["seed"], journal_root=p["journal_root"], evidence_root=p["evidence_root"],
                       llm_max_tokens=p["llm_max_tokens"], retry_transient=p.get("retry_transient", 0)).to_dict()
    res["worker_checks"] = {"truth_entries_visible": visible, "network": network_state(), "pid": os.getpid()}
    json.dump(res, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
