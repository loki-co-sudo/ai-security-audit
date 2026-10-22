"""P2.1: 実LLM評価(AUDIT)。正解付きサンプルに対し、複数回実行した再現率・未ラベル所見・呼出し数・所要時間を記録する。

使い方: python tools/live_eval.py audit --model MODEL --runs 3 --max-calls 30 [--save FILE]
config.jsonは書き換えない(モデル・エフォートはこのプロセス内だけで上書き)。送るのはヒントを除いたサンプルコード(秘密値なし)のみ。
レート制限や接続失敗は結果に記録して中断する(自動の再試行ループはしない)。結果は『そのモデル・その日』の値で、本番モデルの品質ではない。
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import tempfile
import time
import tokenize
from contextlib import redirect_stdout
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from agents.audit_agent import AuditAgent  # noqa: E402
from core import config  # noqa: E402
from core.event_bus import EventBus  # noqa: E402
from core.llm_client import LLMClient  # noqa: E402

TRUTH = os.path.join(ROOT, "testlab", "benchmark", "ground_truth_audit.json")


class CallLimit(Exception):
    pass


def strip_hints(source: str) -> str:
    """答えのヒントになり得る全コメントとdocstringを空にする。行番号は変えない。"""
    import ast
    lines = source.split("\n")
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            r, c = tok.start
            lines[r - 1] = lines[r - 1][:c].rstrip()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) \
                    and isinstance(first.value.value, str):
                for i in range(first.lineno - 1, first.end_lineno):
                    lines[i] = ""
    return "\n".join(lines)


def line_numbers(location: str) -> list[int]:
    out = []
    for a, b in re.findall(r"(\d+)(?:\s*[-–]\s*(\d+))?", location or ""):
        lo, hi = int(a), int(b) if b else int(a)
        out.extend(range(lo, min(hi, lo + 200) + 1))
    return out


def match(findings: list[dict], truth: dict) -> tuple[dict[str, list[str]], list[dict]]:
    margin = truth.get("match_margin_lines", 0)
    hit: dict[str, list[str]] = {}
    extra = []
    for f in findings:
        nums = set(line_numbers(f.get("location", "")))
        ids = [v["id"] for v in truth["vulnerabilities"]
               if any(v["lines"][0] - margin <= n <= v["lines"][1] + margin for n in nums)]
        for i in ids:
            hit.setdefault(i, []).append(f.get("description", "")[:80])
        if not ids:
            extra.append({"location": f.get("location", ""), "description": f.get("description", "")[:100],
                          "severity": f.get("severity", "")})
    return hit, extra


class CountingLLM(LLMClient):
    calls = 0
    limit = 0
    chars_in = 0
    chars_out = 0

    def _gate(self, messages):
        if self.limit and self.calls >= self.limit:
            raise CallLimit(f"呼出し上限({self.limit})に達しました")
        self.calls += 1
        self.chars_in += sum(len(str(m.get("content", ""))) for m in messages)

    def stream(self, messages, *a, **kw):
        self._gate(messages)
        out = super().stream(messages, *a, **kw)
        self.chars_out += len(out or "")
        return out

    def complete(self, messages, *a, **kw):
        self._gate(messages)
        out = super().complete(messages, *a, **kw)
        self.chars_out += len(out or "")
        return out


def run_audit_once(model: str, path: str, effort: str, max_calls: int, timeout: int = 0) -> dict:
    with open(TRUTH, encoding="utf-8") as f:
        truth = json.load(f)
    config.load()
    llm = CountingLLM(base_url=config.get("llm_base_url"), api_key=config.get("llm_api_key"),
                      model=model, timeout=timeout or config.get("llm_timeout"))
    llm.limit = max_calls
    agent = AuditAgent(EventBus(), llm)
    t0 = time.time()
    err = ""
    with mock.patch.object(AuditAgent, "_save_investigation", lambda *a, **k: None), \
         mock.patch.object(AuditAgent, "_record_telemetry", lambda *a, **k: None), \
         mock.patch.dict(config._cfg, {"effort": effort, "save_evidence": False}), \
         redirect_stdout(sys.stderr):
        try:
            agent._safe_run(path=path)
        except CallLimit as e:
            err = str(e)
    res = agent._last_scan_result
    d = res.to_dict() if res else {"state": "failed", "findings": [], "errors": ["結果なし"]}
    hit, extra = match(d.get("findings", []), truth)
    return {"state": d["state"], "errors": d.get("errors", []) + ([err] if err else []),
            "n_findings": len(d.get("findings", [])), "hit": hit, "unlabeled": extra,
            "llm_calls": llm.calls, "chars_in": llm.chars_in, "chars_out": llm.chars_out,
            "elapsed_s": round(time.time() - t0, 1)}


def evaluate(model: str, runs: int, effort: str, max_calls: int, timeout: int = 0) -> dict:
    with open(TRUTH, encoding="utf-8") as f:
        truth = json.load(f)
    with open(os.path.join(ROOT, truth["source"]), encoding="utf-8") as f:
        stripped = strip_hints(f.read())
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "target_code.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(stripped)
        results, used = [], 0
        for _ in range(runs):
            r = run_audit_once(model, path, effort, max(0, max_calls - used) if max_calls else 0, timeout)
            used += r["llm_calls"]
            results.append(r)
            if r["state"] == "failed" or any("上限" in e for e in r["errors"]):
                break
    ids = [v["id"] for v in truth["vulnerabilities"]]
    ok = [r for r in results if r["state"] in ("completed", "partial") and r["n_findings"] > 0]
    per = {i: sum(1 for r in ok if i in r["hit"]) for i in ids}
    return {"mode": "AUDIT", "model": model, "effort": effort, "runs_requested": runs, "runs_done": len(results),
            "runs_with_findings": len(ok), "per_vuln_hits": per,
            "recall_per_run": [round(sum(1 for i in ids if i in r["hit"]) / len(ids), 3) for r in results],
            "total_llm_calls": used, "hint_stripped": True, "results": results,
            "note": "モデルと日付に依存する参考値。未ラベル所見は誤検知と断定しない。"}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["audit"])
    p.add_argument("--model", required=True)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--effort", choices=("speed", "balanced", "quality"), default="balanced")
    p.add_argument("--max-calls", type=int, default=30)
    p.add_argument("--timeout", type=int, default=0, help="1回のLLM呼出しのタイムアウト秒(0=config値)")
    p.add_argument("--save")
    a = p.parse_args(argv)
    out = evaluate(a.model, a.runs, a.effort, a.max_calls, a.timeout)
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if a.save:
        with open(a.save, "w", encoding="utf-8") as f:
            f.write(text)
    print(text)


if __name__ == "__main__":
    main()
