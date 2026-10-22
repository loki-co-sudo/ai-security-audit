"""P2.1: 実LLM評価(AUDIT。defense/fuzz/attackは tools/live_eval_modes.py)。正解付きサンプルに対し、複数回実行した再現率・未ラベル所見・呼出し数・所要時間を記録する。

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
TRUTHS = {"v1": TRUTH, "v2": os.path.join(ROOT, "testlab", "benchmark", "ground_truth_audit_v2.json"),
          "v3": os.path.join(ROOT, "testlab", "benchmark", "ground_truth_audit_v3.json")}


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


def _is_same_class(f: dict, decoy: dict) -> bool:
    """所見がdecoyの『似せている種類』の指摘か。判定は**CWE(rule_id)と所見のタイトル(description)だけ**。

    本文(analysis/snippet)は見ない: 『コマンドインジェクションではない』といった否定の文や、`literal_eval`のような
    関数名に種類のキーワードが含まれて誤って一致するため。キーワードは単語の一致で、判定は粗い近似(意味の理解ではない)。
    """
    rule = str(f.get("rule_id", "")).upper()
    if any(re.search(rf"{re.escape(c.upper())}(?!\d)", rule) for c in decoy.get("class_cwes", [])):
        return True
    title = str(f.get("description", "")).lower()
    for k in decoy.get("class_keywords", []):
        k = k.lower()
        if k.isascii():        # 英字の語は単語境界で一致(`rce`が`resource`に、`md5`が別語の一部に一致しない)
            if re.search(rf"(?<![a-z0-9_]){re.escape(k)}(?![a-z0-9_])", title):
                return True
        elif k in title:
            return True
    return False


def match_decoys(findings: list[dict], truth: dict, same_class_only: bool = False) -> dict[str, list[str]]:
    """欠陥(vulnerabilities)に当たらず、decoy(安全だが危なそうに見える箇所)の範囲に当たる所見を decoy_id 別に返す。

    欠陥の範囲と重なる所見はdecoyに数えない(欠陥の指摘として扱う)。位置不明の所見は数えない。
    `same_class_only=True`はdecoyが似せている種類の指摘だけ(別の観点の指摘は数えない。decoyの`class_cwes`/`class_keywords`)。
    """
    margin = truth.get("match_margin_lines", 0)
    out: dict[str, list[str]] = {}
    for f in findings:
        nums = set(line_numbers(f.get("location", "")))
        if any(v["lines"][0] - margin <= n <= v["lines"][1] + margin for v in truth["vulnerabilities"] for n in nums):
            continue
        for d in truth.get("decoys", []):
            if any(d["lines"][0] - margin <= n <= d["lines"][1] + margin for n in nums):
                if same_class_only and not _is_same_class(f, d):
                    continue
                out.setdefault(d["id"], []).append(f.get("description", "")[:80])
    return out


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

    def complete_structured(self, messages, schema, *a, **kw):
        self._gate(messages)                                  # 構造化出力の呼出しも回数・文字数に数える(数えないと出力0文字=無効に見える)
        data, meta = super().complete_structured(messages, schema, *a, **kw)
        self.chars_out += len(json.dumps(data, ensure_ascii=False))
        return data, meta


# 評価プロセス内だけの上書き(config.jsonは書き換えない): ローカルOllamaを使う場合のbase_urlと構造化出力
OVERRIDES: dict = {"base_url": "", "structured": False}


def run_audit_once(model: str, path: str, effort: str, max_calls: int, timeout: int = 0,
                   truth_path: str = TRUTH) -> dict:
    with open(truth_path, encoding="utf-8") as f:
        truth = json.load(f)
    config.load()
    llm = CountingLLM(base_url=OVERRIDES["base_url"] or config.get("llm_base_url"),
                      api_key="ollama" if OVERRIDES["base_url"] else config.get("llm_api_key"),
                      model=model, timeout=timeout or config.get("llm_timeout"))
    llm.limit = max_calls
    agent = AuditAgent(EventBus(), llm)
    t0 = time.time()
    err = ""
    with mock.patch.object(AuditAgent, "_save_investigation", lambda *a, **k: None), \
         mock.patch.object(AuditAgent, "_record_telemetry", lambda *a, **k: None), \
         mock.patch.dict(config._cfg, {"effort": effort, "save_evidence": False,
                                       "llm_structured": OVERRIDES["structured"]}), \
         redirect_stdout(sys.stderr):
        try:
            agent._safe_run(path=path)
        except CallLimit as e:
            err = str(e)
    res = agent._last_scan_result
    d = res.to_dict() if res else {"state": "failed", "findings": [], "errors": ["結果なし"]}
    hit, extra = match(d.get("findings", []), truth)
    decoys = match_decoys(d.get("findings", []), truth)
    decoys_same = match_decoys(d.get("findings", []), truth, same_class_only=True)
    decoy_texts = [{"decoy": i, "rule_id": f.get("rule_id", ""), "description": f.get("description", "")[:300]}
                   for f in d.get("findings", []) for i in decoys
                   if any(f.get("description", "")[:80] == x for x in decoys[i])]          # 判定の根拠を後から読めるよう全文(300字)を残す
    extra = [e for e in extra if not any(e["description"][:80] in v for v in decoys.values())]   # decoy側へ数えたものは未ラベルから外す
    return {"state": d["state"], "errors": d.get("errors", []) + ([err] if err else []),
            "n_findings": len(d.get("findings", [])), "hit": hit, "unlabeled": extra, "decoy_hits": decoys,
            "decoy_same_class_hits": decoys_same, "decoy_findings": decoy_texts,
            "llm_calls": llm.calls, "chars_in": llm.chars_in, "chars_out": llm.chars_out,
            "elapsed_s": round(time.time() - t0, 1)}


def evaluate(model: str, runs: int, effort: str, max_calls: int, timeout: int = 0, sample: str = "v1") -> dict:
    truth_path = TRUTHS[sample]
    with open(truth_path, encoding="utf-8") as f:
        truth = json.load(f)
    with open(os.path.join(ROOT, truth["source"]), encoding="utf-8") as f:
        stripped = strip_hints(f.read())
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "target_code.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(stripped)
        results, used = [], 0
        for _ in range(runs):
            r = run_audit_once(model, path, effort, max(0, max_calls - used) if max_calls else 0, timeout, truth_path)
            used += r["llm_calls"]
            results.append(r)
            if r["state"] == "failed" or any("上限" in e for e in r["errors"]):
                break
    ids = [v["id"] for v in truth["vulnerabilities"]]
    # LLMの応答が空(出力0文字)の回は、レート制限・接続失敗などで測定が成立していない。再現率0.0とは区別して集計から外す
    for r in results:
        r["invalid"] = r["chars_out"] == 0
    ok = [r for r in results if r["state"] in ("completed", "partial") and r["n_findings"] > 0 and not r["invalid"]]
    per = {i: sum(1 for r in ok if i in r["hit"]) for i in ids}
    decoy_ids = [d["id"] for d in truth.get("decoys", [])]
    return {"mode": "AUDIT", "model": model, "effort": effort, "sample": sample, "runs_requested": runs,
            "runs_done": len(results), "runs_with_findings": len(ok), "per_vuln_hits": per,
            **({"decoy_false_positives_per_run": [sorted(r["decoy_hits"]) for r in results],
                "decoy_same_class_per_run": [sorted(r["decoy_same_class_hits"]) for r in results],
                "per_decoy_hits": {i: sum(1 for r in ok if i in r["decoy_hits"]) for i in decoy_ids},
                "per_decoy_same_class_hits": {i: sum(1 for r in ok if i in r["decoy_same_class_hits"]) for i in decoy_ids}}
               if decoy_ids else {}),
            "recall_per_run": [None if r["invalid"] else round(sum(1 for i in ids if i in r["hit"]) / len(ids), 3)
                               for r in results],
            "runs_invalid": sum(1 for r in results if r["invalid"]),
            "total_llm_calls": used, "hint_stripped": True, "results": results,
            "note": "モデルと日付に依存する参考値。未ラベル所見は誤検知と断定しない。応答が空の回(invalid)は測定不成立でrecall_per_runはnull。"}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["audit", "defense", "fuzz", "attack"],
                   help="audit=ソース監査 / defense=ログ分析のLLM解釈 / fuzz=WEB FUZZのトリアージ / attack=偵察結果の解釈(tools/live_eval_modes.py)")
    p.add_argument("--model", required=True)
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--effort", choices=("speed", "balanced", "quality"), default="balanced")
    p.add_argument("--max-calls", type=int, default=30)
    p.add_argument("--timeout", type=int, default=0, help="1回のLLM呼出しのタイムアウト秒(0=config値)")
    p.add_argument("--sample", choices=sorted(TRUTHS), default="v1",
                   help="v1=samples/target_code.py(8欠陥) / v2=target_code_v2.py(8欠陥+6decoy) / v3=target_code_v3.py(8欠陥+対応する安全版8decoy)")
    p.add_argument("--base-url", default="", help="LLMのbase_urlをこのプロセス内だけで上書き(例: http://127.0.0.1:11434/v1=ローカルOllama)")
    p.add_argument("--structured", action="store_true", help="ローカルOllamaのスキーマ制約モード(llm_structured)を有効にして測る")
    p.add_argument("--save")
    a = p.parse_args(argv)
    OVERRIDES.update(base_url=a.base_url, structured=a.structured)
    if a.mode != "audit":
        from tools.live_eval_modes import evaluate_mode
        out = evaluate_mode(a.mode, a.model, a.runs, a.max_calls, a.timeout)
    else:
        out = evaluate(a.model, a.runs, a.effort, a.max_calls, a.timeout, a.sample)
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if a.save:
        with open(a.save, "w", encoding="utf-8") as f:
            f.write(text)
    print(text)


if __name__ == "__main__":
    main()
