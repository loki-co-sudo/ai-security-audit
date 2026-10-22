"""実験(製品には組み込まない): Ollamaのformat(JSONスキーマ)で、ローカル小型モデルにAUDITの所見を構造化出力させる。

huginn(~/projects/huginn/ollama_client.py)と同じ手法(スキーマ制約つき生成・think無効)を、AUDITの評価サンプルに当てて、
出力形式の遵守と検出品質を測る。ローカルのOllamaだけを使い、外部へは送らない(無料)。
  python tools/experiments/ollama_structured_audit.py {v1|v2|v3} MODEL OUT.json
結果は参考値(1回・temperature=0)。評価の判定は tools/live_eval.py と同じ(行範囲の重なり・decoyの同種判定)。
"""
import sys, json, time, re, urllib.request
import os
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from tools import live_eval as le
sample, model, out = sys.argv[1], sys.argv[2], sys.argv[3]
truth = json.load(open(le.TRUTHS[sample], encoding="utf-8"))
src = le.strip_hints(open(os.path.join(ROOT, truth["source"]), encoding="utf-8").read())
numbered = "\n".join(f"{i}| {l}" for i, l in enumerate(src.splitlines(), 1))
schema = {"type": "object", "required": ["findings"], "properties": {"findings": {"type": "array", "items": {
    "type": "object", "required": ["name", "severity", "cwe", "lines", "explanation"], "properties": {
        "name": {"type": "string"}, "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "cwe": {"type": "string"}, "lines": {"type": "string", "description": "affected line range like 12-20"},
        "explanation": {"type": "string"}}}}}}
system = ("You are a white-hat code auditor. Find real security vulnerabilities, including logic flaws, in the code. "
          "Each line is prefixed with its line number. Report only vulnerabilities that actually exist; do not report code that is safe. "
          "For each, give the affected line range in `lines`.")
body = {"model": model, "stream": False, "think": False, "format": schema,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": "```python\n" + numbered + "\n```"}],
        "options": {"num_ctx": 12288, "temperature": 0}}
t0 = time.time()
req = urllib.request.Request("http://127.0.0.1:11434/api/chat", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
raw = json.load(urllib.request.urlopen(req, timeout=3000))
text = raw["message"]["content"]
try:
    findings = json.loads(text)["findings"]; ok = True
except Exception:
    findings, ok = [], False
fs = [{"location": f.get("lines", ""), "description": f.get("name", ""), "rule_id": f.get("cwe", ""), "analysis": f.get("explanation", "")} for f in findings]
hit, extra = le.match(fs, truth)
dec = le.match_decoys(fs, truth)
dec_same = le.match_decoys(fs, truth, same_class_only=True)
res = {"model": model, "sample": sample, "parsed_ok": ok, "n_findings": len(fs), "recall": round(len([v for v in truth["vulnerabilities"] if v["id"] in hit]) / len(truth["vulnerabilities"]), 3),
       "hit": sorted(hit), "decoy_overlap": sorted(dec), "decoy_same_class": sorted(dec_same), "unlabeled": len(extra),
       "elapsed_s": round(time.time() - t0), "prompt_tokens": raw.get("prompt_eval_count"), "out_tokens": raw.get("eval_count"),
       "findings_brief": [{"lines": f.get("lines"), "name": f.get("name"), "cwe": f.get("cwe")} for f in findings]}
json.dump(res, open(out, "w"), ensure_ascii=False, indent=1)
print(json.dumps({k: res[k] for k in res if k != "findings_brief"}, ensure_ascii=False))
