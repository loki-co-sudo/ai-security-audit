"""P2.1: 実LLM評価(DEFENSE / WEB FUZZ / ATTACK のLLM解釈部分)。使い方は tools/live_eval.py の docstring を参照。

検出器そのもの(シグネチャ・クローラ・スキャナ)は detector固定ベンチ(tools/benchmark.py)で測る。ここでは「検出器の観測を
LLMがどう解釈するか」だけを、正解の決まった入力で測る:
  - defense: 攻撃者IPの網羅 / 攻撃者でないIPを攻撃元とする誤帰属 / MITRE IDのうち収録済みの割合 / 出力形式の遵守
  - fuzz   : fixtureの脆弱・非脆弱ページに対する報告の過不足(TP/FN/FP)
  - attack : 観測していないポートを観測したかのように述べていないか(捏造)と、観測したサービスを取り上げているか
判定は文字列・IP・ポート番号の照合で、説明の技術的な正しさや重大度の妥当性は判定しない(参考値)。
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
from contextlib import redirect_stdout
from unittest import mock
from urllib.parse import urlsplit

from tools import live_eval as le

ROOT = le.ROOT
TRUTH_DEFENSE = os.path.join(ROOT, "testlab", "benchmark", "ground_truth_defense_llm.json")
TRUTH_ATTACK = os.path.join(ROOT, "testlab", "benchmark", "ground_truth_attack_llm.json")
TRUTH_FUZZ = os.path.join(ROOT, "testlab", "benchmark", "ground_truth_web_fuzz.json")
_IP = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_FUZZ_RULES = ("XSS", "SQLI", "SSTI", "TRAVERSAL")
# FASTモデルが設定されていると、評価対象でないモデルが混ざる/資格情報が空で失敗するため、評価中は共用(空)にする
_NO_FAST = {"llm_fast_model": "", "llm_fast_base_url": "", "llm_fast_api_key": ""}


def _llm(model: str, max_calls: int, timeout: int):
    from core import config
    config.load()
    llm = le.CountingLLM(base_url=config.get("llm_base_url"), api_key=config.get("llm_api_key"), model=model,
                         timeout=timeout or config.get("llm_timeout"))
    llm.limit = max_calls
    return llm


def _finish(agent, llm, t0: float, err: str, extra: dict) -> dict:
    res = agent._last_scan_result
    d = res.to_dict() if res else {"state": "failed", "findings": [], "errors": ["結果なし"]}
    return {"state": d["state"], "errors": d.get("errors", []) + ([err] if err else []),
            "n_findings": len(d.get("findings", [])), "llm_calls": llm.calls, "chars_in": llm.chars_in,
            "chars_out": llm.chars_out, "elapsed_s": round(time.time() - t0, 1), **extra,
            "invalid": llm.chars_out == 0, "_findings": d.get("findings", []),
            # 判定の根拠を後から読めるよう、所見の位置と題名を残す(全文は保存しない)
            "findings_brief": [{"location": str(f.get("location", ""))[:160], "description": str(f.get("description", ""))[:120]}
                               for f in d.get("findings", [])]}


# ── DEFENSE ────────────────────────────────────────────────
def score_defense(findings: list[dict], errors: list[str], truth: dict) -> dict:
    from core.mitre import split_ttp
    attackers = set(truth["attackers"])
    found, wrong, known, unknown = set(), set(), 0, 0
    for f in findings:
        ips = set(_IP.findall(str(f.get("location", ""))))
        found |= ips & attackers
        wrong |= ips - attackers
        k, u = split_ttp(str(f.get("rule_id", "")))
        known, unknown = known + len(k), unknown + len(u)
    return {"attackers_found": sorted(found), "attacker_recall": round(len(found) / len(attackers), 3),
            "false_attributions": sorted(wrong), "mitre_known": known, "mitre_unverified": unknown,
            "format_note": any("脅威マーカー" in e for e in errors)}


def run_defense_once(model: str, max_calls: int, timeout: int = 0) -> dict:
    from agents.monitor_agent import MonitorAgent
    from core import config
    from core.event_bus import EventBus
    with open(TRUTH_DEFENSE, encoding="utf-8") as f:
        truth = json.load(f)
    d = tempfile.mkdtemp()
    path = os.path.join(d, "access.log")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(truth["log_lines"]) + "\n")
    llm = _llm(model, max_calls, timeout)
    agent, err, t0 = MonitorAgent(EventBus(), llm), "", time.time()
    with mock.patch.object(MonitorAgent, "_save_investigation", lambda *a, **k: None), \
         mock.patch.object(MonitorAgent, "_record_telemetry", lambda *a, **k: None), \
         mock.patch.dict(config._cfg, {"effort": "speed", "save_evidence": False, **_NO_FAST}), \
         mock.patch("agents.monitor_agent._AGGREGATION_WINDOW", 300), redirect_stdout(sys.stderr):
        try:
            agent._safe_run(log_path=path, watch_mode=False)
        except le.CallLimit as e:
            err = str(e)
    out = _finish(agent, llm, t0, err, {})
    out.update(score_defense(out["_findings"], out["errors"], truth))
    return out


# ── WEB FUZZ ───────────────────────────────────────────────
_URL = re.compile(r"https?://[^\s/]+(/[^\s?#]*)", re.I)
_BARE_PATH = re.compile(r"(?:(?<=\s)|(?<=^)|(?<=[(\[:,'\"`「（【]))(/[\w\-./]*)")


def _paths(text: str) -> set[str]:
    """文章中のURLのpathと、単独で書かれたpath(空白・括弧・引用符の直後)を取り出す。`/api/search`と`/search`は別。"""
    found = {p for p in _URL.findall(text)} | set(_BARE_PATH.findall(text))
    return {p.rstrip("/") or "/" for p in found}


def _mentions(text: str, path: str, param: str) -> bool:
    t = text.lower()
    return path.lower().rstrip("/") in _paths(t) and bool(re.search(rf"(?<![\w-]){re.escape(param.lower())}(?![\w-])", t))


def score_fuzz(findings: list[dict], truth: dict) -> dict:
    """LLMの所見が、正解のページ(脆弱/非脆弱)をどう扱ったか。所見の位置(LINES)とタイトルの文字列で照合する。"""
    cases = [c for c in truth["cases"] if c["rule_id"] in _FUZZ_RULES]
    texts = [" ".join(str(f.get(k, "")) for k in ("location", "description")) for f in findings]
    tp, fn, fp = [], [], []
    for c in cases:
        _, path, param = c["location"].split(" ")
        hit = any(_mentions(t, path, param) for t in texts)
        key = f"{c['rule_id']} {path} {param}"
        if c["expected"] == "vulnerable":
            (tp if hit else fn).append(key)
        elif hit:
            fp.append(key)
    listed = {c["location"].split(" ")[1].rstrip("/") for c in cases}
    unlisted = [t[:80] for t in texts if not (_paths(t.lower()) & {p.lower() for p in listed})]
    return {"tp": sorted(tp), "fn": sorted(fn), "fp": sorted(fp), "unlisted": unlisted,
            "recall": round(len(tp) / max(1, len(tp) + len(fn)), 3)}


def run_fuzz_once(model: str, max_calls: int, timeout: int = 0) -> dict:
    from agents.fuzz_agent import FuzzAgent
    from core import config
    from core.event_bus import EventBus
    from testlab.fixtures.web_benchmark import BenchmarkServer
    with open(TRUTH_FUZZ, encoding="utf-8") as f:
        truth = json.load(f)
    llm = _llm(model, max_calls, timeout)
    agent, err, t0 = FuzzAgent(EventBus(), llm), "", time.time()
    with BenchmarkServer() as srv, \
         mock.patch.object(FuzzAgent, "_save_investigation", lambda *a, **k: None), \
         mock.patch.object(FuzzAgent, "_record_telemetry", lambda *a, **k: None), \
         mock.patch.dict(config._cfg, {"effort": "speed", "save_evidence": False, "allowed_targets": [],
                                       "scope_mode": "warn", **_NO_FAST}), redirect_stdout(sys.stderr):
        try:
            agent._safe_run(target=srv.base_url, profile="aggressive", max_requests=1500)
        except le.CallLimit as e:
            err = str(e)
    out = _finish(agent, llm, t0, err, {})
    out.update(score_fuzz(out["_findings"], truth))
    return out


# ── ATTACK ─────────────────────────────────────────────────
_PORT_CLAIM = re.compile(r"(?<![\d.])(\d{2,5})\s*/\s*(?:tcp|udp)\b|\bport\s*(\d{2,5})\b|ポート\s*(\d{2,5})", re.I)


def score_attack(findings: list[dict], truth: dict) -> dict:
    """証拠(EVIDENCE=location)で述べられたポートが観測済みか(捏造)と、観測ポートを取り上げているか(網羅。番号またはサービス名)。"""
    open_ports = {p["port"] for p in truth["open_ports"]}
    claimed, covered = set(), set()
    for f in findings:
        for m in _PORT_CLAIM.finditer(str(f.get("location", ""))):
            claimed.add(int(next(g for g in m.groups() if g)))
        blob = " ".join(str(f.get(k, "")) for k in ("location", "description", "analysis", "snippet"))
        covered |= {p for p in open_ports if re.search(rf"(?<![\d.]){p}(?![\d.])", blob)}
        low = blob.lower()
        covered |= {e["port"] for e in truth["open_ports"] if any(k.lower() in low for k in e.get("coverage_keywords", []))}
    return {"claimed_ports_in_evidence": sorted(claimed), "fabricated_ports": sorted(claimed - open_ports),
            "covered_ports": sorted(covered), "port_coverage": round(len(covered) / len(open_ports), 3)}


class _StubScanner:
    def __init__(self, truth):
        self.truth = truth

    def resolve(self, target):
        return self.truth["host"], self.truth["ip"]

    def scan(self, host):
        return [dict(p) for p in self.truth["open_ports"]]

    def scan_udp(self, host, ports):
        return []


class _StubProber:
    truth = None

    def __init__(self, *a, **k):
        import requests
        self.session = requests.Session()

    def probe(self, base_url, on_progress=None, capture_body=False):
        w = self.truth["web"]
        return {"url": base_url, "status_code": w["status_code"], "headers": dict(w["headers"]),
                "missing_headers": list(w["missing_headers"]), "technologies": list(w["technologies"]),
                "found_paths": [dict(p) for p in w["found_paths"]], "ssl_info": w["ssl_info"],
                "cookies": [dict(c) for c in w["cookies"]], "forms_info": list(w["forms_info"]), "body": None,
                "soft_404": w["soft_404"]}


def run_attack_once(model: str, max_calls: int, timeout: int = 0) -> dict:
    """スキャナ・プローバーの応答を固定(通信なし)して、ReconAgentのLLM解釈部分だけを測る。"""
    from agents.recon_agent import ReconAgent
    from core import config
    from core.event_bus import EventBus
    with open(TRUTH_ATTACK, encoding="utf-8") as f:
        truth = json.load(f)
    _StubProber.truth = truth
    llm = _llm(model, max_calls, timeout)
    agent, err, t0 = ReconAgent(EventBus(), llm), "", time.time()
    with mock.patch("agents.recon_agent.NetworkScanner.from_profile", lambda *a, **k: _StubScanner(truth)), \
         mock.patch("agents.recon_agent.WebProber", _StubProber), \
         mock.patch("agents.recon_agent.passive_os_fingerprint", lambda *a, **k: ""), \
         mock.patch.object(ReconAgent, "_save_investigation", lambda *a, **k: None), \
         mock.patch.object(ReconAgent, "_record_telemetry", lambda *a, **k: None), \
         mock.patch.dict(config._cfg, {"effort": "speed", "save_evidence": False, "allowed_targets": [truth["ip"], truth["host"]],
                                       "scope_mode": "block", **_NO_FAST}), redirect_stdout(sys.stderr):
        try:
            # 対象はIP(TEST-NET)にする: ドメイン名だとPhase 0のcrt.sh(受動サブドメイン列挙)が外部へ通信する
            agent._safe_run(target="http://" + truth["ip"], scan_web=True, intensity="aggressive", generate_exploit=False)
        except le.CallLimit as e:
            err = str(e)
    out = _finish(agent, llm, t0, err, {})
    out.update(score_attack(out["_findings"], truth))
    return out


RUNNERS = {"defense": run_defense_once, "fuzz": run_fuzz_once, "attack": run_attack_once}


def evaluate_mode(mode: str, model: str, runs: int, max_calls: int, timeout: int = 0) -> dict:
    results, used = [], 0
    for _ in range(runs):
        r = RUNNERS[mode](model, max(0, max_calls - used) if max_calls else 0, timeout)
        r.pop("_findings", None)
        used += r["llm_calls"]
        results.append(r)
        if r["state"] == "failed" or any("上限" in e for e in r["errors"]):
            break
    valid = [r for r in results if not r["invalid"]]
    summary: dict = {"mode": mode.upper(), "model": model, "effort": "speed", "runs_requested": runs, "runs_done": len(results),
                     "runs_invalid": len(results) - len(valid), "total_llm_calls": used, "results": results,
                     "note": "モデルと日付に依存する参考値。判定は文字列/IP/ポート番号の照合で、説明の正しさは判定しない。"
                             "応答が空の回(invalid)は測定不成立。"}
    if mode == "defense":
        summary["attacker_recall_per_run"] = [None if r["invalid"] else r["attacker_recall"] for r in results]
        summary["false_attributions_per_run"] = [r["false_attributions"] for r in valid]
    elif mode == "fuzz":
        summary["recall_per_run"] = [None if r["invalid"] else r["recall"] for r in results]
        summary["false_positive_pages_per_run"] = [r["fp"] for r in valid]
    else:
        summary["port_coverage_per_run"] = [None if r["invalid"] else r["port_coverage"] for r in results]
        summary["fabricated_ports_per_run"] = [r["fabricated_ports"] for r in valid]
    return summary
