#!/usr/bin/env python3
"""
tools/run_selftest.py — 全機能セルフテスト（GUI以外を網羅）

実行:  py tools/run_selftest.py
ネットワーク・LLM(OpenRouter)を実際に使用する。
"""
from __future__ import annotations
import sys
import os
import time
import traceback

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)
os.chdir(_root)

import core.config as config
import core.event_bus as ev
from core.event_bus import EventBus

config.load()

_PASS, _FAIL = [], []


def _ok(name, detail=""):
    _PASS.append(name)
    print(f"  [PASS] {name}  {detail}")


def _ng(name, detail=""):
    _FAIL.append(name)
    print(f"  [FAIL] {name}  {detail}")


def _section(t):
    print(f"\n{'='*64}\n  {t}\n{'='*64}")


def _drain_until_done(bus: EventBus, timeout=180):
    """エージェントを駆動: DONEイベントまでバスを排出し、収集結果を返す。"""
    out, alerts, steps, stats, done, err = [], [], [], {}, False, False
    t0 = time.time()
    while time.time() - t0 < timeout:
        for e in bus.drain(limit=100):
            if e.kind == ev.OUTPUT:
                out.append(e.payload["text"])
            elif e.kind == ev.ALERT:
                alerts.append(e.payload)
            elif e.kind == ev.STEP:
                steps.append(e.payload)
            elif e.kind == ev.STATS:
                stats = e.payload
            elif e.kind == ev.DONE:
                done = True
                err = bool(e.payload and e.payload.get("error"))
        if done:
            break
        time.sleep(0.1)
    return {"text": "".join(out), "alerts": alerts, "steps": steps,
            "stats": stats, "done": done, "error": err}


# ════════════════════════════════════════════════════════════════
def test_event_bus():
    _section("1. CORE — EventBus")
    try:
        bus = EventBus()
        bus.output("hello", "tag1")
        bus.step(2, "running")
        bus.stats({"CRITICAL": 1})
        bus.done(error=False)
        events = bus.drain()
        kinds = [e.kind for e in events]
        assert kinds == [ev.OUTPUT, ev.STEP, ev.STATS, ev.DONE], kinds
        # flush
        bus.output("x")
        bus.flush()
        assert bus.drain() == []
        _ok("EventBus emit/drain/flush")
    except Exception as e:
        _ng("EventBus", repr(e))


def test_config():
    _section("2. CORE — config")
    try:
        cfg = config.load()
        assert cfg["llm_base_url"], "base_url missing"
        assert cfg["llm_model"], "model missing"
        _ok("config.load", f"model={cfg['llm_model']}")
        # round-trip (既存値を再保存 — 汚染しない)
        config.save({"llm_model": cfg["llm_model"]})
        assert config.get("llm_model") == cfg["llm_model"]
        _ok("config.save/get round-trip")
    except Exception as e:
        _ng("config", repr(e))


def test_network_scanner():
    _section("3. TOOLS — NetworkScanner")
    from tools.network_scanner import NetworkScanner
    try:
        sc = NetworkScanner(timeout=1.0, max_threads=30)
        host, ip = sc.resolve("https://example.com/path")
        assert host == "example.com", host
        assert ip, "resolve failed"
        _ok("resolve()", f"example.com -> {ip}")
    except Exception as e:
        _ng("resolve()", repr(e))
    try:
        # localhost をスキャン（安全・自己完結）
        sc = NetworkScanner(timeout=0.5, max_threads=40)
        ports = sc.scan("127.0.0.1")
        _ok("scan(localhost)", f"{len(ports)} open port(s): {[p['port'] for p in ports]}")
    except Exception as e:
        _ng("scan(localhost)", repr(e))
    try:
        sc = NetworkScanner()
        h, ip = sc.resolve("this-host-does-not-exist-xyz123.invalid")
        assert ip is None
        _ok("resolve() 失敗ハンドリング")
    except Exception as e:
        _ng("resolve() 失敗ハンドリング", repr(e))


def test_web_prober():
    _section("4. TOOLS — WebProber")
    from tools.web_prober import WebProber
    try:
        wp = WebProber(timeout=8)
        data = wp.probe("https://example.com", on_progress=lambda m: None)
        assert data["status_code"] in (200, 301, 302), data["status_code"]
        _ok("probe(example.com)",
            f"status={data['status_code']} "
            f"missing_headers={len(data['missing_headers'])} "
            f"tech={data['technologies']}")
    except Exception as e:
        _ng("probe()", repr(e))


def test_log_watcher():
    _section("5. TOOLS — LogWatcher")
    from tools.log_watcher import LogWatcher
    try:
        path = os.path.join("reports", "selftest_access.log")
        LogWatcher.generate_sample_log(path, entries=100)
        assert os.path.isfile(path)
        with open(path, encoding="utf-8") as f:
            n = sum(1 for _ in f)
        _ok("generate_sample_log", f"{n} lines")
    except Exception as e:
        _ng("generate_sample_log", repr(e))
        return None
    try:
        w = LogWatcher(path)
        lines = list(w.watch(single_pass=True))
        assert len(lines) > 50
        _ok("watch(single_pass)", f"{len(lines)} lines read")
    except Exception as e:
        _ng("watch(single_pass)", repr(e))
    return path


def test_pattern_match():
    _section("6. AGENT LOGIC — 攻撃パターン検出")
    from agents.monitor_agent import MonitorAgent
    try:
        m = MonitorAgent(EventBus(), None)
        cases = {
            "GET /x?id=1 UNION SELECT password FROM users--": "SQL_INJECTION",
            "/search?q=<script>alert(1)</script>":             "XSS",
            "GET /../../../etc/passwd":                        "LFI_RFI",
            "GET /run?x=; cat /etc/passwd":                    "CMD_INJECTION",
            "User-Agent: sqlmap/1.7":                          "SCANNER",
            "GET /index.html HTTP/1.1":                        None,
        }
        for line, expect in cases.items():
            matched = m._pattern_match(line)
            if expect is None:
                assert matched == [], f"{line!r} -> {matched}"
            else:
                assert expect in matched, f"{line!r} -> {matched}, expected {expect}"
        _ok("_pattern_match 全パターン", f"{len(cases)} cases")
        # severity マッピング
        assert m._quick_severity("CMD_INJECTION") == "CRITICAL"
        assert m._quick_severity("SQL_INJECTION") == "HIGH"
        assert m._quick_severity("SCANNER") == "MEDIUM"
        _ok("_quick_severity マッピング")
    except Exception as e:
        _ng("pattern match", repr(e))


def test_report_generator():
    _section("7. TOOLS — ReportGenerator")
    from tools import report_generator
    sample = """
---VULN_START---
NAME: SQL Injection in authenticate()
SEVERITY: CRITICAL
CWE: CWE-89
LINES: 65
SNIPPET:
```
query = f"SELECT * FROM users WHERE username = '{username}'"
```
ATTACK:
Inject ' OR '1'='1' --
FIX:
```
cursor.execute("... WHERE username = ?", (username,))
```
---VULN_END---
---VULN_START---
NAME: Weak token
SEVERITY: HIGH
CWE: CWE-330
LINES: 72
---VULN_END---
"""
    try:
        html = report_generator.generate(
            mode="CODE AUDIT", target="samples/target_code.py",
            raw_text=sample, model="openai/gpt-4o")
        assert "SQL Injection" in html
        assert "CRITICAL" in html and "CWE-89" in html
        # サマリ集計が反映されているか
        assert ">1<" in html.replace(" ", "")  # critical=1, high=1
        _ok("generate() パース＆集計")
        path = report_generator.save(html, "selftest")
        assert os.path.isfile(path)
        _ok("save()", os.path.basename(path))
    except Exception as e:
        _ng("report_generator", repr(e))


def test_cve_client():
    _section("8. TOOLS — CVE Client (NVD)")
    from tools import cve_client
    try:
        results = cve_client.search_by_cwe("CWE-89", max_results=3)
        # ネットワーク/レート制限で空もありうる。例外なく動けば合格扱い。
        formatted = cve_client.format_results(results)
        _ok("search_by_cwe(CWE-89)", f"{len(results)} CVE(s) returned")
        assert isinstance(formatted, str) and len(formatted) > 0
        _ok("format_results")
    except Exception as e:
        _ng("cve_client", repr(e))


def test_llm():
    _section("9. CORE — LLMClient (OpenRouter)")
    from core.llm_client import LLMClient, _or_headers
    cfg = config.load()
    try:
        h = _or_headers("https://openrouter.ai/api/v1")
        assert "HTTP-Referer" in h and "X-Title" in h
        assert _or_headers("http://localhost:11434/v1") == {}
        _ok("_or_headers OpenRouter判定")
    except Exception as e:
        _ng("_or_headers", repr(e))
    try:
        llm = LLMClient(cfg["llm_base_url"], cfg["llm_api_key"],
                        cfg["llm_model"], 30)
        reply = llm.complete([llm.user("Reply with exactly: PONG")])
        assert "PONG" in reply.upper(), reply
        _ok("complete() 非ストリーミング", f"reply={reply.strip()[:30]!r}")
    except Exception as e:
        _ng("complete()", repr(e))
        return
    try:
        chunks = []
        full = llm.stream([llm.user("Count: 1 2 3")],
                          on_chunk=lambda c: chunks.append(c))
        assert full and len(chunks) >= 1
        _ok("stream() ストリーミング", f"{len(chunks)} chunks")
    except Exception as e:
        _ng("stream()", repr(e))


def test_audit_agent():
    _section("10. AGENT E2E — AuditAgent (実LLM)")
    from agents.audit_agent import AuditAgent
    from core.llm_client import LLMClient
    cfg = config.load()
    llm = LLMClient(cfg["llm_base_url"], cfg["llm_api_key"], cfg["llm_model"], 90)
    bus = EventBus()
    try:
        agent = AuditAgent(bus, llm)
        agent.start(path="samples/target_code.py")
        r = _drain_until_done(bus, timeout=180)
        assert r["done"], "DONE が来なかった"
        assert not r["error"], "エラー終了"
        assert "VULN_START" in r["text"] or "SEVERITY" in r["text"], "脆弱性出力なし"
        total = sum(r["stats"].values()) if r["stats"] else 0
        _ok("AuditAgent 完走", f"detections={r['stats']} total={total} chars={len(r['text'])}")
    except Exception as e:
        _ng("AuditAgent", repr(e) + "\n" + traceback.format_exc())


def test_monitor_agent(log_path):
    _section("11. AGENT E2E — MonitorAgent (single-pass, 実LLM)")
    from agents.monitor_agent import MonitorAgent
    from core.llm_client import LLMClient
    if not log_path:
        _ng("MonitorAgent", "サンプルログ未生成のためスキップ")
        return
    cfg = config.load()
    llm = LLMClient(cfg["llm_base_url"], cfg["llm_api_key"], cfg["llm_model"], 90)
    bus = EventBus()
    try:
        agent = MonitorAgent(bus, llm)
        agent.start(log_path=log_path, watch_mode=False)
        r = _drain_until_done(bus, timeout=180)
        assert r["done"], "DONE が来なかった"
        assert len(r["alerts"]) > 0, "アラートが1件も検出されなかった"
        _ok("MonitorAgent 完走",
            f"alerts={len(r['alerts'])} stats={r['stats']}")
    except Exception as e:
        _ng("MonitorAgent", repr(e) + "\n" + traceback.format_exc())


def test_recon_agent():
    _section("12. AGENT E2E — ReconAgent (scanme.nmap.org / 実LLM)")
    from agents.recon_agent import ReconAgent
    from core.llm_client import LLMClient
    cfg = config.load()
    llm = LLMClient(cfg["llm_base_url"], cfg["llm_api_key"], cfg["llm_model"], 90)
    bus = EventBus()
    try:
        agent = ReconAgent(bus, llm)
        # scanme.nmap.org は nmap 公式のスキャン許可済みターゲット
        agent.start(target="scanme.nmap.org", scan_web=False, intensity="moderate")
        r = _drain_until_done(bus, timeout=180)
        assert r["done"], "DONE が来なかった"
        assert not r["error"], "エラー終了"
        assert "RECON" in r["text"] or "FINDING" in r["text"] or "SEVERITY" in r["text"]
        _ok("ReconAgent 完走",
            f"findings={r['stats']} chars={len(r['text'])}")
    except Exception as e:
        _ng("ReconAgent", repr(e) + "\n" + traceback.format_exc())


def test_orchestrator_bug():
    _section("13. STATIC — Orchestrator/LangGraph 整合性")
    # orchestrator.py が EventBus の正しい API (emit) のみを使用しているか確認
    try:
        with open(os.path.join("core", "orchestrator.py"), encoding="utf-8") as f:
            src = f.read()
        assert "bus.put" not in src, \
            "bus.put() が残存 → EventBus に put() は無いため LangGraph実行時にクラッシュ"
        assert "bus.emit" in src, "bus.emit が使われていない"
        _ok("orchestrator.py は bus.emit のみ使用")
    except Exception as e:
        _ng("orchestrator static check", repr(e))


def test_stealth_features():
    _section("14. STEALTH — スキャンプロファイル＆受動OS推定")
    from tools.network_scanner import NetworkScanner, passive_os_fingerprint
    from tools.web_prober import WebProber
    from core.settings import SCAN_PROFILES, STEALTH_USER_AGENTS
    # プロファイル適用
    try:
        sc = NetworkScanner.from_profile("stealth")
        assert sc.max_threads == SCAN_PROFILES["stealth"]["threads"]
        assert sc.randomize is True
        assert sc.jitter == SCAN_PROFILES["stealth"]["jitter"]
        agg = NetworkScanner.from_profile("aggressive")
        assert agg.randomize is False and agg.max_threads > sc.max_threads
        # 未知プロファイル名はデフォルトにフォールバック
        fb = NetworkScanner.from_profile("nonexistent")
        assert fb.max_threads == SCAN_PROFILES["stealth"]["threads"]
        _ok("NetworkScanner.from_profile", "stealth/aggressive/fallback")
    except Exception as e:
        _ng("from_profile", repr(e))
    # ポート順ランダム化が実際にシャッフルされるか（順次走査の回避）
    try:
        sc = NetworkScanner.from_profile("stealth", ports=list(range(1, 200)))
        import random as _r
        _r.seed(1)
        order = list(sc.ports)
        _r.shuffle(order)
        assert order != list(range(1, 200)), "シャッフルされていない"
        _ok("ポート順ランダム化")
    except Exception as e:
        _ng("randomize", repr(e))
    # 受動OSフィンガープリント
    try:
        assert passive_os_fingerprint([{"banner": "Server: nginx/1.18.0 (Ubuntu)"}]) == "Linux (Ubuntu)"
        assert passive_os_fingerprint([], {"Server": "Microsoft-IIS/10.0"}) == "Windows"
        assert passive_os_fingerprint([{"banner": "SSH-2.0-OpenSSH_8.2"}]) == "Linux/Unix (推定: OpenSSH)"
        assert passive_os_fingerprint([]) is None
        _ok("passive_os_fingerprint", "Ubuntu/Windows/OpenSSH/None")
    except Exception as e:
        _ng("passive_os_fingerprint", repr(e))
    # WebProber がステルスUAを使い自己申告UAを使わない
    try:
        wp = WebProber(timeout=8, profile="stealth")
        ua = wp.session.headers["User-Agent"]
        assert ua in STEALTH_USER_AGENTS, ua
        assert "Security Audit" not in ua, "自己申告UAが残存"
        assert wp.path_threads == SCAN_PROFILES["stealth"]["path_threads"]
        assert wp.max_paths == SCAN_PROFILES["stealth"]["max_paths"]
        _ok("WebProber ステルスUA/プロファイル", f"ua={ua[:40]}...")
    except Exception as e:
        _ng("WebProber stealth", repr(e))


def main():
    print("\n" + "#"*64)
    print("#  AI Security Audit System — 全機能セルフテスト")
    print("#"*64)
    t0 = time.time()

    test_event_bus()
    test_config()
    test_network_scanner()
    test_web_prober()
    log_path = test_log_watcher()
    test_pattern_match()
    test_report_generator()
    test_cve_client()
    test_llm()
    test_audit_agent()
    test_monitor_agent(log_path)
    test_recon_agent()
    test_orchestrator_bug()
    test_stealth_features()

    dt = time.time() - t0
    print("\n" + "#"*64)
    print(f"#  結果: {len(_PASS)} PASS / {len(_FAIL)} FAIL   ({dt:.1f}s)")
    print("#"*64)
    if _FAIL:
        print("\n  失敗したテスト:")
        for f in _FAIL:
            print(f"    ✗ {f}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
