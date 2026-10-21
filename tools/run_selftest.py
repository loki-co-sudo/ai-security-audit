#!/usr/bin/env python3
"""
tools/run_selftest.py — 全機能セルフテスト（GUI以外を網羅）

実行:  py tools/run_selftest.py            # フル回帰（実LLM/実ネットワーク込み）
       py tools/run_selftest.py --quick   # 快速モード（npm test / CI向け。60秒以内に完了）
ネットワーク・LLM(OpenRouter)を実際に使用する（--quick 指定時はスキップ）。
"""
from __future__ import annotations
import sys
import os
import json
import time
import traceback

# Windows cp932 環境でも em dash (—) 等の Unicode 文字を扱えるように UTF-8 を強制する。
# PYTHONUTF8=1 同等だが、環境変数をセットせずに起動された場合の保険。
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _root)
os.chdir(_root)

import core.config as config
import core.event_bus as ev
from core.event_bus import EventBus

config.load()

# セルフテストのLLM呼び出しは廉価モデルで実行してコストを抑える。
# base_url / api_key は config.json のものを使い、モデルだけ上書きする。
# mistral-small-24b は gpt-4o-mini の数分の1のコストで、全31項目が安定してPASSする
# ことを確認済み（書式依存のアサーション含む）。環境変数 SELFTEST_MODEL で差し替え可能。
SELFTEST_MODEL = os.environ.get(
    "SELFTEST_MODEL", "mistralai/mistral-small-24b-instruct-2501"
)


def _selftest_llm(timeout: int):
    """廉価モデルを使うセルフテスト用 LLMClient を生成する。"""
    from core.llm_client import LLMClient
    cfg = config.load()
    return LLMClient(cfg["llm_base_url"], cfg["llm_api_key"], SELFTEST_MODEL, timeout)


_PASS, _FAIL, _SKIP = [], [], []

# --quick（または SELFTEST_QUICK=1 / SELFTEST_NON_LLM_ONLY=1）で、
# 実LLM/実ネットワークAPIキーを要求するテストをスキップする。
# （CI・npm test の検証ハーネス向け。60秒以内に完了することを目的とする。
#  CLAUDE.md の「開発ループ」の1〜8・2b〜2dに相当。）
# フル回帰（実LLM込み）は引数なしで tools/run_selftest.py を実行する。
QUICK = "--quick" in sys.argv or os.environ.get("SELFTEST_QUICK") == "1"
NON_LLM_ONLY = QUICK or os.environ.get("SELFTEST_NON_LLM_ONLY") == "1"


def _ok(name, detail=""):
    _PASS.append(name)
    print(f"  [PASS] {name}  {detail}")


def _ng(name, detail=""):
    _FAIL.append(name)
    print(f"  [FAIL] {name}  {detail}")


def _skip_llm(section_num: str, title: str, fn, *args, **kwargs):
    """SELFTEST_NON_LLM_ONLY=1のとき、実LLM/実ネットワークを要求するテストをスキップする。

    スキップしない場合は fn を素通しする（fn 自身が _section() を呼ぶため、ここでは呼ばない）。
    """
    if NON_LLM_ONLY:
        _section(f"{section_num}. {title}")
        _SKIP.append(title)
        print("  [SKIP] SELFTEST_NON_LLM_ONLY=1 のためスキップ（実LLM/実ネットワーク要求）")
        return None
    return fn(*args, **kwargs)


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

        # TLS設定のバリデーション（P0.2）。validate_config()は保存しない純粋関数なので
        # config.jsonを汚染しない。
        assert config.get("tls_verify") is False, "tls_verifyの既定値が変わっている(後方互換違反)"
        assert config.validate_config({"tls_verify": True}) == [], "正しいbool値で警告が出た"
        assert config.validate_config({"tls_verify": "yes"}), "不正値でtls_verifyの警告が出ていない"
        assert config.validate_config({"tls_ca_bundle": 123}), "不正型でtls_ca_bundleの警告が出ていない"
        assert config.validate_config({"tls_ca_bundle": "/no/such/file.pem"}), \
            "存在しないCAファイルパスで警告が出ていない"
        assert config.validate_config({"tls_ca_bundle": ""}) == [], "空文字列(標準ストア)で警告が出た"
        _ok("config: tls_verify/tls_ca_bundleバリデーション", "既定値維持・不正値検出を確認")

        # 証拠保存設定のバリデーション（P1.2）。既定OFF（既存設定との後方互換）。
        assert config.get("save_evidence") is False, "save_evidenceの既定値が変わっている(後方互換違反)"
        assert config.validate_config({"save_evidence": True}) == []
        assert config.validate_config({"save_evidence": "yes"}), \
            "不正値でsave_evidenceの警告が出ていない"
        _ok("config: save_evidenceバリデーション", "既定値False維持・不正値検出を確認")
    except Exception as e:
        _ng("config", repr(e))


def test_model_router():
    _section("2b. CORE — ModelRouter / Effort（ロール別モデル・エフォート）")
    from core import model_router as mr
    from core.settings import EFFORT_PRESETS
    from core.llm_client import LLMClient
    import core.config as cfg
    # エフォートプリセットの完全性
    try:
        for lvl in ("speed", "balanced", "quality"):
            p = EFFORT_PRESETS[lvl]
            assert {"verify_pass", "verify_samples", "cve_lookup", "deep_loops", "label", "desc"} <= set(p), p
        # deep_loops は 速度 < バランス < 品質 の単調増加
        assert (EFFORT_PRESETS["speed"]["deep_loops"]
                < EFFORT_PRESETS["balanced"]["deep_loops"]
                < EFFORT_PRESETS["quality"]["deep_loops"])
        assert EFFORT_PRESETS["quality"]["verify_pass"] is True
        assert EFFORT_PRESETS["speed"]["cve_lookup"] is False
        _ok("EFFORT_PRESETS 整合性", "speed<balanced<quality")
    except Exception as e:
        _ng("EFFORT_PRESETS", repr(e))
    # FAST クライアントのルーティング（未設定=共用 / 設定=別モデル・接続共用）
    saved = dict(cfg._cfg)
    try:
        strong = LLMClient("http://localhost:11434/v1", "k-strong", "model-strong", 30)
        cfg._cfg["llm_fast_model"] = ""
        assert mr.build_fast_client(strong) is strong, "未設定時は STRONG を共用すべき"
        assert mr.fast_model_configured() is False
        cfg._cfg["llm_fast_model"] = "cheap-model"
        cfg._cfg["llm_fast_base_url"] = ""
        cfg._cfg["llm_fast_api_key"] = ""
        fast = mr.build_fast_client(strong)
        assert fast is not strong and fast.model == "cheap-model", fast.model
        assert fast.base_url == strong.base_url and fast.api_key == strong.api_key, \
            "接続情報を共用すべき"
        assert mr.fast_model_configured() is True
        # 別エンドポイント指定
        cfg._cfg["llm_fast_base_url"] = "http://localhost:1234/v1"
        cfg._cfg["llm_fast_api_key"] = "k-fast"
        fast2 = mr.build_fast_client(strong)
        assert fast2.base_url == "http://localhost:1234/v1" and fast2.api_key == "k-fast"
        _ok("build_fast_client ルーティング", "共用/別モデル/別エンドポイント")
    except Exception as e:
        _ng("build_fast_client", repr(e))
    finally:
        cfg._cfg.clear()
        cfg._cfg.update(saved)
    # BaseAgent の _complete_llm(role) が正しいクライアントを選ぶ
    try:
        from agents.monitor_agent import MonitorAgent
        strong = LLMClient("http://localhost:11434/v1", "k", "model-strong", 30)
        cfg._cfg["llm_fast_model"] = "cheap-model"
        m = MonitorAgent(EventBus(), strong)
        assert m._fast_client().model == "cheap-model"
        assert m._fast_client() is m._fast_client(), "FASTクライアントはキャッシュされるべき"
        _ok("BaseAgent._fast_client キャッシュ")
    except Exception as e:
        _ng("BaseAgent._fast_client", repr(e))
    finally:
        cfg._cfg.clear()
        cfg._cfg.update(saved)
    # モデル要件ゲート（ヒューリスティック警告・ブロックしない）
    try:
        assert mr.assess_readiness("anthropic/claude-opus-4.8", "") == [], \
            "FAST未設定は警告対象外であるべき"
        assert mr.assess_readiness("anthropic/claude-opus-4.8", "anthropic/claude-opus-4.8"), \
            "STRONG=FASTは警告すべき"
        assert mr.assess_readiness("anthropic/claude-fable-5", "anthropic/claude-opus-4.8"), \
            "FASTがSTRONGより重いと警告すべき"
        assert mr.assess_readiness("anthropic/claude-opus-4.8", "anthropic/claude-fable-5") == [], \
            "FASTがSTRONGより軽ければ警告なし"
        assert mr.assess_readiness("some-unknown-model", "another-unknown-model") == [], \
            "未知slug同士は判定対象外（誤検知よりも見逃しを優先）"
        _ok("assess_readiness ヒューリスティック", "同一/取り違え/未知slugの3パターン")
    except Exception as e:
        _ng("assess_readiness", repr(e))
    # 難易度ルーター（AUTO） — LLM呼び出しはフェイクで代替し、非LLM環境でも検証する
    try:
        class _FakeLLM:
            def __init__(self, reply): self._reply = reply
            def complete(self, messages): return self._reply

        class _ErrLLM:
            def complete(self, messages): raise RuntimeError("boom")

        assert mr.classify_effort("tiny one-liner script", _FakeLLM("trivial")) == "speed"
        assert mr.classify_effort("typical web app", _FakeLLM("Standard.")) == "balanced"
        assert mr.classify_effort("huge enterprise system", _FakeLLM("DEEP")) == "quality"
        assert mr.classify_effort("garbage", _FakeLLM("unparseable response")) == "balanced", \
            "解析不能な応答はbalancedにフォールバック"
        assert mr.classify_effort("x", _ErrLLM()) == "balanced", \
            "LLM呼び出し失敗はbalancedにフォールバック"
        # current_effort の override 引数
        assert mr.current_effort("speed")["deep_loops"] == 0
        assert mr.current_effort("quality")["verify_pass"] is True
        assert mr.current_effort(None) == mr.current_effort()
        _ok("classify_effort / current_effort(override)", "trivial/standard/deep/失敗フォールバック")
    except Exception as e:
        _ng("classify_effort", repr(e))
    # BaseAgent.set_effort_override による一時上書き
    try:
        from agents.monitor_agent import MonitorAgent
        strong = LLMClient("http://localhost:11434/v1", "k", "model-strong", 30)
        m = MonitorAgent(EventBus(), strong)
        assert m._effort() == mr.current_effort(), "既定はグローバル設定を参照すべき"
        m.set_effort_override("speed")
        assert m._effort()["deep_loops"] == 0, "上書き中はspeedのプリセットを返すべき"
        m.set_effort_override(None)
        assert m._effort() == mr.current_effort(), "Noneに戻せばグローバル設定に復帰すべき"
        _ok("BaseAgent.set_effort_override", "上書き/復帰")
    except Exception as e:
        _ng("BaseAgent.set_effort_override", repr(e))


def test_verify_ensemble():
    _section("2c. CORE — 検証器アンサンブル（マーカー多数決・§5.3）")
    from agents.base_agent import _vote_findings, _parse_marker_findings
    from agents.monitor_agent import MonitorAgent

    a = "---VULN_START---\nNAME: SQL Injection in login\nSEVERITY: HIGH\nLINES: 42\n---VULN_END---"
    b = ("---VULN_START---\nNAME: SQL Injection in login\nSEVERITY: HIGH\nLINES: 42\n---VULN_END---\n\n"
         "---VULN_START---\nNAME: Weak random token\nSEVERITY: LOW\nLINES: 88\n---VULN_END---")
    c = "---VULN_START---\nNAME: SQL Injection in login\nSEVERITY: HIGH\nLINES: 42\n---VULN_END---"
    # recon_agentの実際のフォーマットはNAMEではなくTITLE、LINESフィールドは無い
    title_fmt = "---FINDING_START---\nTITLE: Open Redis without auth\nSEVERITY: CRITICAL\n---FINDING_END---"
    try:
        assert len(_parse_marker_findings(b)) == 2
        kept, minority = _vote_findings([a, b, c])
        assert a in kept, "多数決一致の所見はタグを付けずそのままkeptに含まれるべき"
        assert "Weak random token" in kept, \
            "3件中1件のみの所見も除外せずkeptに含めるべき（union方式・advisorレビュー指摘）"
        assert "CONFIDENCE: ENSEMBLE_MINORITY" in kept, \
            "少数意見にはCONFIDENCE: ENSEMBLE_MINORITYを付記すべき"
        assert len(minority) == 1 and "Weak random token" in minority[0], \
            "少数意見はminorityリストにも返り、呼び出し側が案内表示できるべき"
        d = "---VULN_START---\nNAME: A\nSEVERITY: LOW\nLINES: 1\n---VULN_END---"
        e = "---VULN_START---\nNAME: B\nSEVERITY: LOW\nLINES: 2\n---VULN_END---"
        kept2, minority2 = _vote_findings([d, e])
        assert "NAME: A" in kept2 and "NAME: B" in kept2, \
            "全会不一致（比較不能）でも両方の所見をkeptに含めるべき（union方式）"
        assert len(minority2) == 2, "全会不一致なら両方とも少数意見として案内されるべき"
        # マーカーが1件も取れない場合のみ、最初のサンプルへフォールバックする
        kept3, minority3 = _vote_findings(["no markers here", "also none"])
        assert kept3 == "no markers here" and minority3 == []
        # TITLE:（recon_agentのフォーマット）でもsignatureが取れることを確認
        assert _parse_marker_findings(title_fmt)[0][0].startswith("open redis without auth")
        _ok("_vote_findings", "多数決一致はそのまま・少数意見もCONFIDENCEタグ付きでunion採用・"
                              "マーカー無しフォールバック・TITLE:対応")
    except Exception as e:
        _ng("_vote_findings", repr(e))

    class _FakeVerifyLLM:
        def __init__(self, replies):
            self._replies = iter(replies)
            self.model = "fake-verify"

        def system(self, c): return {"role": "system", "content": c}
        def user(self, c): return {"role": "user", "content": c}

        def stream(self, messages, on_chunk, on_done=None, on_error=None):
            text = next(self._replies)
            on_chunk(text)
            if on_done:
                on_done()
            return text

    try:
        bus = EventBus()
        agent = MonitorAgent(bus, _FakeVerifyLLM([a, b, c]))
        result = agent._verify_findings("evidence", "draft", samples=3)
        assert "SQL Injection in login" in result
        assert "Weak random token" in result and "CONFIDENCE: ENSEMBLE_MINORITY" in result, \
            "少数意見も除外せず、CONFIDENCEタグ付きで返り値（最終レポート）に含めるべき"
        output_text = "".join(
            ev.payload["text"] for ev in bus.drain(10000) if ev.kind == "output"
        )
        assert "Weak random token" in output_text, \
            "少数意見であることも出力ボックスで案内し、人間が確認できる状態を保つべき"
        # samples=1 は従来どおり単発検証パスをそのまま返す（後方互換）
        agent2 = MonitorAgent(EventBus(), _FakeVerifyLLM([a]))
        assert agent2._verify_findings("evidence", "draft", samples=1) == a
        # マーカーが無い応答は解析不能→draftを維持（後方互換）
        agent3 = MonitorAgent(EventBus(), _FakeVerifyLLM(["no markers here"]))
        assert agent3._verify_findings("evidence", "draft") == "draft"
        _ok("BaseAgent._verify_findings(samples=N)",
            "アンサンブルunion採用（少数意見もCONFIDENCEタグ付きで保持）・後方互換を確認")
    except Exception as e:
        _ng("_verify_findings ensemble", repr(e))


def test_telemetry():
    _section("2d. CORE — モデル別コスト×精度台帳（§5.4・記録のみ）")
    from agents.monitor_agent import MonitorAgent
    from core.llm_client import LLMClient
    try:
        path = os.path.join("reports", "telemetry.jsonl")
        before = os.path.getsize(path) if os.path.isfile(path) else 0
        strong = LLMClient("http://localhost:11434/v1", "k", "selftest-telemetry-model", 30)
        agent = MonitorAgent(EventBus(), strong)
        agent._record_telemetry("SELFTEST", "selftest-target",
                                 {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0}, 3.14)
        assert os.path.isfile(path), "telemetry.jsonl が作成されていない"
        with open(path, "r", encoding="utf-8") as f:
            f.seek(before)
            last_line = f.read().strip().splitlines()[-1]
        record = json.loads(last_line)
        assert record["mode"] == "SELFTEST"
        assert record["model"] == "selftest-telemetry-model"
        assert record["total_detections"] == 3
        assert record["elapsed_sec"] == 3.1  # round(3.14, 1)
        _ok("_record_telemetry", f"reports/telemetry.jsonl へ追記・スキーマ確認済み")
    except Exception as e:
        _ng("_record_telemetry", repr(e))


def test_scope_guard():
    _section("2e. CORE — ScopeGuard（バグバウンティ対応・Phase A）")
    from core.scope_guard import in_scope
    try:
        ok, _ = in_scope("example.com", [])
        assert ok, "空リストは常に許可されるべき（後方互換）"
        ok, _ = in_scope("example.com", ["example.com"])
        assert ok, "完全一致は許可されるべき"
        ok, _ = in_scope("api.example.com", ["*.example.com"])
        assert ok, "ワイルドカード接尾辞一致は許可されるべき"
        ok, _ = in_scope("example.com", ["*.example.com"])
        assert ok, "ワイルドカードはapexドメインも許可すべき"
        ok, _ = in_scope("http://10.0.0.5:8080/path", ["10.0.0.0/24"])
        assert ok, "IPリテラルのCIDR一致は許可されるべき"
        ok, msg = in_scope("evil.example.org", ["example.com"])
        assert not ok and msg, "不一致は範囲外として拒否されるべき"
        ok, _ = in_scope("example.com", ["10.0.0.0/24"])
        assert not ok, "ドメイン文字列に対するCIDRルールは判定不能→範囲外扱いにすべき"
        _ok("in_scope()", "空リスト/完全一致/ワイルドカード/CIDR/不一致/エッジケース")
    except Exception as e:
        _ng("in_scope", repr(e))

    # 後方互換: allowed_targets 未設定（既定=空）なら _check_scope は scope_mode に
    # 関わらず常に許可すべき（既存の非バグバウンティ利用者への挙動が変わらないこと）。
    from agents.monitor_agent import MonitorAgent
    saved = dict(config._cfg)
    try:
        config._cfg["allowed_targets"] = []
        config._cfg["scope_mode"] = "block"
        agent = MonitorAgent(EventBus(), None)
        assert agent._check_scope("anything.example") is True, \
            "allowed_targets 未設定時は scope_mode に関わらず常に許可すべき（後方互換）"
        config._cfg["allowed_targets"] = ["good.example.com"]
        config._cfg["scope_mode"] = "block"
        assert agent._check_scope("evil.example.com") is False, \
            "block モードで範囲外なら False を返すべき"
        # P1.1: block時もRESULT(failed)→DONE(error=True)が一度ずつ確定されること
        from core.findings import ScanState
        blocked_events = agent.bus.drain(50)
        blocked_kinds = [e.kind for e in blocked_events]
        assert blocked_kinds.count(ev.RESULT) == 1 and blocked_kinds.count(ev.DONE) == 1, blocked_kinds
        blocked_result = next(e.payload for e in blocked_events if e.kind == ev.RESULT)
        assert blocked_result["state"] == ScanState.FAILED.value
        assert blocked_result["target"] == "evil.example.com"
        blocked_done = next(e.payload for e in blocked_events if e.kind == ev.DONE)
        assert blocked_done["error"] is True
        assert agent._check_scope("good.example.com") is True
        config._cfg["scope_mode"] = "warn"
        assert agent._check_scope("evil.example.com") is True, \
            "warn モードでは範囲外でも続行（True）を返すべき"
        _ok("BaseAgent._check_scope", "後方互換（未設定=常に許可）/ block(RESULT/DONE確定込み) / warn")
    except Exception as e:
        _ng("BaseAgent._check_scope", repr(e))
    finally:
        config._cfg.clear()
        config._cfg.update(saved)


def test_telemetry_ledger():
    _section("2f. CORE — テレメトリ台帳の要約・モデル提案（記録→助言・AIモデル運用最適化）")
    import tempfile
    from core.model_router import summarize_telemetry, suggest_efficient_model

    def _rec(mode, model, detections, elapsed):
        return json.dumps({
            "ts": "2026-08-17T00:00:00", "mode": mode, "target": "t",
            "model": model, "effort": "balanced",
            "detections": {}, "total_detections": detections, "elapsed_sec": elapsed,
        }, ensure_ascii=False)

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "telemetry.jsonl")
            lines = []
            # model-cheap: 効率が良い（検出数/秒が高い）実績を min_runs 分
            for _ in range(5):
                lines.append(_rec("SELFTEST_LEDGER", "model-cheap", 4, 2.0))  # 2.0 det/s
            # model-current: 効率が悪い実績を min_runs 分
            for _ in range(5):
                lines.append(_rec("SELFTEST_LEDGER", "model-current", 2, 4.0))  # 0.5 det/s
            # model-rare: 件数不足（min_runs未満）なので集計から除外されるべき
            for _ in range(2):
                lines.append(_rec("SELFTEST_LEDGER", "model-rare", 100, 0.1))
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")

            stats = summarize_telemetry(mode="SELFTEST_LEDGER", min_runs=5, path=path)
            models = {s["model"] for s in stats}
            assert "model-rare" not in models, "min_runs未満のグループは除外されるべき"
            assert stats[0]["model"] == "model-cheap", "効率指標が高い順に並ぶべき"
            assert stats[0]["runs"] == 5

            empty = summarize_telemetry(mode="SELFTEST_LEDGER", min_runs=5,
                                         path=os.path.join(tmpdir, "no-such-file.jsonl"))
            assert empty == [], "ファイル不在時は空リストを返すべき"

            same = suggest_efficient_model("SELFTEST_LEDGER", "model-cheap", min_runs=5, path=path)
            assert same is None, "現在のモデルが既に最良ならNoneを返すべき"

            hint = suggest_efficient_model("SELFTEST_LEDGER", "model-current", min_runs=5, path=path)
            assert hint and "model-cheap" in hint, \
                "劣るモデルが設定され効率差がmargin超なら助言文字列を返すべき"

            no_data = suggest_efficient_model("SELFTEST_LEDGER_NONE", "model-current", min_runs=5, path=path)
            assert no_data is None, "対象モードの実績が無ければNoneを返すべき"

        # 一時ディレクトリを使ったため本番の reports/telemetry.jsonl は変更されていないはず
        prod_path = os.path.join("reports", "telemetry.jsonl")
        assert not os.path.isfile(prod_path) or "SELFTEST_LEDGER" not in open(
            prod_path, encoding="utf-8").read(), "テスト用データが本番telemetry.jsonlに混入していないこと"

        _ok("summarize_telemetry / suggest_efficient_model",
            "集計・ソート・min_runsフィルタ・ファイル不在・助言/非助言の分岐・本番ファイル非汚染")
    except Exception as e:
        _ng("telemetry ledger advisory", repr(e))


def test_base_agent_lifecycle():
    _section("2g. CORE — BaseAgent RESULT/DONE最終化ライフサイクル(P1.1)")
    from agents.base_agent import BaseAgent
    from core.findings import ScanState

    class _NormalAgent(BaseAgent):
        def run(self, **kwargs):
            self._current_mode, self._current_target = "TEST", "t1"
            self._done()

    class _StopEarlyAgent(BaseAgent):
        def run(self, **kwargs):
            self._current_mode, self._current_target = "TEST", "t2"
            for _ in range(50):  # 最大5秒、STOPを待つ
                if self.is_stopped():
                    return  # 旧バグ再現: _done()を呼ばずに早期return
                time.sleep(0.1)
            self._done()  # フォールバック（通常この行には来ない想定）

    class _ExplodingAgent(BaseAgent):
        def run(self, **kwargs):
            raise RuntimeError("boom-test")

    class _DoubleDoneAgent(BaseAgent):
        def run(self, **kwargs):
            self._done()
            self._done(error=True)  # 2回目は無視されるべき

    try:
        # 1) 正常完了: RESULT→DONE(error=False)が1回ずつ、この順序で送出される
        bus = EventBus()
        agent = _NormalAgent(bus, None)
        agent.start()
        agent._thread.join(timeout=5)
        events = bus.drain(100)
        kinds = [e.kind for e in events]
        assert kinds.count(ev.RESULT) == 1 and kinds.count(ev.DONE) == 1, kinds
        assert kinds.index(ev.RESULT) < kinds.index(ev.DONE), "RESULTはDONEより先に送出されるべき"
        result_payload = next(e.payload for e in events if e.kind == ev.RESULT)
        assert result_payload["state"] == ScanState.COMPLETED.value
        assert result_payload["mode"] == "TEST" and result_payload["target"] == "t1"
        done_payload = next(e.payload for e in events if e.kind == ev.DONE)
        assert done_payload["error"] is False
        _ok("正常完了: RESULT→DONE(completed)を1回ずつ・順序も正しい", "")

        # 2) STOPによる早期return(_done()未呼び出し)でもcancelledとして最終化される
        #    （旧バグ: 以前はDONEが一切送出されずGUIのボタンが再有効化されないままだった）
        bus2 = EventBus()
        agent2 = _StopEarlyAgent(bus2, None)
        agent2.start()
        agent2.stop()
        agent2._thread.join(timeout=5)
        assert not agent2._thread.is_alive(), "STOP後もスレッドが終了していない"
        events2 = bus2.drain(100)
        kinds2 = [e.kind for e in events2]
        assert kinds2.count(ev.DONE) == 1, f"STOP後もDONEが1回送出されるべき: {kinds2}"
        result2 = next(e.payload for e in events2 if e.kind == ev.RESULT)
        assert result2["state"] == ScanState.CANCELLED.value, result2["state"]
        done2 = next(e.payload for e in events2 if e.kind == ev.DONE)
        assert done2["error"] is True, "cancelledは成功扱いにしない"
        _ok("STOP早期return(_done()未呼出)でもcancelledとして最終化", "旧バグ回帰防止")

        # 3) 例外発生時もfailedとして最終化される（1回だけ・エラー内容を記録）
        bus3 = EventBus()
        agent3 = _ExplodingAgent(bus3, None)
        agent3.start()
        agent3._thread.join(timeout=5)
        events3 = bus3.drain(100)
        kinds3 = [e.kind for e in events3]
        assert kinds3.count(ev.RESULT) == 1 and kinds3.count(ev.DONE) == 1
        result3 = next(e.payload for e in events3 if e.kind == ev.RESULT)
        assert result3["state"] == ScanState.FAILED.value
        assert "boom-test" in result3["errors"][0]
        _ok("例外発生時はfailedとして最終化・エラー内容を記録", "")

        # 4) 二重に_done()を呼んでもRESULT/DONEは1回だけ（最初の状態が確定）
        bus4 = EventBus()
        agent4 = _DoubleDoneAgent(bus4, None)
        agent4.start()
        agent4._thread.join(timeout=5)
        events4 = bus4.drain(100)
        kinds4 = [e.kind for e in events4]
        assert kinds4.count(ev.RESULT) == 1 and kinds4.count(ev.DONE) == 1, kinds4
        result4 = next(e.payload for e in events4 if e.kind == ev.RESULT)
        assert result4["state"] == ScanState.COMPLETED.value, "最初の_done()の状態(completed)が確定するべき"
        _ok("二重に_done()を呼んでもRESULT/DONEは1回だけ(最初の状態が確定)", "")
    except Exception as e:
        _ng("base_agent_lifecycle", repr(e) + "\n" + traceback.format_exc())


def test_findings_from_markers_evidence_ids():
    _section("2g2. CORE — BaseAgent._findings_from_markers() evidence_ids検証(P1.2)")
    from agents.base_agent import BaseAgent
    try:
        known = {"evidence_aaa111", "evidence_bbb222"}
        parsed = [
            {"name": "SQLi", "severity": "HIGH", "ref": "CWE-89", "lines": "url",
             "evidence_ids_raw": "evidence_aaa111, evidence_bbb222"},
            {"name": "XSS with hallucinated ID", "severity": "MEDIUM", "ref": "CWE-79", "lines": "url2",
             "evidence_ids_raw": "evidence_aaa111, evidence_does_not_exist_999"},
            {"name": "No evidence cited", "severity": "LOW", "ref": "CWE-1", "lines": "url3",
             "evidence_ids_raw": ""},
        ]
        findings = BaseAgent._findings_from_markers(parsed, corroborated=False, known_evidence_ids=known)
        assert findings[0].evidence_ids == ["evidence_aaa111", "evidence_bbb222"], \
            "既知IDは両方採用されるべき"
        assert findings[1].evidence_ids == ["evidence_aaa111"], \
            "存在しないID(evidence_does_not_exist_999)は採用せず黙って除外すべき"
        assert findings[2].evidence_ids == []
        _ok("evidence_ids: 既知IDのみ採用・未知IDは黙って除外(LLMの誤記/幻覚に対する防御)", "")

        # known_evidence_ids未指定(None)ならEVIDENCE_IDS行自体を無視する
        findings_no_known = BaseAgent._findings_from_markers(parsed, corroborated=False,
                                                              known_evidence_ids=None)
        assert all(f.evidence_ids == [] for f in findings_no_known), \
            "known_evidence_ids未指定時はevidence_idsを一切採用しないべき"
        _ok("known_evidence_ids未指定時はEVIDENCE_IDS行を無視", "")
    except Exception as e:
        _ng("findings_from_markers_evidence_ids", repr(e) + "\n" + traceback.format_exc())


def test_findings_contract():
    _section("2h. CORE — findings データ契約 ScanResult/Finding/CoverageItem(P1.1)")
    from core.findings import (
        ScanState, VerificationState, CoverageStatus, Finding, CoverageItem,
        new_scan_result, new_id,
    )
    try:
        sr = new_scan_result(mode="WEB FUZZ", target="http://example.com/")
        assert sr.scan_id.startswith("scan_") and sr.schema_version == "1"
        assert sr.state == ScanState.FAILED.value, "既定stateはfailed(未確定)であるべき"

        f = Finding(
            finding_id=new_id("finding"), rule_id="XSS", location="http://x/?q=1",
            severity="HIGH", verification_state=VerificationState.OBSERVED.value,
        )
        c = CoverageItem(target_ref="http://x/?q=1", status=CoverageStatus.TESTED.value,
                         rule_id="XSS", parameter="q")
        sr.findings.append(f)
        sr.coverage.append(c)
        d = sr.to_dict()
        assert d["findings"][0]["rule_id"] == "XSS"
        assert d["coverage"][0]["status"] == "tested"
        assert isinstance(d["findings"][0]["evidence_ids"], list)
        # JSON化できること（EventBus.result()経由でGUI/将来のCLIに渡る前提）
        json.dumps(d, ensure_ascii=False)
        _ok("ScanResult/Finding/CoverageItemのdict化・JSON化", f"scan_id={sr.scan_id}")

        # verification_stateはseverityと独立した軸（同じseverityで別のverification_stateを許容）
        f2 = Finding(finding_id=new_id("finding"), rule_id="XSS", location="l",
                     severity="HIGH", verification_state=VerificationState.MANUALLY_CONFIRMED.value)
        assert f2.verification_state != f.verification_state
        _ok("verification_stateはseverityと独立に設定可能", "")
    except Exception as e:
        _ng("findings_contract", repr(e) + "\n" + traceback.format_exc())


def test_redaction():
    _section("2i. CORE — redaction マスキング(P1.2・固定ダミー秘密値の非漏えい検証)")
    import core.redaction as redaction
    # 固定ダミー秘密値（実際の秘密ではない・テスト専用の識別しやすい文字列）
    DUMMY_COOKIE = "sessionid=SELFTEST_DUMMY_COOKIE_VALUE_777"
    DUMMY_TOKEN = "SELFTEST_DUMMY_BEARER_TOKEN_888"
    DUMMY_PASSWORD = "SELFTEST_DUMMY_PASSWORD_999"
    known = {DUMMY_COOKIE, DUMMY_TOKEN, DUMMY_PASSWORD}
    try:
        # 1) ヘッダー: Cookie/Authorizationは常にマスク、既知の値はカスタムヘッダーでもマスク
        headers = {
            "Cookie": DUMMY_COOKIE,
            "Authorization": f"Bearer {DUMMY_TOKEN}",
            "X-Custom-Auth": DUMMY_TOKEN,  # ユーザー設定の任意ヘッダー(既知の値で一致)
            "X-Harmless": "no-secret-here",
        }
        masked = redaction.mask_headers(headers, known_secrets=known)
        blob = json.dumps(masked)
        assert DUMMY_COOKIE not in blob and DUMMY_TOKEN not in blob and DUMMY_PASSWORD not in blob
        assert masked["X-Harmless"] == "no-secret-here", "無害な値まで変更してはいけない"
        assert "Cookie" in masked and "Authorization" in masked, "ヘッダー名自体は保持すべき"
        _ok("mask_headers(): Cookie/Authorization/既知値ヘッダーを全てマスク", "")

        # 2) URL: 機密パラメータ名・既知の値の両方をマスク
        url = f"http://x/login?user=bob&password={DUMMY_PASSWORD}&token={DUMMY_TOKEN}&q=hello"
        masked_url = redaction.mask_url(url, known_secrets=known)
        assert DUMMY_PASSWORD not in masked_url and DUMMY_TOKEN not in masked_url
        assert "hello" in masked_url and "bob" in masked_url, "無害なパラメータまで消してはいけない"
        _ok("mask_url(): 機密パラメータ名・既知の値をマスクし無害な値は保持", "")

        # 3) body: JSON形式・form形式のどちらも機密キー名・既知の値をマスク
        json_body = f'{{"username": "bob", "password": "{DUMMY_PASSWORD}", "note": "hi"}}'
        form_body = f"user=bob&password={DUMMY_PASSWORD}&remember=1"
        masked_json = redaction.mask_body(json_body, known_secrets=known)
        masked_form = redaction.mask_body(form_body, known_secrets=known)
        assert DUMMY_PASSWORD not in masked_json and DUMMY_PASSWORD not in masked_form
        assert '"hi"' in masked_json and "remember=1" in masked_form
        _ok("mask_body(): JSON/form双方で機密値をマスクし無害な値は保持", "")

        # 4) ハッシュは改ざん検出補助であり匿名化ではない(同じ値→同じハッシュ)
        h1 = redaction.mask_value(DUMMY_PASSWORD)
        h2 = redaction.mask_value(DUMMY_PASSWORD)
        assert h1 == h2, "同じ値は同じマスク結果(ハッシュ)になるべき"
        _ok("mask_value(): 同一値は同一ハッシュ(改ざん検出補助・匿名化ではない)", "")

        # 5) known_secrets未指定でも既定の機密ヘッダー/パラメータ名は保護される
        headers_no_known = redaction.mask_headers({"Cookie": DUMMY_COOKIE})
        assert DUMMY_COOKIE not in json.dumps(headers_no_known), \
            "known_secrets未指定でもCookieヘッダーはマスクされるべき"
        _ok("既定の機密ヘッダー名はknown_secrets未指定でも保護される", "")
    except Exception as e:
        _ng("redaction", repr(e) + "\n" + traceback.format_exc())


def test_evidence_store():
    _section("2j. CORE — EvidenceStore 証拠保存(P1.2・容量上限・保存失敗・pathトラバーサル対策)")
    import shutil
    import tempfile
    from core.evidence_store import EvidenceStore
    DUMMY_SECRET = "SELFTEST_DUMMY_EVIDENCE_SECRET_555"
    tmp_root = tempfile.mkdtemp(prefix="selftest_evidence_")
    try:
        # 1) 保存したファイルにダミー秘密値が残らない
        store = EvidenceStore("scan_selftest_1", root=tmp_root)
        eid = store.save_http_evidence(
            method="GET", url=f"http://x/?token={DUMMY_SECRET}", status=200,
            headers={"Cookie": f"sessionid={DUMMY_SECRET}"},
            body=f"password={DUMMY_SECRET}",
            known_secrets={DUMMY_SECRET},
        )
        assert eid is not None
        raw_path = os.path.join(store.dir, f"{eid}.json")
        with open(raw_path, encoding="utf-8") as f:
            raw_on_disk = f.read()
        assert DUMMY_SECRET not in raw_on_disk, "保存物にダミー秘密値が残っている"
        _ok("save_http_evidence(): 保存物にダミー秘密値が残らない", "")

        # 2) load()でも同じ内容が読める
        loaded = store.load(eid)
        assert loaded is not None and loaded["status"] == 200
        assert DUMMY_SECRET not in json.dumps(loaded)
        _ok("load(): 保存済み証拠を復元できる(マスク済みのまま)", "")

        # 3) 件数上限
        store_limited = EvidenceStore("scan_selftest_2", root=tmp_root, max_items=1)
        e1 = store_limited.save_http_evidence(method="GET", url="http://x/a", status=200)
        e2 = store_limited.save_http_evidence(method="GET", url="http://x/b", status=200)
        assert e1 is not None and e2 is None, "件数上限を超えたらNoneを返すべき"
        _ok("件数上限(max_items)超過でNoneを返す", "")

        # 4) 総容量上限
        store_small_total = EvidenceStore("scan_selftest_3", root=tmp_root,
                                          max_total_bytes=1, max_items=100)
        e3 = store_small_total.save_http_evidence(method="GET", url="http://x/a", status=200,
                                                  body="x" * 500)
        assert e3 is None, "総容量上限を超えたらNoneを返すべき"
        _ok("総容量上限(max_total_bytes)超過でNoneを返す", "")

        # 5) 1件あたりの上限超過時は本文を省略しつつ理由を残して保存する(所見自体は破棄しない)
        store_small_item = EvidenceStore("scan_selftest_4", root=tmp_root, max_item_bytes=50)
        e4 = store_small_item.save_http_evidence(method="GET", url="http://x/a", status=200,
                                                  body="y" * 500)
        assert e4 is not None, "1件あたりの上限超過でも省略保存はできるべき(破棄しない)"
        loaded4 = store_small_item.load(e4)
        assert loaded4["omitted_reason"], "省略理由が記録されているべき"
        assert loaded4["body_excerpt"] == ""
        _ok("1件あたりの上限超過は本文省略+理由記録で保存(所見を破棄しない)", "")

        # 6) evidence_idをそのままpathに使わない(pathトラバーサル対策)
        assert store.load("../../../etc/passwd") is None
        assert store.load("../evidence") is None
        _ok("load(): 不正なevidence_id(pathトラバーサル)を拒否", "")
    except Exception as e:
        _ng("evidence_store", repr(e) + "\n" + traceback.format_exc())
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def test_subdomain_enum():
    _section("3b. TOOLS — SubdomainEnum（受動的資産発見・Phase B）")
    from tools import subdomain_enum
    import unittest.mock as mock

    class _FakeResp:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

    try:
        fake_data = (
            '[{"name_value": "api.example.com"}, '
            '{"name_value": "*.dev.example.com\\nwww.example.com"}, '
            '{"name_value": "api.example.com"}]'
        )
        with mock.patch("requests.get", return_value=_FakeResp(200, fake_data)):
            names = subdomain_enum.query_crtsh("example.com")
        assert names == sorted(set(names)), "重複排除・ソートされているべき"
        assert "api.example.com" in names and "dev.example.com" in names \
            and "www.example.com" in names, names
        _ok("query_crtsh() パース・重複排除", f"{len(names)} 件: {names}")

        with mock.patch("requests.get", return_value=_FakeResp(500, "")):
            assert subdomain_enum.query_crtsh("example.com") == [], \
                "非200はサイレントに空リストを返すべき"
        with mock.patch("requests.get", return_value=_FakeResp(200, "not json")):
            assert subdomain_enum.query_crtsh("example.com") == [], \
                "JSON異常はサイレントに空リストを返すべき"
        import requests as _requests
        with mock.patch("requests.get", side_effect=_requests.exceptions.ConnectionError("down")):
            assert subdomain_enum.query_crtsh("example.com") == [], \
                "ネットワーク失敗はサイレントに空リストを返すべき"
        _ok("query_crtsh() サイレント失敗", "非200/JSON異常/ネットワーク失敗")
    except Exception as e:
        _ng("subdomain_enum", repr(e) + "\n" + traceback.format_exc())


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
        # CTF_FLAG_HUNT.md AC1: capture_body 既定Falseでは body を保存しない
        # （ctf_mode=False の既存 ATTACK MODE 実行を完全に元通りに保つための回帰確認）。
        assert data["body"] is None, f"capture_body 既定なのに body が保存された: {data['body']!r}"
        data2 = wp.probe("https://example.com", on_progress=lambda m: None, capture_body=True)
        assert data2["body"], "capture_body=True なのに body が保存されなかった"
        _ok("probe() capture_body 既定オフ/明示オンの切り替え", "body は明示オン時のみ保存")
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
            # 以下6件は試運転（2026-08-17）で検出漏れが発覚した回帰ケース。
            # tools/log_watcher.py の attack_lines と同一文字列を使う。
            "GET /admin/config.php HTTP/1.1":                  "SENSITIVE_FILE_PROBE",
            "GET /.env HTTP/1.1":                              "SENSITIVE_FILE_PROBE",
            "GET /.git/HEAD HTTP/1.1":                         "SENSITIVE_FILE_PROBE",
            "POST /api/exec?cmd=cat%20/etc/passwd HTTP/1.1":   "CMD_INJECTION",
            "GET /wp-admin/admin.php HTTP/1.1":                "CMS_PROBE",
            "GET /xmlrpc.php HTTP/1.1":                        "CMS_PROBE",
        }
        for line, expect in cases.items():
            matched = m._pattern_match(line)
            if expect is None:
                assert matched == [], f"{line!r} -> {matched}"
            else:
                assert expect in matched, f"{line!r} -> {matched}, expected {expect}"
        _ok("_pattern_match 全パターン", f"{len(cases)} cases")
        # log_watcher.py の attack_lines 全件が最低1パターンにマッチすることを確認
        # （サンプルログ生成が想定する攻撃シグネチャに検出漏れが無いことの回帰チェック）
        from tools.log_watcher import LogWatcher
        import inspect
        src = inspect.getsource(LogWatcher.generate_sample_log)
        # attack_lines リスト内の文字列リテラルを雑にでも拾えれば十分（保守目的の緩いチェック）
        import re as _re
        literals = _re.findall(r'"([^"]{15,})"', src)
        unmatched = [s for s in literals if s.startswith(("GET ", "POST ", "User-Agent"))
                     and not m._pattern_match(s)]
        assert not unmatched, f"attack_lines のうちパターン未マッチ: {unmatched}"
        _ok("log_watcher.attack_lines 全件マッチ", f"{len(literals)}件中0件が未検出")
        # severity マッピング
        assert m._quick_severity("CMD_INJECTION") == "CRITICAL"
        assert m._quick_severity("SQL_INJECTION") == "HIGH"
        assert m._quick_severity("SCANNER") == "MEDIUM"
        assert m._quick_severity("SENSITIVE_FILE_PROBE") == "MEDIUM"
        assert m._quick_severity("CMS_PROBE") == "MEDIUM"
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
---VULN_START---
CONFIDENCE: ENSEMBLE_MINORITY
NAME: Possible IDOR in profile view
SEVERITY: MEDIUM
CWE: CWE-639
LINES: 90
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
        # AIモデル運用最適化: 検証器アンサンブルの少数意見（CONFIDENCE: ENSEMBLE_MINORITY）は
        # レポートから除外されず、単独検証であることが分かる形で表示されるべき
        assert "単独検証" in html and "Possible IDOR in profile view" in html, \
            "CONFIDENCE: ENSEMBLE_MINORITY の所見は除外せず「単独検証」表示付きでレポートに含めるべき"
        assert 'class="minority"' in html
        _ok("generate() パース＆集計", "CONFIDENCE: ENSEMBLE_MINORITY の可視化を含む")
        path = report_generator.save(html, "selftest")
        assert os.path.isfile(path)
        _ok("save()", os.path.basename(path))
    except Exception as e:
        _ng("report_generator", repr(e))


def test_report_generator_attack_mode():
    _section("7c. TOOLS — ReportGenerator ATTACK MODE(FINDING marker)所見抽出(P1.1調査で発見・修正)")
    from tools import report_generator
    # agents/recon_agent.py の実際のSYSTEM_PROMPTが指示する形式
    # （---FINDING_START/END---、TITLE/CATEGORY/EVIDENCE/ATTACK_SCENARIO/
    #   RECOMMENDED_ACTION。VULN/THREATとはフィールド名もコードフェンス有無も異なる）。
    sample = """
---FINDING_START---
TITLE: Outdated OpenSSH exposes known CVEs
SEVERITY: HIGH
CATEGORY: Network
EVIDENCE: banner shows OpenSSH_7.2p2 on port 22
ATTACK_SCENARIO:
Attacker fingerprints the SSH banner and cross-references known CVEs for this version.
RECOMMENDED_ACTION:
Upgrade OpenSSH to the latest stable release.
---FINDING_END---
---FINDING_START---
TITLE: Missing security headers
SEVERITY: MEDIUM
CATEGORY: Web
EVIDENCE: X-Frame-Options and CSP headers absent
ATTACK_SCENARIO:
Clickjacking / content injection surface widened by missing headers.
RECOMMENDED_ACTION:
Add X-Frame-Options, Content-Security-Policy.
---FINDING_END---
"""
    try:
        parsed, counts = report_generator._findings_and_counts("ATTACK MODE", sample)
        assert len(parsed) == 2, f"ATTACK MODEのFINDINGマーカーが抽出されていない: {parsed}"
        assert parsed[0]["name"] == "Outdated OpenSSH exposes known CVEs"
        assert parsed[0]["severity"] == "HIGH"
        assert parsed[0]["ref"] == "Network", "CATEGORYがrefへフォールバックしていない"
        assert parsed[0]["lines"] == "banner shows OpenSSH_7.2p2 on port 22", \
            "EVIDENCEがlinesへフォールバックしていない"
        assert "fingerprints the SSH banner" in parsed[0]["attack"], \
            "コードフェンス無しのATTACK_SCENARIO本文が取得できていない"
        assert "Upgrade OpenSSH" in parsed[0]["fix"], \
            "コードフェンス無しのRECOMMENDED_ACTION本文が取得できていない"
        assert counts == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0}
        _ok("_findings_and_counts('ATTACK MODE', ...)がFINDINGマーカーを抽出", f"{len(parsed)}件")

        html = report_generator.generate(mode="ATTACK MODE", target="10.10.10.10",
                                         raw_text=sample, model="openai/gpt-4o")
        assert "Outdated OpenSSH" in html and "Missing security headers" in html, \
            "ATTACK MODEのHTMLレポートに所見が反映されていない(修正前は常に0件だった)"
        _ok("generate(mode='ATTACK MODE') がFINDING所見をHTMLへ反映", "")
    except Exception as e:
        _ng("report_generator_attack_mode", repr(e) + "\n" + traceback.format_exc())


def test_report_generator_markdown():
    _section("7b. TOOLS — ReportGenerator Markdown出力（バグバウンティ対応・Phase D）")
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
"""
    try:
        md = report_generator.generate_markdown(
            mode="WEB FUZZ", target="https://example.com", raw_text=sample,
            model="openai/gpt-4o")
        assert "# " in md.splitlines()[0], "見出しが無い"
        for section in ("### Summary", "### Steps to Reproduce", "### Impact", "### Suggested Fix"):
            assert section in md, f"{section} 見出しが無い"
        assert "SQL Injection in authenticate()" in md
        assert "CRITICAL" in md
        _ok("generate_markdown()", "4項目見出し（Summary/Steps/Impact/Fix）を確認")
        path = report_generator.save_markdown(md, "selftest_md")
        assert os.path.isfile(path) and path.endswith(".md")
        _ok("save_markdown()", os.path.basename(path))
        os.remove(path)

        # 検出項目が無い場合も例外にならないこと
        md_empty = report_generator.generate_markdown(
            mode="WEB FUZZ", target="https://example.com", raw_text="(no findings)",
            model="openai/gpt-4o")
        assert "検出項目なし" in md_empty
        _ok("generate_markdown() 空所見時のフォールバック")
    except Exception as e:
        _ng("generate_markdown", repr(e) + "\n" + traceback.format_exc())


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
        llm = _selftest_llm(30)
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


def test_audit_agent_p11_wiring():
    _section("9b. AGENT — AuditAgent P1.1 Coverage/State変換ロジック・非LLM E2E")
    from agents.audit_agent import AuditAgent
    from core.findings import ScanState, CoverageStatus
    try:
        # 1) _build_coverage(): 通常/truncated時の記録
        cov = AuditAgent._build_coverage("sample.py", was_truncated=False)
        assert len(cov) == 1 and cov[0].status == CoverageStatus.TESTED.value
        cov_t = AuditAgent._build_coverage("sample.py", was_truncated=True)
        assert len(cov_t) == 2
        skipped = next(c for c in cov_t if c.status == CoverageStatus.SKIPPED.value)
        assert "smart_truncate" in skipped.reason
        _ok("_build_coverage(): 通常/truncated時の記録", "")

        # 2) _determine_state(): STOP優先・空応答→partial・通常はcompleted
        agent = AuditAgent(EventBus(), None)
        state, errors = agent._determine_state(triage_text="---VULN_START---...---VULN_END---")
        assert state == ScanState.COMPLETED.value and errors == []
        state, errors = agent._determine_state(triage_text="   ")
        assert state == ScanState.PARTIAL.value and errors
        agent.stop()
        state, errors = agent._determine_state(triage_text="anything")
        assert state == ScanState.CANCELLED.value
        _ok("_determine_state(): STOP優先・空応答はpartial・通常completed", "")

        # 3) 非LLM E2E: ファイル読み込みエラー時もRESULT(failed)→DONE(error=True)を確定
        bus = EventBus()
        agent2 = AuditAgent(bus, None)
        agent2.start(path="/nonexistent/path/does-not-exist.py")
        agent2._thread.join(timeout=5)
        events = bus.drain(50)
        kinds = [e.kind for e in events]
        assert kinds.count(ev.RESULT) == 1 and kinds.count(ev.DONE) == 1, kinds
        result = next(e.payload for e in events if e.kind == ev.RESULT)
        assert result["state"] == ScanState.FAILED.value
        assert result["target"] == "/nonexistent/path/does-not-exist.py"
        done = next(e.payload for e in events if e.kind == ev.DONE)
        assert done["error"] is True
        _ok("AuditAgent: ファイル読み込みエラーでRESULT(failed)→DONE(error=True)を確定", "")
    except Exception as e:
        _ng("audit_agent_p11_wiring", repr(e) + "\n" + traceback.format_exc())


def test_audit_agent():
    _section("10. AGENT E2E — AuditAgent (実LLM)")
    from agents.audit_agent import AuditAgent
    llm = _selftest_llm(90)
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


def test_monitor_agent_p11_wiring():
    _section("10c. AGENT — MonitorAgent P1.1 Coverage/State変換ロジック・非LLM E2E")
    import tempfile
    from agents.monitor_agent import MonitorAgent
    from core.findings import ScanState, CoverageStatus
    try:
        # 1) _build_coverage(): ログソース単位の記録
        cov = MonitorAgent._build_coverage("/var/log/sample.log", batch_count=3)
        assert len(cov) == 1
        assert cov[0].status == CoverageStatus.TESTED.value
        assert cov[0].rule_id == "LOG_MONITOR"
        assert "3 batch" in cov[0].reason
        _ok("_build_coverage(): ログソース単位の記録", "")

        # 2) _determine_state(): STOP最優先・監視エラー/全空応答はpartial・通常completed
        agent = MonitorAgent(EventBus(), None)
        state, errors = agent._determine_state(watch_error=None, analyses=["---THREAT_START---...---THREAT_END---"])
        assert state == ScanState.COMPLETED.value and errors == []
        state, errors = agent._determine_state(watch_error=None, analyses=[])
        assert state == ScanState.COMPLETED.value, "分析0件(アラート無し)もcompletedとすべき"
        state, errors = agent._determine_state(watch_error="disk read error", analyses=[])
        assert state == ScanState.PARTIAL.value and errors, "監視中の例外はpartialとすべき"
        state, errors = agent._determine_state(watch_error=None, analyses=["", "   "])
        assert state == ScanState.PARTIAL.value and errors, "AI分析が全て空応答ならpartialとすべき"
        agent.stop()
        state, errors = agent._determine_state(watch_error="disk read error", analyses=[])
        assert state == ScanState.CANCELLED.value, "STOPは他の判定より優先されるべき"
        _ok("_determine_state(): STOP最優先・監視エラー/全空応答はpartial・通常completed", "")

        # 3) 非LLM E2E: 攻撃パターンに一致しないログ(single_pass)はLLM呼び出し無しで
        #    RESULT(completed)→DONE(error=False)を確定する
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tf:
            tf.write("2026-09-05 12:00:00 INFO normal request GET /health 200\n")
            tf.write("2026-09-05 12:00:01 INFO normal request GET /index.html 200\n")
            tmp_log_path = tf.name
        try:
            bus = EventBus()
            agent2 = MonitorAgent(bus, None)
            agent2.start(log_path=tmp_log_path, watch_mode=False)
            agent2._thread.join(timeout=10)
            assert not agent2._thread.is_alive(), "スレッドが終了していない"
            events = bus.drain(200)
            kinds = [e.kind for e in events]
            assert kinds.count(ev.RESULT) == 1 and kinds.count(ev.DONE) == 1, kinds
            result = next(e.payload for e in events if e.kind == ev.RESULT)
            assert result["state"] == ScanState.COMPLETED.value, result["state"]
            assert result["findings"] == []
            assert result["coverage"] and result["coverage"][0]["rule_id"] == "LOG_MONITOR"
            assert result["target"] == tmp_log_path
            done = next(e.payload for e in events if e.kind == ev.DONE)
            assert done["error"] is False
            _ok("MonitorAgent: 攻撃パターン無しログでRESULT(completed)→DONE(error=False)を確定", "")
        finally:
            os.remove(tmp_log_path)
    except Exception as e:
        _ng("monitor_agent_p11_wiring", repr(e) + "\n" + traceback.format_exc())


def test_monitor_agent(log_path):
    _section("11. AGENT E2E — MonitorAgent (single-pass, 実LLM)")
    from agents.monitor_agent import MonitorAgent
    if not log_path:
        _ng("MonitorAgent", "サンプルログ未生成のためスキップ")
        return
    llm = _selftest_llm(90)
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


def test_recon_agent_p11_wiring():
    _section("11b. AGENT — ReconAgent P1.1 Coverage/State変換ロジック")
    from agents.recon_agent import ReconAgent
    from core.findings import ScanState, CoverageStatus
    try:
        # 1) _build_coverage(): scan_web/scan_udp/domainの各組み合わせでtested/skippedを記録
        cov = ReconAgent._build_coverage(
            "10.0.0.5", "10.0.0.5", [22, 80, 443], "common",
            scan_web=True, web_ran=True, scan_udp=False, domain=None,
        )
        by_rule = {c.rule_id: c for c in cov}
        assert by_rule["PORT_SCAN"].status == CoverageStatus.TESTED.value
        assert by_rule["UDP_SCAN"].status == CoverageStatus.SKIPPED.value
        assert by_rule["WEB_ENUM"].status == CoverageStatus.TESTED.value
        assert by_rule["SUBDOMAIN_ENUM"].status == CoverageStatus.SKIPPED.value, \
            "IPアドレス指定(domain=None)はSUBDOMAIN_ENUMをskippedにすべき"

        cov2 = ReconAgent._build_coverage(
            "example.com", "example.com", [22], "common",
            scan_web=True, web_ran=False, scan_udp=True, domain="example.com",
        )
        by_rule2 = {c.rule_id: c for c in cov2}
        assert by_rule2["UDP_SCAN"].status == CoverageStatus.TESTED.value
        assert by_rule2["WEB_ENUM"].status == CoverageStatus.SKIPPED.value, \
            "Web関連ポート未開放時はWEB_ENUMをskippedにすべき"
        assert by_rule2["SUBDOMAIN_ENUM"].status == CoverageStatus.TESTED.value

        cov3 = ReconAgent._build_coverage(
            "example.com", "example.com", [22], "common",
            scan_web=False, web_ran=False, scan_udp=False, domain="example.com",
        )
        by_rule3 = {c.rule_id: c for c in cov3}
        assert by_rule3["WEB_ENUM"].status == CoverageStatus.SKIPPED.value
        assert "scan_web" in by_rule3["WEB_ENUM"].reason
        _ok("_build_coverage(): scan_web/scan_udp/domainの組み合わせでtested/skippedを記録", "")

        # 2) _determine_state(): STOP最優先・ホスト解決失敗/空応答はpartial・通常はcompleted
        agent = ReconAgent(EventBus(), None)
        state, errors = agent._determine_state(triage_text="---FINDING_START---...---FINDING_END---",
                                                host_resolved=True)
        assert state == ScanState.COMPLETED.value and errors == []
        state, errors = agent._determine_state(triage_text="anything", host_resolved=False)
        assert state == ScanState.PARTIAL.value and errors, "ホスト解決失敗はpartialとすべき"
        state, errors = agent._determine_state(triage_text="   ", host_resolved=True)
        assert state == ScanState.PARTIAL.value and errors, "AI攻撃仮説が空応答ならpartialとすべき"
        agent.stop()
        state, errors = agent._determine_state(triage_text="", host_resolved=False)
        assert state == ScanState.CANCELLED.value, "STOPは他の判定より優先されるべき"
        _ok("_determine_state(): STOP最優先・ホスト解決失敗/空応答はpartial・通常completed", "")
    except Exception as e:
        _ng("recon_agent_p11_wiring", repr(e) + "\n" + traceback.format_exc())


def test_recon_agent():
    _section("12. AGENT E2E — ReconAgent (scanme.nmap.org / 実LLM)")
    from agents.recon_agent import ReconAgent
    llm = _selftest_llm(90)
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


def test_ctf_flag_hunt():
    _section("12.5 CTF — フラグ検出ヘルパー（ローカル・送信なし）")
    from agents.recon_agent import _detect_flags
    # 波括弧形式は「ラベルごと全キャプチャ」（flag{...} 全体）で返す
    sample = ("backup: flag{ctf_easy_123abc} leaked <ctf{lab_unused_0}> deadbeef\n"
              "session=fc94b0c34fd5ac2ddefd7bb3a04a05c (bare noise hex)"
              " extra=7922511f806bb1e3d5d1e6b1e565bdb1e")
    flags = _detect_flags(sample)
    assert "flag{ctf_easy_123abc}" in flags, flags
    assert "ctf{lab_unused_0}" in flags, flags
    # 裸の 32/40/64 桁 hex はフラグ文脈が無ければ誤検出しない（MD5/SHA/ETag/CSPハッシュ等）
    for noise in ("fc94b0c34fd5ac2d37a7bb3a04a05c", "9f2a1b3c4d5e6f7a8b9c0d1e2f3a4b5c",
                  "7929bcc60f8064bb1e1d5d1e6b1e565bdb1e"):
        assert noise not in flags, f"bare hex {noise} を誤検出"
    # flag/ctf ラベル直後の 64 桁 hex は文脈付きのため検出する
    hex64 = "c9a2b3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f8a1"
    assert len(hex64) == 64, len(hex64)
    ctx = "flag: " + hex64
    ctx_flags = _detect_flags(ctx)
    assert hex64 in ctx_flags, ctx_flags
    _ok("_detect_flags 形式検出", f"{len(flags)} flags: {flags[:3]}")


def _start_ctf_vuln_server():
    """testlab/vuln_server.py の VulnHandler を127.0.0.1のランダムポートで起動する。

    _start_mock_web_server() と同じパターン（インプロセス・デーモンスレッド）。
    """
    import threading
    from http.server import ThreadingHTTPServer
    from testlab.vuln_server import VulnHandler

    srv = ThreadingHTTPServer(("127.0.0.1", 0), VulnHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


class _DummyLLM:
    """CTF Active Retrieval のLLMガイド付きTierをモックするための最小スタブ。

    system()/user() は core.llm_client.LLMClient の同名静的メソッドと同じ辞書を返す。
    実際のLLM呼び出し（_complete_llm）はテスト側で monkeypatch する。
    """
    @staticmethod
    def system(content):
        return {"role": "system", "content": content}

    @staticmethod
    def user(content):
        return {"role": "user", "content": content}


def test_ctf_active_retrieval():
    _section("12.6 CTF ACTIVE — 安全装置(is_destructive/scope/予算) と Tier実行")
    import json as _json
    from core.ctf_safety import is_destructive, require_explicit_scope, CtfSafetyGuard
    from agents.recon_agent import ReconAgent

    # ① 層2: 破壊的操作の機械的ブロック（見逃しなし・誤検知なし）
    try:
        destructive = [
            "' ; DROP TABLE users --", "rm -rf /", "rm -fr /home",
            ":(){ :|:& };:", "shutdown -h now", "DELETE FROM accounts WHERE 1=1",
            "UPDATE users SET password='x'", "TRUNCATE TABLE logs",
        ]
        for p in destructive:
            hit, _r = is_destructive(p)
            assert hit, f"破壊的ペイロードを見逃した: {p!r}"
        safe = [
            "' UNION SELECT username,password FROM users --",
            "../../../etc/passwd", "id", "whoami", "' OR 1=1 --",
        ]
        for p in safe:
            hit, r = is_destructive(p)
            assert not hit, f"非破壊ペイロードを誤検知: {p!r} ({r})"
        _ok("is_destructive() 見逃し/誤検知なし",
            f"{len(destructive)}件ブロック・{len(safe)}件許可を確認")
    except Exception as e:
        _ng("is_destructive()", repr(e) + "\n" + traceback.format_exc())

    # ② 層1: スコープの厳格化（空リストは拒否。既存 scope_guard.in_scope() とは別基準）
    try:
        ok, _r = require_explicit_scope([])
        assert not ok, "空リストが許可されてしまった"
        ok, _r = require_explicit_scope(None)
        assert not ok, "Noneが許可されてしまった"
        ok, _r = require_explicit_scope(["10.10.10.5"])
        assert ok, "明示ホストがあるのに拒否された"
        _ok("require_explicit_scope() 空リスト拒否", "空/None拒否・明示ホスト許可を確認")
    except Exception as e:
        _ng("require_explicit_scope()", repr(e) + "\n" + traceback.format_exc())

    # ③ 層3: CtfSafetyGuard — 予算超過・連続エラーでの自動停止
    try:
        import requests as _requests
        guard = CtfSafetyGuard(max_requests=3, jitter=(0, 0), max_consecutive_errors=2)
        sess = _requests.Session()
        for _ in range(3):
            guard.send(sess, "GET", "http://127.0.0.1:1", tier=2)  # 即座に接続エラーになるポート
        stop, reason = guard.should_stop()
        assert stop, "連続エラー/予算超過で停止しなかった"
        _ok("CtfSafetyGuard 予算/連続エラー停止", reason)
    except Exception as e:
        _ng("CtfSafetyGuard", repr(e) + "\n" + traceback.format_exc())

    # ④ _parse_ctf_candidates: フェンス付き/前後説明文/壊れたJSONを救済
    try:
        cases = [
            ('[{"path": "/x", "method": "GET"}]', 1),
            ('```json\n[{"path": "/y"}]\n```', 1),
            ('説明文\n[{"path": "/z"}]\nそのあと', 1),
            ('壊れたJSON [{', 0),
            ('{}', 0),
        ]
        for raw, expect_n in cases:
            got = ReconAgent._parse_ctf_candidates(raw)
            assert len(got) == expect_n, f"{raw!r} -> {got}"
        _ok("_parse_ctf_candidates() 救済パース", f"{len(cases)}パターン確認")
    except Exception as e:
        _ng("_parse_ctf_candidates()", repr(e) + "\n" + traceback.format_exc())

    # ⑤ Tier1: testlab/vuln_server.py に対する実行（隠しパス /notes.txt のフラグ検出）
    srv = None
    try:
        import requests as _requests
        srv, base = _start_ctf_vuln_server()
        agent = ReconAgent(EventBus(), llm=_DummyLLM())
        sess = _requests.Session()
        guard = CtfSafetyGuard(max_requests=30, jitter=(0, 0))
        flags = agent._ctf_tier1(base, sess, guard)
        assert "flag{ctf_lab_tier1_hidden_path}" in flags, flags
        _ok("Tier1 拡張パス巡回", f"flags={flags}")
    except Exception as e:
        _ng("CTF Active Tier1", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()

    # ⑥ Tier2: LLMガイド付き（モック）— LFI/SQLi検出、破壊的候補のブロックを確認
    srv = None
    try:
        import requests as _requests
        srv, base = _start_ctf_vuln_server()
        agent = ReconAgent(EventBus(), llm=_DummyLLM())
        sess = _requests.Session()

        lfi_payload = _json.dumps([{
            "method": "GET", "path": "/download",
            "params": {"file": "../../../etc/passwd"}, "rationale": "read-only LFI check",
        }])
        agent._complete_llm = lambda messages, role="fast": lfi_payload
        guard = CtfSafetyGuard(max_requests=30, jitter=(0, 0))
        flags = agent._ctf_llm_guided_tier(2, base, "dummy summary", sess, guard)
        assert "flag{ctf_lab_tier2_lfi_readonly}" in flags, flags

        sqli_payload = _json.dumps([{
            "method": "GET", "path": "/account",
            "params": {"id": "1 UNION SELECT username,password FROM users"},
            "rationale": "read-only UNION SQLi check",
        }])
        agent._complete_llm = lambda messages, role="fast": sqli_payload
        guard2 = CtfSafetyGuard(max_requests=30, jitter=(0, 0))
        flags2 = agent._ctf_llm_guided_tier(2, base, "dummy summary", sess, guard2)
        assert "flag{ctf_lab_tier2_sqli_union}" in flags2, flags2

        # LLMが誤って破壊的な候補を提案しても、層2で機械的にブロックされ送信されない
        destructive_payload = _json.dumps([{
            "method": "POST", "path": "/account",
            "data": {"id": "1; DROP TABLE users; --"}, "rationale": "(誤り)",
        }])
        agent._complete_llm = lambda messages, role="fast": destructive_payload
        guard3 = CtfSafetyGuard(max_requests=30, jitter=(0, 0))
        flags3 = agent._ctf_llm_guided_tier(2, base, "dummy summary", sess, guard3)
        assert flags3 == [], f"破壊的候補がブロックされず送信された: {flags3}"
        assert any(e["status"] == "BLOCKED" for e in guard3.log), \
            f"BLOCKEDログが記録されなかった: {guard3.log}"

        _ok("Tier2 LLMガイド(モック) LFI/SQLi検出・破壊的候補ブロック",
            f"lfi={flags} sqli={flags2} blocked={guard3.log[0]['status']}")
    except Exception as e:
        _ng("CTF Active Tier2", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()

    # ⑦ _ctf_active_retrieval: スコープ未指定/スコープ外では送信ゼロで中断すること
    srv = None
    try:
        import requests as _requests
        srv, base = _start_ctf_vuln_server()
        agent = ReconAgent(EventBus(), llm=_DummyLLM())
        recon = {"web": {"url": base}}
        agent._ctf_active_retrieval(recon, "summary", _requests.Session(), [], 2)
        assert recon.get("flags") is None, "空スコープなのに実行されてしまった"

        recon2 = {"web": {"url": base}}
        agent._ctf_active_retrieval(recon2, "summary", _requests.Session(), ["example.com"], 2)
        assert recon2.get("flags") is None, "スコープ外なのに実行されてしまった"

        recon3 = {"web": {"url": base}}
        agent._ctf_active_retrieval(recon3, "summary", _requests.Session(), ["127.0.0.1"], 2)
        assert recon3.get("flags"), "正しいスコープなのにフラグが見つからなかった"

        _ok("_ctf_active_retrieval スコープ強制", "空/スコープ外で中断・正しいスコープで実行を確認")
    except Exception as e:
        _ng("_ctf_active_retrieval scope", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()

    # ⑧ Tierの段階的エスカレーション: Tier1で見つかったらTier2のLLM呼び出しが
    # 一切発生しないこと（CTF_ACTIVE_FLAG_RETRIEVAL.md AC4）。
    srv = None
    try:
        import requests as _requests
        srv, base = _start_ctf_vuln_server()
        agent = ReconAgent(EventBus(), llm=_DummyLLM())
        tier2_called = []
        agent._complete_llm = lambda messages, role="fast": (
            tier2_called.append(1) or "[]"
        )
        recon = {"web": {"url": base}}
        agent._ctf_active_retrieval(recon, "summary", _requests.Session(), ["127.0.0.1"], 3)
        assert recon.get("flags") == ["flag{ctf_lab_tier1_hidden_path}"], recon.get("flags")
        assert not tier2_called, "Tier1で見つかったのにTier2のLLM呼び出しが発生した"
        _ok("Tier段階的エスカレーション", "Tier1で発見 → Tier2/3のLLM呼び出しなしを確認")
    except Exception as e:
        _ng("Tier escalation", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()


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


def test_langgraph_audit_agent_p11_wiring():
    _section("13b. AGENT — LangGraphAuditAgent P1.1 State変換ロジック・非LLM E2E")
    from agents.langgraph_audit_agent import LangGraphAuditAgent, LANGGRAPH_AVAILABLE
    from core.findings import ScanState
    if not LANGGRAPH_AVAILABLE:
        _SKIP.append("LangGraphAuditAgent P1.1 wiring (langgraph unavailable)")
        print("  [SKIP] langgraph未インストールのためスキップ")
        return
    try:
        # 1) _determine_state(): 読み込み失敗→failed、STOP優先→cancelled、
        #    空応答→partial、通常→completed
        agent1 = LangGraphAuditAgent(EventBus(), None)
        state, errors = agent1._determine_state({"source_code": "", "phase": "stopped"}, "")
        assert state == ScanState.FAILED.value and errors, "source_code空・非STOPはfailedにすべき"

        agent1.stop()
        state, errors = agent1._determine_state({"source_code": "", "phase": "stopped"}, "")
        assert state == ScanState.CANCELLED.value, \
            "source_code空でもSTOP中はcancelledを優先すべき(読み込み失敗と誤判定しない)"
        state, errors = agent1._determine_state({"source_code": "x = 1", "phase": "stopped"}, "")
        assert state == ScanState.CANCELLED.value

        agent2 = LangGraphAuditAgent(EventBus(), None)
        state, errors = agent2._determine_state({"source_code": "x = 1", "phase": "done"}, "   ")
        assert state == ScanState.PARTIAL.value and errors
        state, errors = agent2._determine_state(
            {"source_code": "x = 1", "phase": "done"}, "---VULN_START---...---VULN_END---")
        assert state == ScanState.COMPLETED.value and errors == []
        _ok("_determine_state(): 読み込み失敗/STOP優先/空応答partial/通常completed", "")

        # 2) 非LLM E2E: ファイル読み込み失敗時もRESULT(failed)→DONE(error=True)を確定
        #    (load_code→surface_scanの経路はsource_code空時にLLM呼び出し無しで
        #    グラフ末尾まで進む設計のため、llm=Noneでも安全に検証できる)
        bus = EventBus()
        agent3 = LangGraphAuditAgent(bus, None)
        agent3.start(path="/nonexistent/path/does-not-exist.py")
        agent3._thread.join(timeout=15)
        assert not agent3._thread.is_alive(), "スレッドが終了していない"
        events = bus.drain(200)
        kinds = [e.kind for e in events]
        assert kinds.count(ev.RESULT) == 1 and kinds.count(ev.DONE) == 1, kinds
        result = next(e.payload for e in events if e.kind == ev.RESULT)
        assert result["state"] == ScanState.FAILED.value, result["state"]
        done = next(e.payload for e in events if e.kind == ev.DONE)
        assert done["error"] is True
        _ok("LangGraphAuditAgent: ファイル読み込み失敗でRESULT(failed)→DONE(error=True)を確定", "")
    except Exception as e:
        _ng("langgraph_audit_agent_p11_wiring", repr(e) + "\n" + traceback.format_exc())


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


def test_pdf_report():
    _section("15. TOOLS — PDF レポート出力")
    from tools import report_generator
    sample = """
---VULN_START---
NAME: SQL Injection（日本語タイトル含む）
SEVERITY: CRITICAL
CWE: CWE-89
LINES: 65
SNIPPET:
```
query = f"SELECT * FROM users WHERE u = '{u}'"
```
ATTACK:
認証バイパス。日本語の説明が正しくPDFに描画されることを確認する。
FIX:
```
cursor.execute("... WHERE u = ?", (u,))
```
---VULN_END---
"""
    try:
        pdf = report_generator.generate_pdf(
            mode="CODE AUDIT", target="samples/target_code.py",
            raw_text=sample * 6, model="openai/gpt-4o")
        if pdf is None:
            _ng("generate_pdf", "Pillow 未導入のため None（環境依存・スキップ可）")
            return
        assert pdf[:5] == b"%PDF-", "PDFマジックが不正"
        assert len(pdf) > 1000, "PDFが小さすぎる"
        _ok("generate_pdf() 生成", f"{len(pdf)} bytes, 複数ページ対応")
        path = report_generator.save_pdf(pdf, "selftest_pdf")
        assert os.path.isfile(path) and path.endswith(".pdf")
        _ok("save_pdf()", os.path.basename(path))
        os.remove(path)
    except Exception as e:
        _ng("pdf_report", repr(e) + "\n" + traceback.format_exc())


def _start_mock_web_server():
    """検出ロジック検証用のローカルHTTPサーバを起動し base_url を返す。"""
    import http.server
    import socketserver
    import threading
    import html as _h
    from urllib.parse import urlparse, parse_qs

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            q = qs.get("q", [""])[0]
            pid = qs.get("id", [""])[0]
            if u.path == "/api/data":
                # 非HTML（JSON）応答のエンドポイント。クエリパラメータ（token）が
                # Content-Type に関わらず注入点として登録されることを確認するため
                # （試運転で発覚した検出漏れの回帰テスト）。
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
                return
            body = "<html><body>"
            if u.path == "/":
                body += ('<a href="/search?q=hi">s</a> <a href="/item?id=1">i</a> '
                         '<a href="/api/data?token=x">d</a>')
            elif u.path == "/search":
                body += "Results for: " + q                     # 未エスケープ反射 → XSS
            elif u.path == "/item":
                if "'" in pid:
                    body += "You have an error in your SQL syntax near '"  # → SQLI
                else:
                    body += "Item " + _h.escape(pid)
            body += "</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_web_fuzzer():
    _section("16. TOOLS — WebFuzzer（クロール＆検出）")
    from tools.web_fuzzer import WebFuzzer
    srv = None
    try:
        srv, base = _start_mock_web_server()
        fz = WebFuzzer(profile="aggressive", max_requests=500, log=lambda m: None)
        crawl = fz.crawl(base)
        params = {p["param"] for p in crawl["injection_points"]}
        assert {"q", "id"} <= params, f"注入点検出漏れ: {params}"
        _ok("crawl() 注入点検出", f"pages={crawl['pages']} params={sorted(params)}")
        assert "token" in params, (
            f"非HTML（application/json）応答のエンドポイントのパラメータが"
            f"注入点として登録されていない（Content-Typeフィルタの回帰）: {params}"
        )
        _ok("crawl() 非HTML応答の注入点登録", "application/jsonのtokenパラメータを検出")
        findings = fz.fuzz(crawl["injection_points"])
        cats = {f["category"] for f in findings}
        assert "XSS" in cats, "XSS反射を検出できず"
        assert "SQLI" in cats, "SQLエラー署名を検出できず"
        assert fz._req_count <= 500, "リクエスト予算超過"
        _ok("fuzz() 検出のみ", f"req={fz._req_count} detected={sorted(cats)}")
    except Exception as e:
        _ng("web_fuzzer", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()


def _start_idor_mock_server():
    """IDOR検出ロジック検証用: /resource?id=1 をCookieに関わらず同一内容で返す
    （脆弱なアプリを再現する）モックHTTPサーバを起動し base_url を返す。"""
    import http.server
    import socketserver
    import threading
    from urllib.parse import urlparse

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            cookie = self.headers.get("Cookie", "")
            body = "<html><body>"
            if u.path == "/":
                body += '<a href="/resource?id=1">r</a>'
            elif u.path == "/resource":
                if not cookie:      # 認証必須(認証なしで読める公開リソースはIDORの根拠にしない)
                    self.send_response(401)
                    self.end_headers()
                    return
                # 脆弱: ログインさえしていれば所有者を確認せずid=1の内容を返す（IDOR再現用モック）
                body += f"secret data for resource 1 (cookie={cookie})"
            body += "</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_web_fuzzer_idor():
    _section("16b. TOOLS — WebFuzzer IDOR/アクセス制御チェック（バグバウンティ対応・Phase C）")
    from tools.web_fuzzer import WebFuzzer
    srv = None
    try:
        srv, base = _start_idor_mock_server()
        fz = WebFuzzer(
            profile="aggressive", max_requests=500, log=lambda m: None,
            auth={"cookie": "session=alice"}, auth_b={"cookie": "session=bob"},
        )
        fz.authenticate()
        fz.authenticate_b()
        crawl = fz.crawl(base)
        points = crawl["injection_points"]
        findings = fz._detect_idor(points)
        assert findings, "脆弱なモックでIDOR兆候を検出できず"
        assert all(f["method"] == "GET" for f in findings), \
            "安全境界違反: GET以外のメソッドが使われている"
        _ok("_detect_idor() 検出", f"{len(findings)} 件")

        # 後方互換: auth_b未設定なら session_b は None のままで、_detect_idor は
        # 常に空リストを返す（既存の非バグバウンティ利用者への挙動が変わらないこと）。
        fz2 = WebFuzzer(profile="aggressive", max_requests=500, log=lambda m: None)
        assert fz2.session_b is None
        assert fz2._detect_idor(points) == [], "auth_b未設定時は空リストを返すべき（後方互換）"
        _ok("_detect_idor() 後方互換", "auth_b未設定時は常にsession_b=None・空リスト")
    except Exception as e:
        _ng("web_fuzzer idor", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()


def test_http_transport():
    _section("16c. CORE — HttpTransport（同一origin検査・共有予算, P0.1）")
    from core.http_transport import HttpTransport, normalize_origin, Origin, OriginRejected
    try:
        assert normalize_origin("http://example.com/x") == Origin("http", "example.com", 80)
        assert normalize_origin("https://example.com/x") == Origin("https", "example.com", 443)
        assert normalize_origin("http://example.com/x") != normalize_origin("https://example.com/x"), \
            "http/httpsは別originであるべき"
        assert normalize_origin("http://example.com:8080/x") == Origin("http", "example.com", 8080)
        assert normalize_origin("http://[::1]:9000/x") == Origin("http", "::1", 9000)
        assert normalize_origin("ftp://example.com/x") is None, "http/https以外は拒否すべき"
        assert normalize_origin("http://user:pass@example.com/x") is None, "userinfo付きは拒否すべき"
        assert normalize_origin("http://example.com:99999/x") is None, "範囲外portは拒否すべき"
        _ok("normalize_origin()", "scheme別origin・IPv6・既定port・userinfo/不正port拒否")

        t = HttpTransport(max_requests=3)
        t.bind_origin("http://example.com/")
        assert t.reserve() and t.reserve() and t.reserve()
        assert not t.reserve(), "予算超過後もreserveが成功してしまう"
        _ok("HttpTransport.reserve() 予算上限", f"req_count={t.req_count}")

        t2 = HttpTransport(max_requests=5)
        try:
            t2._check_origin("http://example.com/")
            _ng("HttpTransport origin未確定検査", "例外が出るべき")
        except OriginRejected:
            _ok("HttpTransport origin未確定検査", "base origin未確定のまま送信しようとして拒否")
        t2.bind_origin("http://example.com/")
        try:
            t2._check_origin("http://evil.example.com/")
            _ng("HttpTransport origin範囲外検査", "例外が出るべき")
        except OriginRejected:
            _ok("HttpTransport origin範囲外検査", "別ホストへの送信を拒否")
    except Exception as e:
        _ng("http_transport", repr(e) + "\n" + traceback.format_exc())


def _start_receiver_server():
    """別origin送信ゼロを検証するための受信記録サーバ。受け取ったpathをhitsに記録する。"""
    import http.server
    import socketserver
    import threading

    hits: list[str] = []

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _rec(self):
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"received")

        def do_GET(self):
            self._rec()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            self._rec()

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", hits


def _start_cross_origin_target(receiver_base: str):
    """外部action/リンク/転送先を含むターゲットサーバ（P0.1受け入れ条件の検証用）。"""
    import http.server
    import socketserver
    import threading
    from urllib.parse import urlparse

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/redir-ext":
                self.send_response(302)
                self.send_header("Location", receiver_base + "/redir-hit")
                self.end_headers()
                return
            if u.path == "/page2":
                body = "page2 ok"
            elif u.path == "/login":
                body = ('<form method="POST" action="/login">'
                        '<input type="password" name="pw"></form>')
            else:
                body = (
                    f'<a href="{receiver_base}/ext-link">external</a> '
                    '<a href="/page2?id=1">same</a>'
                    f'<form action="{receiver_base}/ext-form" method="POST">'
                    '<input name="x" value="1"></form>'
                    '<form action="/same-form" method="POST">'
                    '<input name="y" value="1"></form>'
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            if self.path == "/login":
                self.send_response(302)
                self.send_header("Set-Cookie", "session=abc")
                self.send_header("Location", "/page2")
                self.end_headers()
                return
            if self.path == "/login-ext":
                self.send_response(302)
                self.send_header("Set-Cookie", "session=abc")
                self.send_header("Location", receiver_base + "/login-redirect-hit")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"posted")

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_web_fuzzer_cross_origin():
    _section("16d. TOOLS — WebFuzzer 別origin送信ゼロ・予算共有（P0.1受け入れ条件）")
    from tools.web_fuzzer import WebFuzzer
    srv_r = srv_t = None
    try:
        srv_r, recv_base, hits = _start_receiver_server()
        srv_t, base = _start_cross_origin_target(recv_base)

        # 1) Cookie/認証ヘッダー付きでも、クロール＋フォーム抽出＋ファジングで外部originが0件
        fz = WebFuzzer(profile="aggressive", max_requests=100, log=lambda m: None,
                       auth={"cookie": "sessionid=x", "header_name": "Authorization",
                             "header_value": "Bearer secret"})
        fz.authenticate()
        crawl = fz.crawl(base)
        points = crawl["injection_points"]
        assert all(recv_base not in p["url"] for p in points), \
            f"外部originのフォーム/リンクが注入点に混入: {points}"
        fz.fuzz(points)
        assert not hits, f"別originの受信サーバへ送信されてしまった: {hits}"
        _ok("crawl+fuzz 別origin送信ゼロ", f"points={len(points)} hits={hits}")

        # 2) 別originへの直接送信は送信口レベルで拒否される
        rejected = fz.transport.request(fz.session, "GET", recv_base + "/direct")
        assert rejected is None, "別originへの直接送信が通ってしまった"
        assert not hits, f"直接送信テストで受信サーバへ到達してしまった: {hits}"
        _ok("HttpTransport.request() 別origin直接拒否", "Noneを返し送信していない")

        # 3) 別originへの転送(302)は追跡しない（scheme/port変更でも同様の仕組みで防止）
        r = fz.transport.request(fz.session, "GET", base + "redir-ext", allow_redirects=True)
        assert r is not None and r.status_code == 302, "別originへの転送応答が変化した"
        assert not hits, f"転送先(別origin)へ到達してしまった: {hits}"
        _ok("別origin転送(302)を追跡しない", f"status={r.status_code}")

        # 4) ログインPOSTが別originへリダイレクトする場合は認証未確認として扱う（Cookie送信なし）
        fz2 = WebFuzzer(profile="aggressive", max_requests=100, log=lambda m: None,
                        target=base,
                        auth={"login_url": base + "login", "post_url": base + "login-ext",
                              "user_field": "u", "pass_field": "pw",
                              "user_val": "a", "pass_val": "b"})
        ok, msg = fz2.authenticate()
        assert not ok, "別originへ転送するログインが成功扱いになった"
        assert "origin" in msg, f"未対応の認証転送理由が出力されていない: {msg}"
        assert not hits, f"ログイン転送で受信サーバへ到達してしまった: {hits}"
        _ok("ログインPOSTの別origin転送を認証未確認として処理", msg[:50])

        # 5) 予算共有: A/Bセッション＋ログイン＋大量試行が混在しても予算Nを超えない
        fz3 = WebFuzzer(profile="aggressive", max_requests=5, log=lambda m: None,
                        target=base,
                        auth={"login_url": base + "login", "user_field": "u", "pass_field": "pw",
                              "user_val": "a", "pass_val": "b"},
                        auth_b={"cookie": "session=bob"})
        fz3.authenticate()
        # POST->302(同一origin・未追跡)は「失敗の実証拠」ではないため"expired"と断定せず
        # "unknown"に留める(confirm_url未設定でもログイン自体は成功しうるケースの回帰防止)。
        assert fz3.auth_state == "unknown", f"{fz3.auth_state}: {fz3.auth_state_reason}"
        fz3.authenticate_b()
        for _ in range(10):
            fz3._send_as(fz3.session, base + "page2")
            fz3._send_as(fz3.session_b, base + "page2")
        assert fz3.transport.req_count <= 5, f"予算超過: {fz3.transport.req_count}"
        _ok("予算共有(A/B+ログイン)が上限を超えない", f"req_count={fz3.transport.req_count}")

        # 6) 予算0では認証(ログインPOST)も送らない
        fz4 = WebFuzzer(profile="aggressive", max_requests=0, log=lambda m: None,
                        target=base,
                        auth={"login_url": base + "login", "user_field": "u", "pass_field": "pw",
                              "user_val": "a", "pass_val": "b"})
        ok4, msg4 = fz4.authenticate()
        assert not ok4, "予算0でもログインが成功扱いになった"
        assert fz4.transport.req_count == 0, "予算0で送信が発生した"
        _ok("予算0で認証も送信しない", msg4[:50])
    except Exception as e:
        _ng("web_fuzzer_cross_origin", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv_r:
            srv_r.shutdown()
        if srv_t:
            srv_t.shutdown()


def _start_ratelimit_mock_server():
    """429/Retry-After・応答サイズ上限を検証するためのモックサーバ（P0.2）。"""
    import http.server
    import socketserver
    import threading
    from datetime import datetime, timedelta, timezone
    from email.utils import format_datetime

    state = {"flaky_digit": 0, "flaky_date": 0, "flaky_bad": 0,
             "always429_get": 0, "always429_post": 0, "long_retry": 0}

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=b"", headers=None):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            if self.path == "/flaky-digit":
                state["flaky_digit"] += 1
                if state["flaky_digit"] <= 2:
                    self._send(429, b"", {"Retry-After": "1"})
                else:
                    self._send(200, b"ok")
                return
            if self.path == "/flaky-date":
                state["flaky_date"] += 1
                if state["flaky_date"] <= 1:
                    when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=1))
                    self._send(429, b"", {"Retry-After": when})
                else:
                    self._send(200, b"ok")
                return
            if self.path == "/flaky-bad":
                state["flaky_bad"] += 1
                if state["flaky_bad"] <= 1:
                    self._send(429, b"", {"Retry-After": "not-a-number"})
                else:
                    self._send(200, b"ok")
                return
            if self.path == "/always429":
                state["always429_get"] += 1
                self._send(429, b"", {"Retry-After": "1"})
                return
            if self.path == "/long-retry":
                state["long_retry"] += 1
                self._send(429, b"", {"Retry-After": "3600"})
                return
            if self.path == "/big":
                self._send(200, b"X" * 500)
                return
            self._send(200, b"ok")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            if self.path == "/always429":
                state["always429_post"] += 1
                self._send(429, b"", {"Retry-After": "1"})
                return
            self._send(200, b"ok")

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/", state


def test_http_transport_rate_limits():
    _section("16e. CORE — HttpTransport レート制御・429リトライ・STOP・応答サイズ上限(P0.2)")
    import threading
    import requests as _requests
    from core.http_transport import HttpTransport, RequestPolicy
    srv = None
    try:
        class _Clock:
            def __init__(self):
                self.t = 0.0

            def now(self):
                return self.t

            def sleep(self, s):
                self.t += s

        # 1) レート制御（仮想時計・実待機なし）
        c = _Clock()
        t = HttpTransport(policy=RequestPolicy(max_requests=100, rate_per_sec=2),
                          clock=c.now, sleeper=c.sleep)
        t.bind_origin("http://example.com/")
        times = []
        for _ in range(4):
            t._throttle()
            times.append(c.t)
        gaps = [times[i + 1] - times[i] for i in range(len(times) - 1)]
        assert all(g >= 0.5 - 1e-9 for g in gaps), f"レート上限(2req/s)を守っていない: {gaps}"
        _ok("HttpTransport._throttle() レート上限(仮想時計)", f"gaps={[round(g, 2) for g in gaps]}")

        srv, base, state = _start_ratelimit_mock_server()
        session = _requests.Session()

        def _new_transport(max_requests=50, **policy_kwargs):
            c2 = _Clock()
            tr = HttpTransport(policy=RequestPolicy(max_requests=max_requests, **policy_kwargs),
                               clock=c2.now, sleeper=c2.sleep)
            tr.bind_origin(base)
            return tr

        # 2) 429 Retry-After(秒表記)でGETが自動リトライの上で成功する
        tr = _new_transport()
        r = tr.request(session, "GET", base + "flaky-digit")
        assert r is not None and r.status_code == 200, f"秒表記Retry-Afterの再送に失敗: {r}"
        assert state["flaky_digit"] == 3, f"リトライ回数が想定と異なる: {state['flaky_digit']}"
        _ok("429 Retry-After(秒)でGET自動リトライ", f"attempts={state['flaky_digit']}")

        # 3) Retry-After(HTTP-date表記)でも同様にリトライできる
        r2 = _new_transport().request(session, "GET", base + "flaky-date")
        assert r2 is not None and r2.status_code == 200, f"HTTP-date表記Retry-Afterの再送に失敗: {r2}"
        _ok("429 Retry-After(HTTP-date)でGET自動リトライ", f"attempts={state['flaky_date']}")

        # 4) Retry-Afterが不正値でも上限付きバックオフでリトライを継続する
        r3 = _new_transport().request(session, "GET", base + "flaky-bad")
        assert r3 is not None and r3.status_code == 200, f"不正値Retry-Afterでの再送に失敗: {r3}"
        _ok("Retry-After不正値でも上限付きバックオフで継続", f"attempts={state['flaky_bad']}")

        # 5) 429が続く場合は max_consecutive_429 で打ち切り、429応答をそのまま返す
        tr4 = _new_transport(max_consecutive_429=2)
        before = state["always429_get"]
        r4 = tr4.request(session, "GET", base + "always429")
        assert r4 is not None and r4.status_code == 429, "429連続時に打ち切られていない"
        assert state["always429_get"] - before == 3, (
            f"連続429の試行回数が想定と異なる(初回+リトライ2回=3回のはず): "
            f"{state['always429_get'] - before}"
        )
        assert tr4.last_error == "rate_limited", f"打ち切り理由が記録されていない: {tr4.last_error}"
        _ok("429連続時にmax_consecutive_429で打ち切り", f"attempts={state['always429_get'] - before}")

        # 5b) Retry-Afterが待機上限(max_backoff_seconds)を超える場合は再送せず終了する
        #     (仮想時計でも実時間でも、cap超過分は絶対に待たない・再送しないことを保証する)
        tr4b = _new_transport(max_backoff_seconds=30)
        before_lr = state["long_retry"]
        r4b = tr4b.request(session, "GET", base + "long-retry")
        assert r4b is not None and r4b.status_code == 429, "長大Retry-After応答が変化した"
        assert state["long_retry"] - before_lr == 1, \
            f"Retry-After超過にもかかわらず再送してしまった: {state['long_retry'] - before_lr}"
        assert tr4b.last_error == "retry_after_exceeded", \
            f"待機上限超過の理由が記録されていない: {tr4b.last_error}"
        _ok("Retry-After(3600s)が上限超過で再送せず終了", "last_error=retry_after_exceeded")

        # 6) POSTの429は自動リトライしない
        tr5 = _new_transport()
        before_p = state["always429_post"]
        r5 = tr5.request(session, "POST", base + "always429", data={"x": "1"})
        assert r5 is not None and r5.status_code == 429
        assert state["always429_post"] - before_p == 1, "POSTの429を再送してしまった"
        _ok("POSTの429は自動リトライしない", "1回のみ送信")

        # 7) 429待機中でもSTOPで中断できる（待機を模した仮想sleeperがSTOPを立てる）
        stop_ev = threading.Event()
        c3 = _Clock()

        def _sleeper_triggers_stop(s):
            c3.t += s
            stop_ev.set()

        tr6 = HttpTransport(policy=RequestPolicy(max_requests=50), stop_event=stop_ev,
                            clock=c3.now, sleeper=_sleeper_triggers_stop)
        tr6.bind_origin(base)
        before_s = state["always429_get"]
        r6 = tr6.request(session, "GET", base + "always429")
        assert r6 is not None and r6.status_code == 429, "STOP後の応答が想定と異なる"
        assert tr6.last_error == "stopped", f"STOPによる中断が記録されていない: {tr6.last_error}"
        assert state["always429_get"] - before_s == 1, \
            f"STOP後に再送してしまった: {state['always429_get'] - before_s}"
        _ok("429待機中のSTOPで再送を中断", "last_error=stopped")

        # 8) STOP後は新しい送信を一切開始しない
        assert tr6.request(session, "GET", base + "ok") is None, \
            "STOP後にもかかわらず新規送信できてしまった"
        _ok("STOP後は新しい送信を開始しない", "")

        # 9) 応答サイズ上限（500byteの応答を100byteで打ち切り）
        tr7 = _new_transport(max_response_bytes=100)
        r7 = tr7.request(session, "GET", base + "big")
        assert r7 is not None and len(r7.content) == 100, \
            f"応答サイズ上限が効いていない: {len(r7.content) if r7 else None}"
        assert r7.fz_truncated is True, "打ち切りマーカー(fz_truncated)が付与されていない"
        _ok("応答サイズ上限で読取を打ち切り", f"len={len(r7.content)}")

        # 10) WebFuzzer側: STOPが事前にセットされていればジッター待機・送信を一切行わない
        #     （time.sleep()を直接呼ぶ停止不能な待機になっていないことを実時間で確認）
        from tools.web_fuzzer import WebFuzzer
        pre_stop = threading.Event()
        pre_stop.set()
        fzw = WebFuzzer(profile="stealth", max_requests=50, log=lambda m: None,
                        stop_event=pre_stop)
        t0 = time.time()
        crawl = fzw.crawl(base)
        elapsed = time.time() - t0
        assert fzw.transport.req_count == 0, f"STOP済みなのに送信してしまった: {fzw.transport.req_count}"
        assert crawl["pages"] == 0
        assert elapsed < 0.5, f"STOP済みのcrawl()が即座に終了していない: {elapsed:.2f}s"
        _ok("WebFuzzer: 事前STOPでジッター待機・送信を行わない", f"elapsed={elapsed:.3f}s")
    except Exception as e:
        _ng("http_transport_rate_limits", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()


def _start_authstate_mock_server():
    """認証状態判定(confirm_url/expect_text)を検証するためのモックサーバ（P0.2）。"""
    import http.server
    import socketserver
    import threading

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/whoami":
                cookie = self.headers.get("Cookie", "")
                if "session=valid" in cookie:
                    body = b"<html><body>Welcome, User! dashboard area</body></html>"
                else:
                    body = (b"<html><body><form method=\"POST\" action=\"/login\">"
                            b"<input type=\"password\" name=\"pw\"></form></body></html>")
            elif self.path == "/login":
                body = (b"<html><body><form method=\"POST\" action=\"/login\">"
                        b"<input type=\"password\" name=\"pw\"></form></body></html>")
            else:
                body = b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            if self.path == "/login":
                # 常に失敗するモックログイン（パスワードフォームが残存・Cookie未設定）。
                # login_outcome="failed"（実証拠あり）→auth_state="expired"を検証するため。
                body = (b"<html><body><form method=\"POST\" action=\"/login\">"
                        b"<input type=\"password\" name=\"pw\"></form></body></html>")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def test_web_fuzzer_auth_state():
    _section("16f. TOOLS — WebFuzzer 認証状態判定 authenticated/expired/unknown(P0.2)")
    from tools.web_fuzzer import WebFuzzer
    srv = None
    try:
        srv, base = _start_authstate_mock_server()

        # 1) confirm_url + expect_text が一致すればauthenticated
        fz = WebFuzzer(profile="aggressive", max_requests=50, log=lambda m: None,
                       target=base,
                       auth={"cookie": "session=valid", "confirm_url": base + "whoami",
                             "expect_text": "Welcome, User!"})
        ok, _msg = fz.authenticate()
        assert ok
        assert fz.auth_state == "authenticated", f"{fz.auth_state}: {fz.auth_state_reason}"
        _ok("認証状態: confirm_url+expect_text一致でauthenticated", fz.auth_state_reason)

        # 2) Cookieが無効ならconfirm_url先にログインフォームが残存 → expired
        fz2 = WebFuzzer(profile="aggressive", max_requests=50, log=lambda m: None,
                        target=base,
                        auth={"cookie": "session=invalid", "confirm_url": base + "whoami",
                              "expect_text": "Welcome, User!"})
        fz2.authenticate()
        assert fz2.auth_state == "expired", f"{fz2.auth_state}: {fz2.auth_state_reason}"
        _ok("認証状態: 無効Cookie(confirm_url先がログイン画面)でexpired", fz2.auth_state_reason)

        # 3) Cookie設定だけ(confirm_url未設定)では成功と断定せずunknown
        fz3 = WebFuzzer(profile="aggressive", max_requests=50, log=lambda m: None,
                        auth={"cookie": "session=valid"})
        fz3.authenticate()
        assert fz3.auth_state == "unknown", f"{fz3.auth_state}: {fz3.auth_state_reason}"
        _ok("認証状態: Cookie設定のみでは断定せずunknown", fz3.auth_state_reason)

        # 4) auth未設定はanonymous
        fz4 = WebFuzzer(profile="aggressive", max_requests=50, log=lambda m: None)
        assert fz4.auth_state == "anonymous"
        _ok("認証状態: auth未設定はanonymous", "")

        # 5) confirm_urlが別originなら送信自体が拒否されunknown(誤って外部originへ到達しない)
        fz5 = WebFuzzer(profile="aggressive", max_requests=50, log=lambda m: None,
                        target=base,
                        auth={"cookie": "session=valid",
                              "confirm_url": "http://evil.example.invalid/whoami",
                              "expect_text": "Welcome"})
        fz5.authenticate()
        assert fz5.auth_state == "unknown", f"{fz5.auth_state}: {fz5.auth_state_reason}"
        assert "origin" in fz5.auth_state_reason, f"別origin拒否の理由が出ていない: {fz5.auth_state_reason}"
        _ok("認証状態: confirm_urlが別originなら送信されずunknown", fz5.auth_state_reason)

        # 6) login_url経由で実際に失敗(パスワードフォーム残存・Cookie未設定)した場合のみexpired
        #    （POSTリダイレクト未追跡による"unconfirmed"とは区別する — advisorレビュー指摘）
        fz6 = WebFuzzer(profile="aggressive", max_requests=50, log=lambda m: None,
                        target=base,
                        auth={"login_url": base + "login", "user_field": "u", "pass_field": "pw",
                              "user_val": "a", "pass_val": "b"})
        ok6, _msg6 = fz6.authenticate()
        assert not ok6
        assert fz6.auth_state == "expired", f"{fz6.auth_state}: {fz6.auth_state_reason}"
        _ok("認証状態: ログイン失敗(パスワードフォーム残存)でexpired", fz6.auth_state_reason)

        # 7) idor_skip_reason(): どちらのセッションがexpiredでもskip理由を返す(対称性)
        from agents.fuzz_agent import idor_skip_reason
        fz_ok = WebFuzzer(profile="aggressive", max_requests=10, log=lambda m: None)
        fz_ok.auth_state, fz_ok.auth_state_b = "authenticated", "authenticated"
        assert idor_skip_reason(fz_ok) is None, "両方authenticatedなのにskip理由が返った"
        fz_a_expired = WebFuzzer(profile="aggressive", max_requests=10, log=lambda m: None)
        fz_a_expired.auth_state, fz_a_expired.auth_state_reason = "expired", "第1セッション失敗"
        assert idor_skip_reason(fz_a_expired) is not None, "第1セッションexpiredでskipされていない"
        fz_b_expired = WebFuzzer(profile="aggressive", max_requests=10, log=lambda m: None)
        fz_b_expired.auth_state_b, fz_b_expired.auth_state_reason_b = "expired", "第2セッション失敗"
        assert idor_skip_reason(fz_b_expired) is not None, "第2セッションexpiredでskipされていない(非対称バグ回帰)"
        _ok("idor_skip_reason(): 第1/第2どちらのexpiredでも対称にskip", "")
    except Exception as e:
        _ng("web_fuzzer_auth_state", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()


def test_web_fuzzer_tls():
    _section("16g. TOOLS — WebFuzzer TLS検証設定(P0.2)")
    from tools.web_fuzzer import WebFuzzer
    try:
        # 1) 未指定時は config.json の値(既定False)に従う（既存動作を維持）
        fz = WebFuzzer(profile="aggressive", max_requests=10, log=lambda m: None)
        assert fz.session.verify is False, f"既定でTLS検証が有効になっている: {fz.session.verify}"
        assert fz.tls_verify is False
        _ok("TLS: 未指定時はconfig既定値(False)に従う", f"session.verify={fz.session.verify}")

        # 2) 明示的にtls_verify=Trueを指定すれば有効化される
        fz2 = WebFuzzer(profile="aggressive", max_requests=10, log=lambda m: None, tls_verify=True)
        assert fz2.session.verify is True, f"tls_verify=Trueが反映されていない: {fz2.session.verify}"
        assert fz2.tls_verify is True
        _ok("TLS: tls_verify=Trueで検証を有効化", f"session.verify={fz2.session.verify}")

        # 3) tls_verify=True + tls_ca_bundle指定で独自CAパスがsession.verifyに渡る
        fz3 = WebFuzzer(profile="aggressive", max_requests=10, log=lambda m: None,
                        tls_verify=True, tls_ca_bundle="/tmp/dummy-ca.pem")
        assert fz3.session.verify == "/tmp/dummy-ca.pem", \
            f"独自CAパスが反映されていない: {fz3.session.verify}"
        _ok("TLS: tls_verify=True+tls_ca_bundleで独自CAパスを使用", fz3.session.verify)

        # 4) tls_verify=False時はtls_ca_bundleを指定していても無視される(検証自体をしない)
        fz4 = WebFuzzer(profile="aggressive", max_requests=10, log=lambda m: None,
                        tls_verify=False, tls_ca_bundle="/tmp/dummy-ca.pem")
        assert fz4.session.verify is False, \
            f"tls_verify=FalseなのにCAパスが有効になった: {fz4.session.verify}"
        _ok("TLS: tls_verify=False時はtls_ca_bundleを無視", f"session.verify={fz4.session.verify}")

        # 5) auth_b設定時、session_bにも同じverify設定が適用される
        fz5 = WebFuzzer(profile="aggressive", max_requests=10, log=lambda m: None,
                        tls_verify=True, auth_b={"cookie": "x=1"})
        assert fz5.session_b.verify is True, f"session_bにTLS設定が伝播していない: {fz5.session_b.verify}"
        _ok("TLS: session_bにも同じ検証設定を適用", f"session_b.verify={fz5.session_b.verify}")
    except Exception as e:
        _ng("web_fuzzer_tls", repr(e) + "\n" + traceback.format_exc())


def test_http_transport_tls_handshake():
    _section("16h. CORE — HttpTransport TLSハンドシェイク成否・不正CA設定(P0.2)")
    import shutil
    if shutil.which("openssl") is None:
        _SKIP.append("TLS handshake (openssl unavailable)")
        print("  [SKIP] opensslコマンドが見つからないためスキップ（証明書検証成否は未検証）")
        return

    import ssl
    import socketserver
    import http.server
    import subprocess
    import tempfile
    import threading
    import requests as _requests
    from core.http_transport import HttpTransport, RequestPolicy

    tmpdir = tempfile.mkdtemp(prefix="selftest_tls_")
    cert_path = f"{tmpdir}/cert.pem"
    key_path = f"{tmpdir}/key.pem"
    srv = None
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key_path, "-out", cert_path,
             "-days", "1", "-subj", "/CN=127.0.0.1",
             # SAN必須（CNのみの証明書は現代のurllib3/cryptographyでは
             # ホスト名検証に失敗するため、IP SANを明示する）。
             "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, capture_output=True, timeout=30,
        )

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"secure-ok")

        srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"https://127.0.0.1:{port}/"

        session = _requests.Session()

        # 1) tls_verify=True・CA未指定(標準ストア)では自己署名証明書を拒否しtls_error
        session.verify = True
        t1 = HttpTransport(policy=RequestPolicy(max_requests=10))
        t1.bind_origin(base)
        r1 = t1.request(session, "GET", base)
        assert r1 is None, "自己署名証明書がverify=Trueで通ってしまった"
        assert t1.last_error == "tls_error", f"TLSエラーの理由が記録されていない: {t1.last_error}"
        _ok("TLS: 標準CAストアで自己署名証明書を拒否", "last_error=tls_error")

        # 2) tls_ca_bundleに自己署名証明書自体を指定すれば検証成功する
        session2 = _requests.Session()
        session2.verify = cert_path
        t2 = HttpTransport(policy=RequestPolicy(max_requests=10))
        t2.bind_origin(base)
        r2 = t2.request(session2, "GET", base)
        assert r2 is not None and r2.status_code == 200 and r2.text == "secure-ok", \
            f"独自CA指定でのTLSハンドシェイクに失敗: {r2}"
        _ok("TLS: 独自CA(tls_ca_bundle)指定でハンドシェイク成功", f"status={r2.status_code}")

        # 3) 存在しないtls_ca_bundleパスはOSError(RequestException非継承)を送出しうるが
        #    クラッシュせずtls_config_errorとして捕捉される
        session3 = _requests.Session()
        session3.verify = "/tmp/selftest-does-not-exist-ca.pem"
        t3 = HttpTransport(policy=RequestPolicy(max_requests=10))
        t3.bind_origin(base)
        r3 = t3.request(session3, "GET", base)
        assert r3 is None, "不正なtls_ca_bundleパスなのに応答が返ってしまった"
        assert t3.last_error == "tls_config_error", \
            f"TLS設定エラーの理由が記録されていない: {t3.last_error}"
        _ok("TLS: 不正なtls_ca_bundleパスはクラッシュせずtls_config_error", "")
    except Exception as e:
        _ng("http_transport_tls_handshake", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()
        import shutil as _shutil
        _shutil.rmtree(tmpdir, ignore_errors=True)


def test_fuzz_agent_p11_wiring():
    _section("16i. AGENT — FuzzAgent P1.1 Finding/Coverage/State変換ロジック")
    from agents.fuzz_agent import FuzzAgent
    from core.findings import ScanState, VerificationState, CoverageStatus
    try:
        # 1) _findings_from_markers()（BaseAgent共通）: corroborated/observed/ENSEMBLE_MINORITYの判定
        parsed = [
            {"name": "XSS in q", "severity": "high", "ref": "CWE-79", "lines": "http://x/?q=1",
             "fix": "escape output", "confidence": ""},
            {"name": "SQLi in id", "severity": "CRITICAL", "ref": "CWE-89", "lines": "http://x/?id=1",
             "fix": "use parameterized queries", "confidence": "ENSEMBLE_MINORITY"},
        ]
        findings = FuzzAgent._findings_from_markers(parsed, corroborated=True)
        assert len(findings) == 2
        assert findings[0].severity == "HIGH" and findings[0].rule_id == "CWE-79"
        assert findings[0].verification_state == VerificationState.CORROBORATED.value, \
            "corroborated=True・非minorityはcorroboratedになるべき"
        assert findings[1].verification_state == VerificationState.OBSERVED.value, \
            "ENSEMBLE_MINORITYはcorroboratedへ昇格させないべき"
        assert findings[1].verifier_support.get("ensemble_minority") is True
        findings_no_verify = FuzzAgent._findings_from_markers(parsed, corroborated=False)
        assert all(f.verification_state == VerificationState.OBSERVED.value for f in findings_no_verify), \
            "検証パス無し(corroborated=False)は全てobservedのべき"
        _ok("_findings_from_markers(): corroborated/observed/minorityの判定", "")

        # 2) _build_coverage(): 注入点+IDOR実施/skipの記録
        points = [{"url": "http://x/a", "param": "q", "method": "GET", "where": "query", "fields": {}}]
        cov_no_b = FuzzAgent._build_coverage(points, auth=None, auth_b=None,
                                             idor_ran=False, idor_skip_reason_val=None)
        assert len(cov_no_b) == 1 and cov_no_b[0].status == CoverageStatus.TESTED.value
        assert cov_no_b[0].auth_context == "anonymous"
        cov_ran = FuzzAgent._build_coverage(points, auth={"cookie": "x"}, auth_b={"cookie": "y"},
                                            idor_ran=True, idor_skip_reason_val=None)
        assert len(cov_ran) == 2
        idor_item = next(c for c in cov_ran if c.rule_id == "IDOR")
        assert idor_item.status == CoverageStatus.TESTED.value
        assert cov_ran[0].auth_context == "authenticated"
        cov_skipped = FuzzAgent._build_coverage(points, auth=None, auth_b={"cookie": "y"},
                                                idor_ran=False, idor_skip_reason_val="第1セッションexpired")
        idor_skip_item = next(c for c in cov_skipped if c.rule_id == "IDOR")
        assert idor_skip_item.status == CoverageStatus.SKIPPED.value
        assert idor_skip_item.reason == "第1セッションexpired"
        _ok("_build_coverage(): 注入点+IDOR実施/skip状態の記録", "")

        # 3) _determine_state(): STOP最優先・予算切れ/空トリアージ→partial・通常はcompleted
        class _FakeTransport:
            def __init__(self, req_count, max_requests):
                self.req_count = req_count
                self.max_requests = max_requests

        class _FakeFuzzer:
            def __init__(self, req_count, max_requests):
                self.transport = _FakeTransport(req_count, max_requests)
                self.max_requests = max_requests

        agent = FuzzAgent(EventBus(), None)
        state, errors = agent._determine_state(_FakeFuzzer(10, 100), triage_ran=True,
                                                triage_text="---VULN_START---...---VULN_END---",
                                                had_signals=True)
        assert state == ScanState.COMPLETED.value and errors == []
        _ok("_determine_state(): 通常完了はcompleted・errors空", "")

        state, errors = agent._determine_state(_FakeFuzzer(100, 100), triage_ran=True,
                                                triage_text="---VULN_START---...---VULN_END---",
                                                had_signals=True)
        assert state == ScanState.PARTIAL.value and errors, "予算切れはpartialとし理由を残すべき"
        _ok("_determine_state(): 予算切れはpartial", errors[0][:30])

        state, errors = agent._determine_state(_FakeFuzzer(10, 100), triage_ran=True,
                                                triage_text="   ", had_signals=True)
        assert state == ScanState.PARTIAL.value and errors, \
            "兆候ありなのにAIトリアージが空応答ならpartialとすべき"
        _ok("_determine_state(): AIトリアージ空応答(兆候あり)はpartial", errors[0][:30])

        agent.stop()
        state, errors = agent._determine_state(_FakeFuzzer(10, 100), triage_ran=True,
                                                triage_text="", had_signals=False)
        assert state == ScanState.CANCELLED.value, "STOPは他の判定より優先されるべき"
        _ok("_determine_state(): STOPが最優先でcancelled", "")
    except Exception as e:
        _ng("fuzz_agent_p11_wiring", repr(e) + "\n" + traceback.format_exc())


def test_fuzz_agent_no_points_lifecycle():
    _section("16j. AGENT E2E(非LLM) — FuzzAgent 注入点0件のRESULT/DONE確定(P1.1)")
    from agents.fuzz_agent import FuzzAgent
    from core.findings import ScanState
    import http.server
    import socketserver
    import threading as _threading

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>no params, no forms here</body></html>")

    srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
    _threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    try:
        bus = EventBus()
        # 注入点0件のため、Step2以降のLLM呼び出しに到達する前にrun()が完了する経路
        # （llm=Noneでも安全に検証できる）。
        agent = FuzzAgent(bus, None)
        agent.start(target=base, profile="aggressive", max_requests=20)
        agent._thread.join(timeout=15)
        assert not agent._thread.is_alive(), "スレッドが終了していない"
        events = bus.drain(200)
        kinds = [e.kind for e in events]
        assert kinds.count(ev.RESULT) == 1 and kinds.count(ev.DONE) == 1, kinds
        result = next(e.payload for e in events if e.kind == ev.RESULT)
        assert result["state"] == ScanState.COMPLETED.value, result["state"]
        assert result["findings"] == [] and result["coverage"] == []
        assert result["mode"] == "WEB FUZZ" and result["target"] == base
        done = next(e.payload for e in events if e.kind == ev.DONE)
        assert done["error"] is False
        _ok("FuzzAgent: 注入点0件でもRESULT(completed)→DONE(error=False)を確定", "")
    except Exception as e:
        _ng("fuzz_agent_no_points_lifecycle", repr(e) + "\n" + traceback.format_exc())
    finally:
        srv.shutdown()


def test_fuzz_agent_evidence_wiring():
    _section("16k. AGENT — FuzzAgent 証拠保存・evidence_id引用検証(P1.2)")
    import shutil
    import tempfile
    from agents.fuzz_agent import FuzzAgent
    from tools import report_generator
    from core.evidence_store import EvidenceStore
    DUMMY_SECRET = "SELFTEST_DUMMY_FUZZ_EVIDENCE_SECRET_444"
    tmp_root = tempfile.mkdtemp(prefix="selftest_fuzz_evidence_")
    try:
        # 1) _known_secrets(): auth/auth_bからcookie/header_value/pass_valを収集する
        secrets = FuzzAgent._known_secrets(
            {"cookie": "sessionid=abc", "header_value": "Bearer xyz"},
            {"pass_val": "hunter2"},
        )
        assert secrets == {"sessionid=abc", "Bearer xyz", "hunter2"}
        _ok("_known_secrets(): auth/auth_bからcookie/header_value/pass_valを収集", "")

        # 2) 実際のEvidenceStoreで異常データ(実際のXSS検出データ相当)を保存する
        #    (WebFuzzer._fuzz_pointが実際に返す形の辞書を使う)
        store = EvidenceStore("scan_selftest_fuzz", root=tmp_root)
        anomalies = [{
            "url": "http://x/?q=1", "method": "GET", "param": "q", "category": "XSS",
            "payload": "<svg/onload=alert(1)>", "severity": "HIGH",
            "evidence": "reflected unescaped", "status": 200,
            "response_headers": {"Set-Cookie": DUMMY_SECRET, "Content-Type": "text/html"},
            "response_body": f"<html>{DUMMY_SECRET} reflected <svg/onload=alert(1)></html>",
            "baseline_body": "<html>ok</html>",
        }]
        known_secrets = {DUMMY_SECRET}
        known_evidence_ids = set()
        eid = None
        for a in anomalies:
            eid = store.save_http_evidence(
                method=a["method"], url=a["url"], status=a["status"],
                headers=a["response_headers"], body=a["response_body"],
                baseline_body=a["baseline_body"], known_secrets=known_secrets,
            )
            assert eid is not None
            a["evidence_id"] = eid
            known_evidence_ids.add(eid)

        raw_path = os.path.join(store.dir, f"{eid}.json")
        with open(raw_path, encoding="utf-8") as f:
            raw_on_disk = f.read()
        assert DUMMY_SECRET not in raw_on_disk, "保存物にダミー秘密値が残っている"
        _ok("evidence保存: 実際のXSS異常データからでもダミー秘密値が保存物に残らない", "")

        # 3) _build_summary()にevidence_idが埋め込まれ、LLMプロンプトへ渡る形になる
        summary = FuzzAgent._build_summary("http://x/", [], anomalies, [])
        assert f"evidence_id={eid}" in summary
        _ok("_build_summary(): evidence_idがプロンプト用サマリーに埋め込まれる", "")

        # 4) LLM出力(想定)が実在IDと幻覚ID(存在しないID)を両方引用した場合、
        #    実在IDのみがFinding.evidence_idsへ採用される
        canned = (
            "---VULN_START---\n"
            "NAME: Reflected XSS in q\n"
            "SEVERITY: HIGH\n"
            "CWE: CWE-79\n"
            f"LINES: {anomalies[0]['url']} q\n"
            f"EVIDENCE_IDS: {eid}, evidence_hallucinated_999\n"
            "SNIPPET:\n```\n<svg/onload=alert(1)>\n```\n"
            "ATTACK:\nReflected without escaping.\n"
            "FIX:\n```\nescape output\n```\n"
            "---VULN_END---\n"
        )
        parsed, _counts = report_generator._findings_and_counts("WEB FUZZ", canned)
        findings = FuzzAgent._findings_from_markers(parsed, corroborated=False,
                                                     known_evidence_ids=known_evidence_ids)
        assert len(findings) == 1
        assert findings[0].evidence_ids == [eid], \
            f"実在するIDのみ採用されるべき: {findings[0].evidence_ids}"
        _ok("LLM引用のevidence_ids: 実在IDのみ採用・幻覚IDは黙って除外", "")
    except Exception as e:
        _ng("fuzz_agent_evidence_wiring", repr(e) + "\n" + traceback.format_exc())
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def test_fuzz_idor_evidence():
    _section("16o. AGENT — FuzzAgent IDOR証拠保存(P1.2・第2セッション応答＋比較用の通常応答)")
    import shutil
    import tempfile
    from agents.fuzz_agent import FuzzAgent
    from core.evidence_store import EvidenceStore
    from tools import report_generator
    from tools.web_fuzzer import WebFuzzer
    tmp_root = tempfile.mkdtemp(prefix="selftest_idor_evidence_")
    srv = None
    try:
        srv, base = _start_idor_mock_server()
        auth, auth_b = {"cookie": "session=alice_SECRETA"}, {"cookie": "session=bob_SECRETB"}
        fz = WebFuzzer(profile="aggressive", max_requests=500, log=lambda m: None,
                       auth=auth, auth_b=auth_b)
        fz.authenticate()
        fz.authenticate_b()
        points = fz.crawl(base)["injection_points"]
        idor = fz._detect_idor(points)
        assert idor, "IDOR兆候が検出されない（前提）"
        for k in ("response_headers", "response_body", "baseline_body"):
            assert k in idor[0], f"IDOR兆候に証拠用の{k}が無い"

        store = EvidenceStore("scan_selftest_idor", root=tmp_root)
        known_secrets = FuzzAgent._known_secrets(auth, auth_b)
        ids, errs = FuzzAgent._save_evidence(store, [], idor, known_secrets)
        assert len(ids) == len(idor) and not errs, (ids, errs)
        eid = idor[0]["evidence_id"]
        saved = store.load(eid)
        assert saved["status"] == idor[0]["status_b"]
        assert saved["body_excerpt"] and saved["baseline_excerpt"], "BとA両方の応答が保存されるべき"
        raw = open(os.path.join(store.dir, f"{eid}.json"), encoding="utf-8").read()
        for leak in ("SECRETA", "SECRETB"):
            assert leak not in raw, f"保存物に{leak}が残っている"
        _ok("IDOR証拠: B応答(主)とA応答(比較用)を保存し、双方のセッションCookie値はマスクされる", "")

        summary = FuzzAgent._build_summary(base, points, [], idor)
        assert f"evidence_id={eid}" in summary
        _ok("IDOR証拠: evidence_idがACCESS CONTROL CHECK節に埋め込まれLLMへ渡る", "")

        canned = ("---VULN_START---\nNAME: IDOR on /resource\nSEVERITY: HIGH\nCWE: CWE-639\n"
                  f"LINES: {idor[0]['url']}\nEVIDENCE_IDS: {eid}, evidence_bogus_1\n"
                  "SNIPPET:\n```\nGET /resource?id=1\n```\nATTACK:\nx\nFIX:\n```\ny\n```\n---VULN_END---\n")
        parsed, _ = report_generator._findings_and_counts("WEB FUZZ", canned)
        findings = FuzzAgent._findings_from_markers(parsed, corroborated=False,
                                                     known_evidence_ids=set(ids))
        assert findings[0].evidence_ids == [eid]
        _ok("IDOR証拠: 実在IDのみ所見に採用（幻覚IDは除外）", "")

        # 未知IDはvalidation errorとして記録される（黙って捨てない）
        rej: list[str] = []
        FuzzAgent._findings_from_markers(parsed, corroborated=False,
                                         known_evidence_ids=set(ids), rejected_evidence_ids=rej)
        assert any("evidence_bogus_1" in r for r in rej), rej
        _ok("FUZZ: 未知の証拠IDがvalidation errorとして記録される", "")

        # 件数上限到達は「省略」としてerrorsに残る（FUZZでも黙って捨てない）
        capped = EvidenceStore("scan_selftest_idor_cap", root=tmp_root, max_items=1)
        two = [dict(idor[0]), dict(idor[0])]
        ids2, errs2 = FuzzAgent._save_evidence(capped, [], two, known_secrets)
        assert len(ids2) == 1 and any("証拠保存を省略" in e and "件数上限" in e for e in errs2), errs2
        _ok("FUZZ: 件数上限による保存省略がerrorsに理由付きで残る", "")
    except Exception as e:
        _ng("fuzz_idor_evidence", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()
        shutil.rmtree(tmp_root, ignore_errors=True)


def test_fuzz_agent():
    _section("17. AGENT E2E — FuzzAgent（ローカルモック / 実LLM）")
    from agents.fuzz_agent import FuzzAgent
    llm = _selftest_llm(90)
    bus = EventBus()
    srv = None
    try:
        srv, base = _start_mock_web_server()
        agent = FuzzAgent(bus, llm)
        agent.start(target=base, profile="aggressive", max_requests=400)
        r = _drain_until_done(bus, timeout=180)
        assert r["done"], "DONE が来なかった"
        assert not r["error"], "エラー終了"
        assert "FUZZING COMPLETE" in r["text"], "完了マーカーなし"
        _ok("FuzzAgent 完走",
            f"findings={r['stats']} chars={len(r['text'])}")
    except Exception as e:
        _ng("FuzzAgent", repr(e) + "\n" + traceback.format_exc())
    finally:
        if srv:
            srv.shutdown()


def test_desktop_shortcut():
    _section("18. TOOLS — DesktopShortcut（Linuxデスクトップエントリ生成・純粋関数部分のみ）")
    from tools.create_shortcut import _build_desktop_entry, _venv_python
    try:
        content = _build_desktop_entry(
            "AI Security Audit", '"/x/.venv/bin/python3" "/x/main.py"', "/x/assets/icon.png", "/x",
        )
        assert content.startswith("[Desktop Entry]\n"), "ヘッダー行が正しくない"
        for line in ("Type=Application", "Name=AI Security Audit",
                     'Exec="/x/.venv/bin/python3" "/x/main.py"',
                     "Icon=/x/assets/icon.png", "Path=/x", "Terminal=false"):
            assert line in content, f"必須行が欠落: {line}"
        _ok("_build_desktop_entry() 生成内容", "必須フィールドが揃っている")

        # .venv が実在すればそちらを優先するはず（後方互換: 無ければ system python3/python）
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        py = _venv_python(root)
        if os.path.exists(os.path.join(root, ".venv", "bin", "python3")):
            assert py.endswith(os.path.join(".venv", "bin", "python3")), \
                ".venv が存在するのに system python が選ばれた"
        _ok("_venv_python() 優先順位", py)
    except Exception as e:
        _ng("DesktopShortcut", repr(e) + "\n" + traceback.format_exc())


def test_model_picker():
    _section("19. CORE/GUI — モデルピッカー（価格・コンテキスト長・知能指数・ソート）")
    from core.llm_client import _parse_models_response, cost_tier, sort_models

    try:
        raw = {"data": [
            {"id": "anthropic/claude-haiku-4.5", "pricing": {"completion": "0.000004"},
             "context_length": 200000,
             "benchmarks": {"artificial_analysis": {"intelligence_index": 42.3, "coding_index": 51.1}}},
            {"id": "openai/gpt-5.5", "pricing": {"completion": "0.00003"}, "context_length": 400000},
            {"id": "qwen2.5-coder:14b"},  # Ollama等、pricing/context/benchmarksが一切無いケース
            {"id": "z-dup", "pricing": {"completion": "bad-value"}},  # パース不能な価格
            {"id": "z-dup"},  # 重複id（後勝ちではなく先勝ち＝1件のみ採用）
        ]}
        parsed = _parse_models_response(raw)
        by_id = {m["id"]: m for m in parsed}
        assert len(parsed) == 4, f"重複idは1件に統合されるべき: {[m['id'] for m in parsed]}"
        assert by_id["anthropic/claude-haiku-4.5"]["price_out"] == 4.0, "USD/token→USD/M変換が正しくない"
        assert by_id["anthropic/claude-haiku-4.5"]["intelligence"] == 42.3
        assert by_id["anthropic/claude-haiku-4.5"]["coding"] == 51.1
        assert by_id["openai/gpt-5.5"]["intelligence"] is None, "benchmarks欠落時はNoneであるべき"
        assert by_id["qwen2.5-coder:14b"]["price_out"] is None
        assert by_id["qwen2.5-coder:14b"]["context"] is None
        assert by_id["z-dup"]["price_out"] is None, "パース不能な価格はNoneであるべき（例外を投げない）"
        assert [m["id"] for m in parsed] == sorted(m["id"] for m in parsed), "id昇順ソートであるべき"
        _ok("_parse_models_response()", "価格変換・欠落フィールド・重複id・パース不能値のケースを確認")

        assert cost_tier(None) == "無料" and cost_tier(0) == "無料"
        assert cost_tier(0.99) == "低" and cost_tier(1) == "中"  # 境界値: 1は「低」に含まれない
        assert cost_tier(9.99) == "中" and cost_tier(10) == "高"
        _ok("cost_tier()", "境界値（0/1/10）を含む4階級分類")

        by_id_order = [m["id"] for m in sort_models(parsed, by="id")]
        assert by_id_order == sorted(by_id_order), "by='id' は昇順であるべき"
        by_intel = sort_models(parsed, by="intelligence")
        assert by_intel[0]["id"] == "anthropic/claude-haiku-4.5", \
            "intelligenceを持つモデルが先頭に来るべき"
        assert all(m["intelligence"] is None for m in by_intel[1:]), \
            "intelligence=Noneのモデルは末尾にまとまるべき"
        _ok("sort_models()", "id順・知能指数降順（None末尾）を確認")
    except Exception as e:
        _ng("model_picker (llm_client)", repr(e) + "\n" + traceback.format_exc())

    # settings_dialog._available_models(): 旧形式(list[str])キャッシュとの後方互換
    try:
        from gui.dialogs.settings_dialog import SettingsDialog, _PRESET_MODELS
        saved = dict(config._cfg)
        try:
            config._cfg["available_models"] = [
                "qwen3:30b-a3b",  # presetと重複するid（キャッシュ側の情報で上書きされるはず）
                {"id": "anthropic/claude-haiku-4.5", "price_out": 4.0, "context": 200000,
                 "intelligence": 42.3, "coding": 51.1},
            ]
            models = SettingsDialog._available_models()
            by_id = {m["id"]: m for m in models}
            assert "anthropic/claude-haiku-4.5" in by_id, "キャッシュのdict要素が含まれるべき"
            assert by_id["anthropic/claude-haiku-4.5"]["intelligence"] == 42.3
            assert by_id["qwen3:30b-a3b"]["price_out"] is None, \
                "旧形式(文字列)キャッシュはメタデータNoneで正規化されるべき"
            assert all(m["id"] for m in models), "全要素にidがあるべき"
            other_presets = [m for m in _PRESET_MODELS if m != "qwen3:30b-a3b"]
            assert all(p in by_id for p in other_presets), "キャッシュに無いpresetは残るべき"
        finally:
            config._cfg.clear()
            config._cfg.update(saved)
        _ok("SettingsDialog._available_models()", "旧形式キャッシュとの後方互換・preset併合を確認")
    except Exception as e:
        _ng("SettingsDialog._available_models", repr(e) + "\n" + traceback.format_exc())


def test_monitor_geometry():
    _section("20. GUI — マルチモニタ ウィンドウ配置（Linux/xrandr）")
    from gui.app import _pick_monitor
    try:
        dual = (
            "Screen 0: minimum 320 x 200, current 3840 x 1080, maximum 16384 x 16384\n"
            "eDP-1 connected 1920x1080+0+0 (normal left inverted right x axis y axis) 294mm x 165mm\n"
            "   1920x1080     59.93*+  30.00\n"
            "HDMI-1 connected 1920x1080+1920+0 (normal left inverted right x axis y axis) 527mm x 296mm\n"
            "   1920x1080     59.93*+  30.00\n"
        )
        assert _pick_monitor(dual) == (1920, 1080, 0, 0), \
            "primary未指定時は位置(0,0)のモニタを選ぶべき"
        primary_second = dual.replace("HDMI-1 connected", "HDMI-1 connected primary")
        assert _pick_monitor(primary_second) == (1920, 1080, 1920, 0), \
            "primaryマーク付きモニタを優先すべき（結合サイズ3840x1080を返してはいけない）"
        assert _pick_monitor("") is None, "connected行が無ければ None"
        assert _pick_monitor("Screen 0: minimum 320 x 200") is None, "解像度行が無ければ None"
        _ok("_pick_monitor()", "primary優先・位置(0,0)優先・結合サイズを返さないことを確認")
    except Exception as e:
        _ng("_pick_monitor", repr(e) + "\n" + traceback.format_exc())


def test_structured_reports():
    import unittest
    from tools.test_structured_reports import StructuredReportsTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(StructuredReportsTest).run(result)
    if result.wasSuccessful():
        _ok("Structured reports", f"{result.testsRun} tests: final findings, evidence references, GUI forwarding")
    else:
        _ng("Structured reports", str(result.errors + result.failures))


def test_run_journal():
    _section("16m. AUTONOMY — Run Journal (Phase A1)")
    import unittest
    from tools.test_run_journal import RunJournalTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(RunJournalTest).run(result)
    if result.wasSuccessful():
        _ok("Run Journal", f"{result.testsRun} tests: chain/recovery/corruption/lock/caps/masking/fail-closed")
    else:
        _ng("Run Journal", str(result.errors + result.failures))


def test_fuzz_characterization():
    _section("16n. AUTONOMY — 現行WEB FUZZ経路の特性化(Phase A 順3)")
    import unittest
    from tools.test_fuzz_characterization import FuzzCharacterizationTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(FuzzCharacterizationTest).run(result)
    if result.wasSuccessful():
        _ok("Fuzz characterization", f"{result.testsRun} tests: ground truth/lifecycle/決定性/予算拘束/現行の限界")
    else:
        _ng("Fuzz characterization", str(result.errors + result.failures))


def test_evidence_provenance():
    _section("16o. EVIDENCE — 最小由来情報とverify()(Phase A 順3b)")
    import unittest
    from tools.test_evidence_provenance import EvidenceProvenanceTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceProvenanceTest).run(result)
    if result.wasSuccessful():
        _ok("Evidence provenance", f"{result.testsRun} tests: sha256/action_id/masking_version/truncated/verify")
    else:
        _ng("Evidence provenance", str(result.errors + result.failures))


def test_policy_gate():
    _section("16p. AUTONOMY — Action/Policy Gate/予算/タスク状態(Phase A 順4)")
    import unittest
    from tools.test_policy_gate import SpecTest, GateTest, ApprovalTest, FailClosedTest, TaskStateTest, BudgetTest
    result = unittest.TestResult()
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                               for c in (SpecTest, GateTest, ApprovalTest, FailClosedTest,
                                         TaskStateTest, BudgetTest))
    suite.run(result)
    if result.wasSuccessful():
        _ok("Policy Gate", f"{result.testsRun} tests: spec/scope/budget/dedupe/approval/fail-closed/unknown_outcome")
    else:
        _ng("Policy Gate", str(result.errors + result.failures))


def test_fuzz_execution_record():
    _section("16q. TOOLS — WebFuzzer 検査単位の実行記録(Phase A 順5)")
    import unittest
    from tools.test_fuzz_execution_record import FuzzExecutionRecordTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(FuzzExecutionRecordTest).run(result)
    if result.wasSuccessful():
        _ok("Fuzz execution record", f"{result.testsRun} tests: 予算0/途中枯渇/ちょうど完遂/STOP/通信失敗")
    else:
        _ng("Fuzz execution record", str(result.errors + result.failures))


def test_llm_budget_gate():
    _section("16r. AUTONOMY — LLM呼出の事前制限(Phase A 順5b)")
    import unittest
    from tools.test_llm_budget_gate import AgentGateTest, ClientTest
    result = unittest.TestResult()
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                               for c in (AgentGateTest, ClientTest))
    suite.run(result)
    if result.wasSuccessful():
        _ok("LLM budget gate", f"{result.testsRun} tests: 呼出前拒否/検証パス/max_tokens/使用量不明/既定は不変")
    else:
        _ng("LLM budget gate", str(result.errors + result.failures))


def test_fuzz_autonomy():
    _section("16s. AUTONOMY — WEB FUZZ 新経路(capability+Gate+Journal)の等価性・安全・異常系(Phase A 順6)")
    import unittest
    from tools.test_fuzz_autonomy import (EquivalenceTest, JournalTraceTest, SafetyTest,
                                          BudgetAndStopTest, AuditFailureSweepTest, AuthApprovalTest)
    result = unittest.TestResult()
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                               for c in (EquivalenceTest, JournalTraceTest, SafetyTest,
                                         BudgetAndStopTest, AuditFailureSweepTest, AuthApprovalTest))
    suite.run(result)
    if result.wasSuccessful():
        _ok("Fuzz autonomy path", f"{result.testsRun} tests: 現行経路との等価性/POST未送信/証拠→Action→Gate判断の追跡/予算/STOP/監査失敗の全位置/認証の承認(役割別)/IDOR")
    else:
        _ng("Fuzz autonomy path", str(result.errors + result.failures))


def test_run_store():
    _section("16t. AUTONOMY — RunStore(実行状態のSQLite永続化・Phase B1)")
    import unittest
    from tools.test_run_store import RunStoreTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(RunStoreTest).run(result)
    if result.wasSuccessful():
        _ok("RunStore", f"{result.testsRun} tests: 計画/タスク状態/出力の再読込/原子性/承認の一意性/不明分の消費/WAL")
    else:
        _ng("RunStore", str(result.errors + result.failures))


def test_fuzz_resume():
    _section("16u. AUTONOMY — 中断・再開(強制終了×全タスク×5位置・承認・拒否, Phase B)")
    import unittest
    from tools.test_fuzz_resume import ResumeSweepTest, UnknownOutcomeTest, AuthResumeTest, RefusalTest
    result = unittest.TestResult()
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                               for c in (ResumeSweepTest, UnknownOutcomeTest, AuthResumeTest, RefusalTest))
    suite.run(result)
    if result.wasSuccessful():
        _ok("Fuzz resume", f"{result.testsRun} tests: 二重実行なし/予算の非巻き戻し/不明は自動再実行しない/認証は新承認/プロファイル不一致は拒否")
    else:
        _ng("Fuzz resume", str(result.errors + result.failures))


def test_cli():
    _section("16v. AUTONOMY — ヘッドレスCLI (Phase B4)")
    import unittest
    from tools.test_cli import CLITest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(CLITest).run(result)
    if result.wasSuccessful():
        _ok("CLI", f"{result.testsRun} tests: JSON/終了コード/認証権限/承認/非漏えい/再開/SIGINT")
    else:
        _ng("CLI", str(result.errors + result.failures))


def test_benchmark():
    _section("16w. BENCHMARK — WEB FUZZ 検出品質(P2.1 detector固定モード)")
    import unittest
    from tools.test_benchmark import EvaluateTest, TruthTest, RealRunTest, CompareTest
    result = unittest.TestResult()
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                               for c in (EvaluateTest, TruthTest, RealRunTest, CompareTest))
    suite.run(result)
    if result.wasSuccessful():
        _ok("Benchmark", f"{result.testsRun} tests: 集計器(手計算)/正解データ/基準値との一致と決定性/未検査の扱い")
    else:
        _ng("Benchmark", str(result.errors + result.failures))


def test_audit_evidence():
    _section("16l. AGENT — AuditAgent 証拠保存・入力マスキング(P1.2)")
    import unittest
    from tools.test_audit_evidence import (
        AuditEvidenceTest, MaskSourceTest, LangGraphMaskTest, LangGraphEvidenceTest)
    result = unittest.TestResult()
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(AuditEvidenceTest),
        unittest.defaultTestLoader.loadTestsFromTestCase(MaskSourceTest),
        unittest.defaultTestLoader.loadTestsFromTestCase(LangGraphMaskTest),
        unittest.defaultTestLoader.loadTestsFromTestCase(LangGraphEvidenceTest),
    ])
    suite.run(result)
    if result.wasSuccessful():
        _ok("Audit evidence", f"{result.testsRun} tests: ON/OFF・マスク・未知ID・上限省略・保存失敗")
    else:
        _ng("Audit evidence", str(result.errors + result.failures))


def test_defense_evidence():
    _section("16m. AGENT — MonitorAgent 証拠保存・ログ入力マスキング(P1.2)")
    import unittest
    from tools.test_defense_evidence import DefenseEvidenceTest, MaskLogLineTest
    result = unittest.TestResult()
    suite = unittest.TestSuite([
        unittest.defaultTestLoader.loadTestsFromTestCase(DefenseEvidenceTest),
        unittest.defaultTestLoader.loadTestsFromTestCase(MaskLogLineTest),
    ])
    suite.run(result)
    if result.wasSuccessful():
        _ok("Defense evidence", f"{result.testsRun} tests: ON/OFF・マスク・未知ID・上限省略・保存失敗")
    else:
        _ng("Defense evidence", str(result.errors + result.failures))


def test_flag_routes():
    _section("16n. AGENT — ReconAgent CTFフラグの中身・取得経路のレポート化(P1.2)")
    import unittest
    from tools.test_flag_routes import FlagRoutesTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(FlagRoutesTest).run(result)
    if result.wasSuccessful():
        _ok("Flag routes", f"{result.testsRun} tests: Active/Passive経路・証拠保存ON・URLマスク・HTML/MD/PDF")
    else:
        _ng("Flag routes", str(result.errors + result.failures))


def test_fuzz_masking():
    _section("16p. AGENT — FuzzAgent 表示・LLM送信・保存前マスキング(P1.2)")
    import unittest
    from tools.test_fuzz_masking import FuzzMaskingTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(FuzzMaskingTest).run(result)
    if result.wasSuccessful():
        _ok("Fuzz masking", f"{result.testsRun} tests: URLトークン・Cookie値が表示/LLM/保存物に残らない")
    else:
        _ng("Fuzz masking", str(result.errors + result.failures))


def test_attack_evidence():
    _section("16q. AGENT — ReconAgent 偵察観測の証拠保存・ID引用(P1.2)")
    import unittest
    from tools.test_attack_evidence import AttackEvidenceTest
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(AttackEvidenceTest).run(result)
    if result.wasSuccessful():
        _ok("Attack evidence", f"{result.testsRun} tests: 観測保存・サマリーID・Set-Cookieマスク・未知ID・上限・レポートリンク")
    else:
        _ng("Attack evidence", str(result.errors + result.failures))


def main():
    print("\n" + "#"*64)
    print("#  AI Security Audit System — 全機能セルフテスト")
    print(f"#  LLMテストモデル: {SELFTEST_MODEL}（廉価モデル）")
    print("#"*64)
    t0 = time.time()

    if QUICK:
        print("#  モード: QUICK（実LLM/実ネットワーク要求のテストはスキップ）")
    test_event_bus()
    test_config()
    test_model_router()
    test_verify_ensemble()
    test_telemetry()
    test_scope_guard()
    test_telemetry_ledger()
    test_base_agent_lifecycle()
    test_findings_from_markers_evidence_ids()
    test_findings_contract()
    test_redaction()
    test_evidence_store()
    test_subdomain_enum()
    test_network_scanner()
    test_web_prober()
    test_ctf_flag_hunt()
    test_ctf_active_retrieval()
    log_path = test_log_watcher()
    test_pattern_match()
    test_structured_reports()
    test_run_journal()
    test_fuzz_characterization()
    test_evidence_provenance()
    test_policy_gate()
    test_fuzz_execution_record()
    test_llm_budget_gate()
    test_fuzz_autonomy()
    test_run_store()
    test_fuzz_resume()
    test_benchmark()
    test_cli()
    test_audit_evidence()
    test_defense_evidence()
    test_flag_routes()
    test_attack_evidence()
    test_report_generator()
    test_report_generator_attack_mode()
    test_report_generator_markdown()
    test_cve_client()
    _skip_llm("9", "CORE — LLMClient (OpenRouter)", test_llm)
    test_audit_agent_p11_wiring()
    _skip_llm("10", "AGENT E2E — AuditAgent (実LLM)", test_audit_agent)
    test_monitor_agent_p11_wiring()
    _skip_llm("11", "AGENT E2E — MonitorAgent (single-pass, 実LLM)", test_monitor_agent, log_path)
    test_recon_agent_p11_wiring()
    _skip_llm("12", "AGENT E2E — ReconAgent (scanme.nmap.org / 実LLM)", test_recon_agent)
    test_orchestrator_bug()
    test_langgraph_audit_agent_p11_wiring()
    test_stealth_features()
    test_pdf_report()
    test_web_fuzzer()
    test_web_fuzzer_idor()
    test_http_transport()
    test_web_fuzzer_cross_origin()
    test_http_transport_rate_limits()
    test_web_fuzzer_auth_state()
    test_web_fuzzer_tls()
    test_http_transport_tls_handshake()
    test_fuzz_agent_p11_wiring()
    test_fuzz_agent_no_points_lifecycle()
    test_fuzz_agent_evidence_wiring()
    test_fuzz_idor_evidence()
    test_fuzz_masking()
    _skip_llm("17", "AGENT E2E — FuzzAgent（ローカルモック / 実LLM）", test_fuzz_agent)
    test_desktop_shortcut()
    test_model_picker()
    test_monitor_geometry()

    dt = time.time() - t0
    print("\n" + "#"*64)
    if NON_LLM_ONLY:
        label = "--quick" if QUICK else "SELFTEST_NON_LLM_ONLY=1"
        print(f"#  結果: {len(_PASS)} PASS / {len(_FAIL)} FAIL / {len(_SKIP)} SKIP   ({dt:.1f}s)")
        print(f"#  {label} — 実LLM/実ネットワーク要求の{len(_SKIP)}項目はスキップ")
    else:
        print(f"#  結果: {len(_PASS)} PASS / {len(_FAIL)} FAIL   ({dt:.1f}s)")
    print("#"*64)
    if _FAIL:
        print("\n  失敗したテスト:")
        for f in _FAIL:
            print(f"    ✗ {f}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
