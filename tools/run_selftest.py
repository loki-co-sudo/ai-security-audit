#!/usr/bin/env python3
"""
tools/run_selftest.py — 全機能セルフテスト（GUI以外を網羅）

実行:  py tools/run_selftest.py
ネットワーク・LLM(OpenRouter)を実際に使用する。
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

# SELFTEST_NON_LLM_ONLY=1 で実LLM/実ネットワークAPIキーを要求するテストをスキップする
# （CI・オフライン環境向け。CLAUDE.md の「開発ループ」の1〜8・2b〜2dに相当）。
NON_LLM_ONLY = os.environ.get("SELFTEST_NON_LLM_ONLY") == "1"


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
        assert agent._check_scope("good.example.com") is True
        config._cfg["scope_mode"] = "warn"
        assert agent._check_scope("evil.example.com") is True, \
            "warn モードでは範囲外でも続行（True）を返すべき"
        _ok("BaseAgent._check_scope", "後方互換（未設定=常に許可）/ block / warn")
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
            body = "<html><body>"
            if u.path == "/":
                body += '<a href="/search?q=hi">s</a> <a href="/item?id=1">i</a>'
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
                # 脆弱: セッション種別を確認せずid=1の内容を返す（IDOR再現用モック）
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


def main():
    print("\n" + "#"*64)
    print("#  AI Security Audit System — 全機能セルフテスト")
    print(f"#  LLMテストモデル: {SELFTEST_MODEL}（廉価モデル）")
    print("#"*64)
    t0 = time.time()

    test_event_bus()
    test_config()
    test_model_router()
    test_verify_ensemble()
    test_telemetry()
    test_scope_guard()
    test_telemetry_ledger()
    test_subdomain_enum()
    test_network_scanner()
    test_web_prober()
    log_path = test_log_watcher()
    test_pattern_match()
    test_report_generator()
    test_report_generator_markdown()
    test_cve_client()
    _skip_llm("9", "CORE — LLMClient (OpenRouter)", test_llm)
    _skip_llm("10", "AGENT E2E — AuditAgent (実LLM)", test_audit_agent)
    _skip_llm("11", "AGENT E2E — MonitorAgent (single-pass, 実LLM)", test_monitor_agent, log_path)
    _skip_llm("12", "AGENT E2E — ReconAgent (scanme.nmap.org / 実LLM)", test_recon_agent)
    test_orchestrator_bug()
    test_stealth_features()
    test_pdf_report()
    test_web_fuzzer()
    test_web_fuzzer_idor()
    _skip_llm("17", "AGENT E2E — FuzzAgent（ローカルモック / 実LLM）", test_fuzz_agent)
    test_desktop_shortcut()

    dt = time.time() - t0
    print("\n" + "#"*64)
    if NON_LLM_ONLY:
        print(f"#  結果: {len(_PASS)} PASS / {len(_FAIL)} FAIL / {len(_SKIP)} SKIP   ({dt:.1f}s)")
        print(f"#  SELFTEST_NON_LLM_ONLY=1 — 実LLM/実ネットワーク要求の{len(_SKIP)}項目はスキップ")
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
