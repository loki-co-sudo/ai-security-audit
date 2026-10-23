"""
core/autonomy/lab_workflow.py — ローカル模擬案件の診断ワークフロー(Observe→Classify→Prioritize→Execute→Evaluate→Replan)

設計: docs/LOCAL_LAB_EVAL.md。既存の ScriptedRunner / PolicyGate / RunJournal / RunStore / HttpTransport / EvidenceStore /
Finding を再利用し、状態管理基盤は新設しない。本モジュールが足すのは次の3点だけ。
  1. 案件設定(lab_case)の固定テスト操作を capability(`lab.test_anon`=T1 / `lab.test_authed`=T2)として登録する薄い層
  2. 観測→仮説の状態(LabState)と、期待値との比較(evaluate)、決定論的/LLM補助の次テスト選択(selector)
  3. 結果(LabRunResult)の組み立て

安全:
  - 実行できるのは案件設定に登録した test_id だけ。LLMが返せるのは候補test_idの選択のみで、リクエスト・パス・ペイロード・
    コマンドを作る経路は無い。選択後も通常どおり Gate(スコープ・副作用・予算・重複)→HttpTransport(同一origin・予算)を通る。
  - 対象から返った本文はLLMへ渡さない(プロンプトは案件設定の静的文言と状態の列挙値だけ)。
  - 認証情報は参照名(`cred:*`)だけが計画・ジャーナル・プロンプトに出る。tokenは実行時にヘッダーへ入れるだけで、
    既知の機密値として証拠・ジャーナルのマスク対象に登録する。
  - タイムアウト・通信失敗・期限切れ(401等)は inconclusive(未判定)で、「問題なし」には数えない。
  - 正解ラベルと採点器はこのモジュールから参照しない(採点は tools/lab_eval.py が実行後に行う)。
"""

from __future__ import annotations
import hashlib
import json
import os
import random
import time
from dataclasses import dataclass, field
from typing import Callable

from core import redaction
from core.autonomy.actions import (
    Action, ActionResult, CapabilityRegistry, CapabilitySpec, SideEffect,
)
from core.autonomy.budget import BudgetLedger
from core.autonomy.journal import JOURNAL_ROOT, JournalError, RunJournal, new_run_id
from core.autonomy import lab_chain
from core.autonomy.lab_case import LabCase, LabTest
from core.autonomy.policy_gate import EngagementPolicy, PolicyGate
from core.autonomy.resume import ResumeError, profile_hash, reconcile
from core.autonomy.run_store import RunStore, RunStoreError
from core.autonomy.runner import ENGINE_VERSION, PlanTask, ScriptedRunner
from core.autonomy.task_graph import TaskState
from core.evidence_store import EvidenceStore
from core.findings import (
    CoverageItem, CoverageStatus, Finding, ScanState, VerificationState, new_id, new_scan_result,
)
from core.http_transport import HttpTransport, RequestPolicy, new_session

LAB_ENGINE_VERSION = "lab-workflow/6"   # 判定契約を変えたら上げる(プロファイルハッシュに含まれ、旧Runの再開は拒否される)
# /5: D0(対照未確認の逸脱を裏付けにしない) /6: evidence_completeに対照を含める・不完全な本文を判定へ伝える
PROMPT_VERSION = "lab-rank/1"
STRATEGIES = ("fixed", "fixed_random", "deterministic", "llm")
T1, T2 = SideEffect.T1_OBSERVE, SideEffect.T2_DIFFERENTIAL
CAP_ANON, CAP_AUTHED = "lab.test_anon", "lab.test_authed"
_URL = {"url": {"type": "str", "required": True}, "test_id": {"type": "str", "required": True},
        "attempt": {"type": "int"}}
TRANSIENT_STATUSES = (408, 429, 502, 503, 504)      # 再試行の対象(401等の認証系は対象外)
RETRY_SUFFIX = "~retry"
RETRY_WAIT_CAP = 2.0

CONFORMS, DEVIATES, INCONCLUSIVE = "conforms", "deviates", "inconclusive"


# ── 期待値との比較(Evaluate) ──────────────────────────────────
def evaluate(test: LabTest, status: int | None, headers: dict, body: str,
             body_complete: bool = True) -> tuple[str, str, list[str]]:
    """応答を事前定義の期待値と比べる。戻り値: (outcome, reason, diffs)。diffsは案件設定由来の静的文言と
    ステータス値だけで、対象の応答本文を含めない。

    body_complete=False(途中切断・サイズ上限・読取時間超過)のとき、本文に依存する判定は読めた範囲でしか言えない:
      - 読めた範囲で見つかった body_not_contains の違反は、逸脱として保持する(読めなかった部分は結果を変えない)。
      - body_contains が見つからない/body_not_contains が見つからないことは、残りの本文に在り得るので conforms にしない。
        他に確定した逸脱が無ければ inconclusive(reason=body_incomplete)。
      - ステータス・ヘッダーの判定は本文の完全性に依存しないので、そのまま行う。"""
    exp = test.expect
    want = exp.get("status")
    want_list = [want] if isinstance(want, int) else list(want or [])
    if status is None:
        return INCONCLUSIVE, "no_response", []
    if status in test.inconclusive_statuses and status not in want_list:
        return INCONCLUSIVE, f"status_{status}", []
    diffs: list[str] = []
    undecided = False
    if want_list and status not in want_list:
        diffs.append(f"status: expected {want_list}, observed {status}")
    for s in exp.get("body_contains", []):
        if s not in body:
            if body_complete:
                diffs.append(f"body: expected to contain {s!r}")
            else:
                undecided = True
    for s in exp.get("body_not_contains", []):
        if s in body:
            diffs.append(f"body: must not contain {s!r}")
        elif not body_complete:
            undecided = True
    lower = {k.lower(): v for k, v in headers.items()}
    for name in exp.get("header_absent", []):
        if name.lower() in lower:
            diffs.append(f"header: {name} must be absent")
    for name, frag in (exp.get("header_contains") or {}).items():
        if frag.lower() not in str(lower.get(name.lower(), "")).lower():
            diffs.append(f"header: {name} must contain {frag!r}")
    if diffs:
        return DEVIATES, "expectation_not_met", diffs
    return (INCONCLUSIVE, "body_incomplete", []) if undecided else (CONFORMS, "", [])


# ── 観測→仮説の状態(Observe / Classify) ──────────────────────────
class LabState:
    def __init__(self, case: LabCase):
        self.case = case
        self.results: dict[str, dict] = {}       # test_id -> 実行出力(マスク済み・RunStoreにも保存される)

    def record(self, test_id: str, out: dict) -> None:
        self.results[test_id] = out

    def unlocked(self, t: LabTest) -> bool:
        if not t.unlocked_by:
            return True
        src = self.results.get(t.unlocked_by["test_id"])
        return bool(src and t.test_id in src.get("unlocks", []))

    def tests_of(self, hid: str, kind: str | None = None) -> list[LabTest]:
        return [t for t in self.case.tests.values() if t.hypothesis == hid and (kind is None or t.kind == kind)]

    def control_state(self, hid: str) -> str:
        """仮説が必要とする対照の状態。not_required(対照を定義していない=明示的な契約) / not_run / passed / failed / inconclusive。

        passedは、定義された対照が全て実行され、全て適合した場合だけ。一部だけ実行・未実行はnot_run。"""
        ctl = self.tests_of(hid, "control")
        if not ctl:
            return "not_required"
        outs = [self.results.get(t.test_id, {}).get("outcome") for t in ctl]
        if DEVIATES in outs:
            return "failed"
        if INCONCLUSIVE in outs:
            return "inconclusive"
        return "passed" if all(o == CONFORMS for o in outs) else "not_run"

    def hyp_status(self, hid: str) -> str:
        """untested / partially_tested / unverified_deviation / supported / refuted / undetermined。

        supported(裏付けあり)とrefuted(期待どおり)は、必要な対照が passed または not_required の場合だけ。
        probeが逸脱しても対照が未実施なら unverified_deviation(候補として残し、所見・連鎖の根拠にしない)。
        対照が失敗・不明なら、全環境が同じ応答を返す等で探査の結果を根拠にできないため undetermined。"""
        outs = [self.results.get(t.test_id, {}).get("outcome") for t in self.tests_of(hid, "probe")]
        cs = self.control_state(hid)
        if DEVIATES in outs:
            if cs in ("failed", "inconclusive"):
                return "undetermined"
            return "unverified_deviation" if cs == "not_run" else "supported"
        if all(o is None for o in outs):
            return "untested"
        if None in outs:
            return "partially_tested"
        if INCONCLUSIVE in outs:
            return "undetermined"
        return "refuted" if cs in ("passed", "not_required") else "undetermined"

    def corroborated(self, hid: str) -> bool:
        """複数根拠での裏付け。必要な対照が未実施・失敗・不明なら、probeの件数に関係なく False。"""
        cs = self.control_state(hid)
        if cs not in ("passed", "not_required"):
            return False
        dev = [t for t in self.tests_of(hid, "probe") if self.results.get(t.test_id, {}).get("outcome") == DEVIATES]
        return len(dev) >= 2 or (len(dev) == 1 and cs == "passed")

    def feature_suspicious(self, feature: str) -> bool:
        return any(self.results.get(t.test_id, {}).get("outcome") == DEVIATES
                   for t in self.case.tests.values() if t.feature == feature)

    def resolved(self, hid: str) -> bool:
        st = self.hyp_status(hid)
        if st == "refuted":
            return True
        if st == "supported":
            if self.corroborated(hid):
                return True
            return not any(t.test_id not in self.results and (t.corroborates or t.kind == "control")
                           for t in self.tests_of(hid))
        return False


# ── 優先順位付け(Prioritize・決定論) ───────────────────────────────
def base_value(case: LabCase, state: LabState, t: LabTest) -> float:
    """期待される情報価値(コストで割る前)。仮説の事前重要度×テストの情報価値に、観測による補正を掛ける。"""
    h = case.hypotheses[t.hypothesis]
    st = state.hyp_status(t.hypothesis)
    if st == "refuted":
        return 0.0
    v = h.prior_value * t.info_value
    if st in ("supported", "unverified_deviation"):
        if state.corroborated(t.hypothesis):
            return v * 0.05
        v *= 1.5 if (t.corroborates or t.kind == "control") else 0.15
        if st == "unverified_deviation" and t.hypothesis in lab_chain.chain_gain_hypotheses(case, state.hyp_status):
            v *= 1.5                           # 対照が通れば連鎖の根拠になる逸脱の確認を優先する
    else:
        if t.corroborates:
            v *= 0.4
        if t.kind in ("control", "navigation"):
            v *= 0.5
        if state.feature_suspicious(t.feature):
            v *= 1.3
        if t.hypothesis in lab_chain.chain_gain_hypotheses(case, state.hyp_status):
            v *= 1.5                           # 検査すると連鎖(より重大な組合せ)が完成しうる仮説
    return v


def score(case: LabCase, state: LabState, t: LabTest) -> float:
    v = base_value(case, state, t)
    for other in case.tests.values():          # 後続の選択を可能にする観測には加点する(1段のみ)
        if (other.unlocked_by and other.unlocked_by["test_id"] == t.test_id
                and other.test_id not in state.results and not state.unlocked(other)):
            v += 0.5 * base_value(case, state, other)
    return v / t.cost


def candidates(case: LabCase, state: LabState, pending: set[str], remaining: int) -> list[LabTest]:
    return [t for t in case.tests.values()
            if t.test_id in pending and state.unlocked(t) and t.cost <= remaining]


def rank(case: LabCase, state: LabState, cands: list[LabTest]) -> list[tuple[float, str]]:
    return sorted(((score(case, state, t), t.test_id) for t in cands), key=lambda x: (-x[0], x[1]))


# ── LLM補助の選択(候補IDの選択だけ) ───────────────────────────────
def build_rank_messages(case: LabCase, state: LabState, cands: list[LabTest], det: list[tuple[float, str]],
                        remaining: int) -> list[dict]:
    """プロンプトは案件設定の静的文言と状態の列挙値だけ。対象の応答本文・ヘッダーは入れない。"""
    lines = []
    for s, tid in det:
        t = case.tests[tid]
        h = case.hypotheses[t.hypothesis]
        lines.append(f"- id={tid} | 機能={case.features[t.feature]['title']} | 仮説={h.title} | "
                     f"仮説の状態={state.hyp_status(h.hypothesis_id)} | 目的={t.purpose} | コスト={t.cost} | 参考スコア={s:.2f}")
    system = ("あなたは模擬診断の優先順位付け担当です。候補の固定テストIDから、次に実行する1件を選びます。"
              "出力はJSONだけ: {\"next\":\"<候補のid>\",\"reason\":\"<短い理由>\"}。"
              "候補にないIDや新しい操作・リクエスト・コマンドの提案は無効です。")
    user = (f"案件: {case.title}\n残りリクエスト数: {remaining}\n"
            f"既に判明した状態は『仮説の状態』のとおりです。情報価値/コストが高いものを選んでください。\n"
            + "\n".join(lines))
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def parse_rank_reply(text: str, allowed: set[str]) -> tuple[str | None, str]:
    """戻り値: (選ばれたtest_id | None, 理由/拒否理由)。候補外は拒否する。"""
    if not text:
        return None, "empty_reply"
    a, b = text.find("{"), text.rfind("}")
    if a < 0 or b < a:
        return None, "not_json"
    try:
        obj = json.loads(text[a:b + 1])
    except ValueError:
        return None, "not_json"
    nxt = obj.get("next") if isinstance(obj, dict) else None
    if not isinstance(nxt, str) or nxt not in allowed:
        return None, "not_a_candidate"
    return nxt, str(obj.get("reason", ""))[:200]


# ── 結果 ─────────────────────────────────────────────────────
@dataclass
class LabRunResult:
    case_id: str
    strategy: str
    run_id: str
    scan_id: str
    state: str                         # ScanState値(全仮説が判定済みでなければcompletedにしない)
    end_reason: str
    finish_reason: str
    clean_finish: bool                 # 監査記録の欠落・内部エラー無しで最後まで通ったか
    tests: dict = field(default_factory=dict)         # test_id -> {state, outcome, reason, evidence_id, ...}
    hypotheses: dict = field(default_factory=dict)    # hid -> {status, corroborated, tests_run, tests_not_run}
    findings: list = field(default_factory=list)       # 裏付けあり(supported)のみ。対照未確認は candidates
    candidates: list = field(default_factory=list)     # 逸脱を観測したが必要な対照が未実施の仮説(所見・連鎖の根拠にしない)
    untested: list = field(default_factory=list)
    selection_log: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    counters: dict = field(default_factory=dict)
    budget: dict = field(default_factory=dict)
    llm: dict = field(default_factory=dict)
    versions: dict = field(default_factory=dict)
    scan_result: dict = field(default_factory=dict)
    out_of_scope: list = field(default_factory=list)
    chains: list = field(default_factory=list)         # 連鎖の仮説(state=hypothesized。確認・実行はしない)
    open_chains: list = field(default_factory=list)    # 一部の不備だけ観測済みで、残りが未判定の連鎖
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        return json.loads(json.dumps(self.__dict__, ensure_ascii=False, default=str))


def build_registry(case: LabCase) -> CapabilityRegistry:
    r = CapabilityRegistry()
    r.register(CapabilitySpec(CAP_ANON, T1, args_schema=dict(_URL), target_arg="url", max_requests=1))
    r.register(CapabilitySpec(CAP_AUTHED, T2, args_schema=dict(_URL), target_arg="url", max_requests=1))
    return r


def test_url(base_url: str, t: LabTest) -> str:
    return base_url.rstrip("/") + t.path


def _retry_wait(retry_after) -> float:
    """Retry-After(秒)を上限つきで尊重する。解釈できない値・日付形式は待たない。"""
    try:
        return max(0.0, min(float(retry_after), RETRY_WAIT_CAP))
    except (TypeError, ValueError):
        return 0.0


def build_plan(case: LabCase, base_url: str, order: list[str], retry: bool = False) -> list[PlanTask]:
    plan = [PlanTask(tid, CAP_ANON if case.tests[tid].role == "anonymous" else CAP_AUTHED,
                     {"url": test_url(base_url, case.tests[tid]), "test_id": tid},
                     auth_context=case.tests[tid].role) for tid in order]
    if retry:                                  # 再試行用の枠(選択されない限り実行しない・同じ操作を2回目として別のdedupe_keyで登録)
        plan += [PlanTask(tid + RETRY_SUFFIX, CAP_ANON if case.tests[tid].role == "anonymous" else CAP_AUTHED,
                          {"url": test_url(base_url, case.tests[tid]), "test_id": tid, "attempt": 2},
                          auth_context=case.tests[tid].role) for tid in order]
    return plan


class Crash(BaseException):
    """試験用: 強制終了の再現(Exceptionではないのでワークフローは握りつぶさない)。"""


def run_lab_case(case: LabCase, base_url: str, creds: dict[str, str], *, strategy: str = "deterministic",
                 llm=None, journal_root: str = JOURNAL_ROOT, evidence_root: str | None = None,
                 seed: int = 0, is_stopped: Callable[[], bool] | None = None,
                 resume_run_id: str | None = None, retry_unknown: list[str] | None = None,
                 only_tests: list[str] | None = None, fault_hook: Callable[[str, str], None] | None = None,
                 budget_override: dict | None = None, clock=time.monotonic,
                 llm_max_tokens: int = 200, retry_transient: int = 0,
                 sleep: Callable[[float], None] = time.sleep) -> LabRunResult:
    """1案件を1回実行する。creds は `cred:<名前>` -> token(実行時にヘッダーへ入れるだけで、記録しない)。

    strategy:
      fixed          既存のScriptedRunner。宣言順に全件(解除条件・価値を見ない)を予算まで実行する
      fixed_random   同上。順序だけseedでシャッフルした対照(宣言順の有利不利を見るため)
      deterministic  Observe→Classify→Prioritize→Execute→Evaluate→Replan(決定論)
      llm            deterministicと同じ候補・停止条件で、次の1件の選択だけLLMに助言させる(失敗時は決定論に戻す)
    """
    if strategy not in STRATEGIES:
        raise ValueError(f"未知のstrategy: {strategy}")
    t_start = time.time()
    stopped = is_stopped or (lambda: False)
    budget = {**case.budget, **(budget_override or {})}
    order = [t for t in case.test_order() if only_tests is None or t in only_tests]
    if strategy == "fixed_random":
        order = random.Random(seed).sample(order, len(order))
    known_secrets = {v for v in creds.values() if v}
    registry = build_registry(case)
    retry_on = bool(retry_transient) and strategy in ("deterministic", "llm")     # 再試行は選択型の方式だけ(最大1回)
    plan = build_plan(case, base_url, order, retry=retry_on)
    effects = {SideEffect.T0_LOCAL} | {SideEffect(s) for s in case.side_effects}
    phash = profile_hash({
        "mode": "LAB", "case": case.public_dict(), "base_url": base_url, "strategy": strategy, "seed": seed,
        "only_tests": order, "budget": budget, "retry": retry_on, "engine": ENGINE_VERSION, "lab_engine": LAB_ENGINE_VERSION})
    sr = new_scan_result("LAB", case.case_id, engagement_id=case.case_id)
    state = LabState(case)
    counters = {"gate_denied": 0, "budget_denied": 0, "llm_selection_rejected": 0, "llm_fallbacks": 0, "selections": 0, "retries": 0}
    selection_log: list[dict] = []
    resuming = resume_run_id is not None
    prior = 0
    journal = store = None
    try:
        journal = RunJournal(resume_run_id or new_run_id(), journal_root, known_secrets=known_secrets)
        store = RunStore(journal.run_id, journal_root, must_exist=resuming)
        if resuming:
            if store.get_meta("profile_hash") != phash:
                raise ResumeError("プロファイル(案件・対象・予算・計画など)が開始時と異なるため再開しません")
            sr.scan_id = store.get_meta("scan_id") or sr.scan_id
            report = reconcile(journal, store)
            prior = store.requests_consumed(0)
            for row in store.tasks().values():       # 結果不明は宣言上限(=1リクエスト)を消費済みとみなす(巻き戻さない)
                if row["state"] in ("unknown_outcome", "running") or row["consumption_unknown"]:
                    prior += 1
            journal.append("run_resumed", profile_hash=phash, prior_requests=prior, notes=report.notes,
                           unknown_tasks=report.unknown_tasks, retry_unknown=sorted(retry_unknown or []))
    except (ResumeError, JournalError, RunStoreError, OSError, ValueError) as e:
        for o in (store, journal):
            if o is not None:
                try:
                    o.close()
                except Exception:   # noqa: BLE001
                    pass
        return LabRunResult(case.case_id, strategy, resume_run_id or "", sr.scan_id, ScanState.FAILED.value,
                            "error", "start_failed", False,
                            errors=[f"{'再開' if resuming else '監査記録の開始'}に失敗しました: {e}"],
                            counters=counters, scan_result=sr.to_dict())

    max_req = int(budget["max_requests"])
    transport = HttpTransport(policy=RequestPolicy(max_requests=max(0, max_req - prior), timeout=5))
    transport.bind_origin(base_url)
    ledger = BudgetLedger(max_requests=max_req, request_counter=lambda: prior + transport.req_count,
                          deadline_seconds=float(budget["max_seconds"]), max_llm_calls=int(budget["max_llm_calls"]),
                          max_llm_input_chars=int(budget.get("max_llm_input_chars", 8000)), clock=clock)
    gate = PolicyGate(registry, EngagementPolicy(base_origin=base_url, allowed_targets=list(case.allowed_hosts),
                                                 allowed_side_effects=frozenset(effects)),
                      ledger, journal, store=store)
    evidence = EvidenceStore(sr.scan_id, **({"root": evidence_root} if evidence_root else {})) \
        if case.evidence.get("save", True) else None
    mask = lambda s: redaction.mask_log_line(str(s), known_secrets)  # noqa: E731

    def execute(action: Action) -> ActionResult:
        t = case.tests[action.args["test_id"]]
        if action.args["url"] != test_url(base_url, t):          # 登録内容と違う引数は実行しない
            return ActionResult("failed", {"reason": "args_mismatch"})
        headers = {}
        if t.role != "anonymous":
            token = creds.get(case.accounts[t.role])
            if not token:
                out = {"outcome": INCONCLUSIVE, "reason": "credential_unavailable", "status_code": None,
                       "diffs": [], "evidence_id": None, "unlocks": []}
                return ActionResult("failed", {"reason": "credential_unavailable"}, outputs=out)
            headers["Authorization"] = f"Bearer {token}"
        if fault_hook:
            fault_hook("before_send", t.test_id)
        resp = transport.request(new_session(), "GET", action.args["url"], params=dict(t.params),
                                 headers=headers)
        if fault_hook:
            fault_hook("after_send", t.test_id)
        if resp is None:
            why = transport.last_error or "network_error"
            out = {"outcome": INCONCLUSIVE, "reason": why, "status_code": None, "diffs": [],
                   "evidence_id": None, "unlocks": []}
            return ActionResult("exhausted" if why == "budget_exhausted" else "failed",
                                {"reason": why}, outputs=out)
        body = resp.text or ""
        cut = getattr(resp, "fz_incomplete_reason", None) if getattr(resp, "fz_truncated", False) else None
        outcome, reason, diffs = evaluate(t, resp.status_code, dict(resp.headers), body, body_complete=cut is None)
        eid = None
        if evidence is not None:
            eid = evidence.save_http_evidence(method="GET", url=resp.request.url or action.args["url"],
                                              status=resp.status_code, headers=dict(resp.headers), body=body,
                                              known_secrets=known_secrets, action_id=action.action_id,
                                              source_incomplete=cut)
        unlocks = [o.test_id for o in case.tests.values()
                   if o.unlocked_by and o.unlocked_by["test_id"] == t.test_id
                   and o.unlocked_by["body_contains"] in body]
        # 本文が不完全で解除条件の文字列が見つからない場合は『無い』と言えない(解除しないが、理由を残す)
        undecided_unlock = [o.test_id for o in case.tests.values()
                            if cut and o.unlocked_by and o.unlocked_by["test_id"] == t.test_id
                            and o.test_id not in unlocks]
        out = {"outcome": outcome, "reason": reason, "status_code": resp.status_code, "diffs": diffs,
               "evidence_id": eid, "unlocks": unlocks, "body_complete": cut is None, "incomplete_reason": cut,
               "bytes_read": getattr(resp, "fz_bytes_read", len(body.encode())), "unlock_undecided": undecided_unlock,
               "body_sha12": hashlib.sha256(body.encode()).hexdigest()[:12],
               "attempt": int(action.args.get("attempt", 1)), "retry_after": resp.headers.get("Retry-After")}
        prev = state.results.get(t.test_id)
        if prev is not None and out["attempt"] > 1:
            out["previous_attempt"] = {"status_code": prev.get("status_code"), "outcome": prev.get("outcome"),
                                       "evidence_id": prev.get("evidence_id")}
        state.record(t.test_id, out)
        return ActionResult("done", {"test_id": t.test_id, "outcome": outcome, "status_code": resp.status_code},
                            evidence_ids=[eid] if eid else [], outputs=out)

    def restore(t: PlanTask, row: dict) -> None:
        if row["outputs"]:
            state.record(t.task_id.removesuffix(RETRY_SUFFIX), row["outputs"])

    selector = None
    if strategy in ("deterministic", "llm"):
        min_score = float(case.stop_conditions.get("min_score", 0.05))

        def selector(outcome) -> tuple[str | None, str]:
            if ledger.time_exhausted():
                return None, "budget_time_exhausted"
            remaining = ledger.requests_remaining()
            if remaining <= 0:
                return None, "budget_requests_exhausted"
            pending = {tid for tid, r in outcome.tasks.items() if r.state == TaskState.PENDING}
            if retry_on:
                for tid, res in sorted(state.results.items()):
                    rt = tid + RETRY_SUFFIX
                    code, t = res.get("status_code"), case.tests[tid]
                    if (rt in pending and res["outcome"] == INCONCLUSIVE and res.get("attempt", 1) == 1
                            and code in TRANSIENT_STATUSES and code in t.inconclusive_statuses and t.cost <= remaining):
                        wait = _retry_wait(res.get("retry_after"))
                        why = f"retry_transient: status_{code} on {tid} (attempt 2 of 2, waited {wait:g}s)"
                        try:
                            journal.append("retry_scheduled", test_id=tid, reason=f"status_{code}", attempt=2, wait_s=wait)
                        except JournalError:
                            return None, "audit_failed"
                        if wait:
                            sleep(wait)
                        counters["retries"] += 1
                        counters["selections"] += 1
                        selection_log.append({"step": counters["selections"], "test_id": rt, "reason": why, "retry": True,
                                              "top": []})
                        return rt, why
            if case.stop_conditions.get("stop_when_all_hypotheses_resolved", True) and all(
                    state.resolved(h) for h in case.hypotheses):
                return None, "all_hypotheses_resolved"
            cands = candidates(case, state, pending, remaining)
            if not cands:
                return None, "no_selectable_tests"
            det = rank(case, state, cands)
            if det[0][0] < min_score:
                return None, "no_valuable_tests"
            chosen, why = det[0][1], f"deterministic score={det[0][0]:.3f}"
            if strategy == "llm" and llm is not None:
                chosen, why = _llm_choice(det, cands, remaining, chosen, why)
            counters["selections"] += 1
            selection_log.append({"step": counters["selections"], "test_id": chosen, "reason": why,
                                  "top": [[tid, round(s, 3)] for s, tid in det[:4]]})
            return chosen, why

    def _llm_choice(det, cands, remaining, default, default_why):
        msgs = build_rank_messages(case, state, cands, det, remaining)
        dec = ledger.reserve_llm_call(sum(len(m["content"]) for m in msgs))
        if not dec.ok:
            counters["llm_fallbacks"] += 1
            return default, f"{default_why} (llm_unavailable:{dec.reason})"
        usage: dict = {}
        try:
            text = llm.complete(msgs, max_tokens=llm_max_tokens, usage_out=usage)
        except Exception as e:      # noqa: BLE001 — LLM失敗は決定論に戻す(黙殺せず記録)
            ledger.record_llm_usage(None)
            counters["llm_fallbacks"] += 1
            return default, f"{default_why} (llm_error:{type(e).__name__})"
        ledger.record_llm_usage(usage or None)
        pick, detail = parse_rank_reply(text, {t.test_id for t in cands})
        try:
            journal.append("llm_rank", accepted=bool(pick), test_id=pick or "", detail=mask(detail),
                           prompt_version=PROMPT_VERSION)
        except JournalError:
            pass
        if pick is None:
            counters["llm_selection_rejected"] += 1
            counters["llm_fallbacks"] += 1
            return default, f"{default_why} (llm_rejected:{detail})"
        return pick, f"llm: {mask(detail)}"

    executors = {CAP_ANON: execute, CAP_AUTHED: execute}
    runner = ScriptedRunner(gate=gate, journal=journal, registry=registry, executors=executors,
                            is_stopped=stopped, budget=ledger, plan=plan, store=store, resumed=resuming,
                            restore_cb=restore, retry_unknown=frozenset(retry_unknown or []),
                            selector=selector)
    finished = False
    try:
        outcome = runner.run(mode="LAB", target=base_url, scan_id=sr.scan_id, profile_hash=phash)
        denied = [r.reason for r in outcome.tasks.values()
                  if r.state in (TaskState.SKIPPED, TaskState.NEEDS_APPROVAL) and r.reason
                  and not r.reason.startswith(("not_selected", "stopped", "dependency", "session"))]
        counters["budget_denied"] = sum(1 for r in denied if r.startswith("budget."))
        counters["gate_denied"] = len(denied) - counters["budget_denied"]     # 予算以外(スコープ・副作用・引数・承認等)
        result = _assemble(case, state, outcome, runner, sr, strategy, journal.run_id, counters,
                           selection_log, ledger, evidence, mask, llm, budget)
        result.errors = [mask(e) for e in result.errors]
        end_errors = runner.close_run(state=result.state, errors=result.errors)
        if end_errors:
            result.errors += end_errors
            result.clean_finish = False
            if result.state == ScanState.COMPLETED.value:
                result.state = ScanState.PARTIAL.value
        finished = True
    finally:
        if not finished:
            runner.close_run(state=ScanState.FAILED.value, errors=["内部エラーで中断しました"])
        for o in (store, journal):
            try:
                o.close()
            except Exception:   # noqa: BLE001
                pass
    result.elapsed_seconds = round(time.time() - t_start, 3)
    return result


def _assemble(case, state, outcome, runner, sr, strategy, run_id, counters, selection_log, ledger,
              evidence, mask, llm, budget) -> LabRunResult:
    tests: dict[str, dict] = {}
    coverage: list[CoverageItem] = []
    for tid, t in case.tests.items():
        rec = outcome.tasks.get(tid)
        res = state.results.get(tid)
        if res is not None:
            st = "executed" if res["outcome"] != INCONCLUSIVE else "inconclusive"
            tests[tid] = {"state": st, "outcome": res["outcome"], "reason": res["reason"],
                          "status_code": res["status_code"], "evidence_id": res["evidence_id"], "diffs": res["diffs"],
                          "body_complete": res.get("body_complete", True), "incomplete_reason": res.get("incomplete_reason")}
            cov = CoverageStatus.TESTED if res["outcome"] != INCONCLUSIVE else CoverageStatus.FAILED
            why = res["reason"]
        else:
            reason = rec.reason if rec else "not_in_plan"
            if rec and rec.state == TaskState.UNKNOWN_OUTCOME:
                reason = "unknown_outcome"
            if reason == "not_selected:no_selectable_tests" and t.unlocked_by and not state.unlocked(t):
                src = state.results.get(t.unlocked_by["test_id"], {})
                undecided = t.test_id in src.get("unlock_undecided", [])
                reason = "locked_unlock_undecided_incomplete_body" if undecided else "locked_never_unlocked"
            tests[tid] = {"state": "not_run", "outcome": None, "reason": reason, "status_code": None,
                          "evidence_id": None, "diffs": []}
            cov, why = CoverageStatus.SKIPPED, reason
        coverage.append(CoverageItem(target_ref=t.path, status=cov.value, rule_id=case.hypotheses[t.hypothesis].rule_id,
                                     parameter=",".join(k for k, _ in t.params), auth_context=t.role, reason=why))

    hyps, findings, untested, candidates = {}, [], [], []
    for hid, h in case.hypotheses.items():
        st = state.hyp_status(hid)
        run = [t.test_id for t in state.tests_of(hid) if t.test_id in state.results]
        not_run = [t.test_id for t in state.tests_of(hid) if t.test_id not in state.results]
        hyps[hid] = {"status": st, "corroborated": state.corroborated(hid), "control_state": state.control_state(hid),
                     "tests_run": run,
                     "tests_not_run": not_run, "feature": h.feature, "rule_id": h.rule_id, "title": h.title}
        if st != "refuted" and st != "supported":
            untested.append({"hypothesis_id": hid, "title": h.title, "status": st, "tests_not_run": not_run,
                             "inconclusive": [t for t in run if state.results[t]["outcome"] == INCONCLUSIVE]})
        if st == "unverified_deviation":
            dev = [t for t in state.tests_of(hid, "probe") if state.results.get(t.test_id, {}).get("outcome") == DEVIATES]
            candidates.append({
                "hypothesis_id": hid, "title": h.title, "rule_id": h.rule_id, "feature": h.feature,
                "status": "deviation_unverified", "control_state": state.control_state(hid),
                "test_ids": [t.test_id for t in dev],
                "control_test_ids": [t.test_id for t in state.tests_of(hid, "control")],
                "diffs": {t.test_id: state.results[t.test_id]["diffs"] for t in dev},
                "evidence_ids": [state.results[t.test_id]["evidence_id"] for t in dev if state.results[t.test_id]["evidence_id"]],
                "observation_limits": [{"test_id": t.test_id, "reason": state.results[t.test_id].get("incomplete_reason")}
                                       for t in dev if not state.results[t.test_id].get("body_complete", True)],
                "note": "逸脱は観測したが、必要な対照が未実施。不備と確定せず、連鎖の根拠にもしない"})
        elif st == "supported" and not_run:
            untested.append({"hypothesis_id": hid, "title": h.title, "status": "supported_partial",
                             "tests_not_run": not_run, "inconclusive": []})
        if st == "supported":
            dev = [t for t in state.tests_of(hid, "probe") if state.results.get(t.test_id, {}).get("outcome") == DEVIATES]
            ctl = [t for t in state.tests_of(hid, "control") if state.results.get(t.test_id, {}).get("outcome") == CONFORMS]
            first = dev[0]
            ev_ids = [state.results[t.test_id]["evidence_id"] for t in dev + ctl if state.results[t.test_id]["evidence_id"]]
            # 裏付けに必要な根拠一式(逸脱probe＋通った対照)。1つでも保存証拠が無ければ第三者は再検証できない
            ev_missing = [t.test_id for t in dev + ctl if not state.results[t.test_id]["evidence_id"]]
            limits = [{"test_id": t.test_id, "reason": state.results[t.test_id].get("incomplete_reason")}
                      for t in dev + ctl if not state.results[t.test_id].get("body_complete", True)]
            corr = state.corroborated(hid)
            f = Finding(
                finding_id=new_id("find"), rule_id=h.rule_id, location=f"{first.path} [{h.feature}]",
                severity=h.severity_hint,
                verification_state=(VerificationState.CORROBORATED if corr else VerificationState.OBSERVED).value,
                evidence_ids=ev_ids, description=h.title,
                remediation=h.remediation,
                analysis="期待値との差: " + "; ".join(state.results[first.test_id]["diffs"]))
            fd = f.to_dict()
            fd.update({"hypothesis_id": hid, "feature": h.feature,
                       "test_ids": [t.test_id for t in dev], "control_test_ids": [t.test_id for t in ctl],
                       "diffs": {t.test_id: state.results[t.test_id]["diffs"] for t in dev},
                       "evidence_complete": bool(ev_ids) and not ev_missing,
                       "evidence_missing_test_ids": ev_missing,
                       "observation_limits": limits,
                       "repro": [repro_step(case, t) for t in dev]})
            findings.append(fd)
            sr.findings.append(f)

    errors = list(outcome.errors)
    if evidence is not None:
        errors += [f"証拠保存エラー: {e}" for e in evidence.save_errors] + [f"証拠保存を省略: {e}" for e in evidence.omissions]
    all_resolved = all(state.resolved(h) for h in case.hypotheses)
    if outcome.audit_failed:
        scan_state = ScanState.FAILED.value
    elif runner.finish_reason == "stopped" or runner.is_stopped():
        scan_state = ScanState.CANCELLED.value
    elif all_resolved and not [u for u in untested if u["status"] != "supported_partial"] and not case.out_of_scope:
        scan_state = ScanState.COMPLETED.value
    else:
        scan_state = ScanState.PARTIAL.value        # 未判定・未実施・検査対象外があるものをcompletedにしない
    clean = not outcome.audit_failed and not any("内部エラー" in e for e in errors)
    sr.state, sr.errors, sr.coverage = scan_state, errors, coverage
    sr.ended_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    sr.config_version = LAB_ENGINE_VERSION
    sr.detector_version = f"{LAB_ENGINE_VERSION}/{strategy}"
    usage = ledger.llm_usage_summary()
    chains, open_chains = lab_chain.find_chains(case, state.hyp_status)
    return LabRunResult(
        case_id=case.case_id, strategy=strategy, run_id=run_id, scan_id=sr.scan_id, state=scan_state,
        end_reason=outcome.end_reason, finish_reason=runner.finish_reason or outcome.end_reason, clean_finish=clean,
        tests=tests, hypotheses=hyps, findings=findings, candidates=candidates, untested=untested, selection_log=selection_log,
        errors=errors, counters=counters, budget={**ledger.snapshot(), "configured": budget}, llm=usage,
        versions={"engine": ENGINE_VERSION, "lab_engine": LAB_ENGINE_VERSION, "prompt": PROMPT_VERSION,
                  "model": getattr(llm, "model", "") if llm is not None else ""},
        scan_result=sr.to_dict(),
        out_of_scope=[dict(o) for o in case.out_of_scope], chains=chains, open_chains=open_chains)


def repro_step(case: LabCase, t: LabTest) -> str:
    q = ("?" + t.query()) if t.params else ""
    who = "未認証" if t.role == "anonymous" else f"{t.role}({case.accounts[t.role]})のセッション"
    return f"{who}で GET {t.path}{q} を送り、応答が期待値(expect)と一致するか確認する"
