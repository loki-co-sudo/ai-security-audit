"""
core/autonomy/research_planner.py — Researcher: 観測の取り込み・仮説の事前登録・優先順位付け・再計画（通信しない）

実行は ScriptedRunner 経由（research_loop.py）。ここは『次に何を調べるか』の判断だけを担い、判断の根拠をジャーナルへ残す。
ジャーナルの順序契約: hypothesis_registered → experiment_planned → task_added → gate_decision → action_started →
action_finished → observation_ingested → hypothesis_updated（予測と反証条件は実験より前のseqに残る）。

優先順位の係数は、結果を見る前に固定した値（評価後に動かさない）:
  value = 型の事前重要度 × (根拠が独立: 1.0 / 推定: 0.5) × 一般化係数 / 追加で必要な実験数
  一般化係数: 同じ(型,操作,ロール)で未検査の最初の1件=1.0、残り=0.3。既に逸脱が見つかった組=0.1、棄却済みの組=0.35。
  同じ(型,操作)で別ロールが既に支持済み=×0.4（同じ欠陥の重複確認は情報価値が低い）。
"""
from __future__ import annotations
from typing import Callable

from core.autonomy.actions import SideEffect  # noqa: F401  (型の明示)
from core.autonomy.budget import BudgetLedger
from core.autonomy.journal import RunJournal
from core.autonomy.research_case import BlindCase
from core.autonomy.research_hypothesis import (
    PRIOR, S_REFUTED, S_REGISTERED, S_SUPPORTED, S_UNVERIFIED,
    Hypothesis, evaluate_check, hyp_state, propose, validate_experiment, validate_hypothesis, INCONCLUSIVE,
)
from core.autonomy import research_llm
from core.autonomy.research_model import ExpResult, Experiment, TargetModel
from core.autonomy.runner import PlanTask
from core.autonomy.task_graph import TaskState

CAP_ANON, CAP_AUTHED = "research.get_anon", "research.get_authed"
UNGROUNDED_FACTOR = 0.5
SAME_KEY_FIRST, SAME_KEY_OTHERS, KEY_REFUTED, KEY_SUPPORTED, OP_SUPPORTED = 1.0, 0.3, 0.35, 0.1, 0.4
DEFAULT_MIN_VALUE = 0.02


class Researcher:
    def __init__(self, case: BlindCase, base_url: str, journal: RunJournal, ledger: BudgetLedger,
                 is_stopped: Callable[[], bool], llm=None, llm_max_tokens: int = 800):
        self.case, self.base_url, self.journal, self.ledger, self.is_stopped = case, base_url, journal, ledger, is_stopped
        self.model = TargetModel(case)
        self.hyps: dict[str, Hypothesis] = {}
        self.rejected: list[dict] = []
        self.states: dict[str, tuple] = {}
        self.experiments: dict[str, Experiment] = {}      # 計画済み(exp_id -> Experiment)
        self.buffer: dict[str, ExpResult] = {}            # executorが書く未取り込みの結果
        self._ingested: set[str] = set()
        self.decisions: list[dict] = []
        self.commit_hid: str | None = None
        self.finish_reason = ""
        self.stage = 0
        self.min_value = float(case.stop_conditions.get("min_value", DEFAULT_MIN_VALUE))
        self.exp_purpose: dict[str, str] = {}
        self.planned_seq: dict[str, int] = {}             # exp_id -> experiment_planned のseq
        self.llm, self.llm_max_tokens = llm, llm_max_tokens
        self._llm_done: set[str] = set()
        self.llm_stats = {"calls": 0, "skipped": 0, "parse_failures": 0, "proposals": 0, "new_registered": 0,
                          "duplicate_of_rule": 0, "duplicate_of_llm": 0, "rejected": {}, "usage": [], "details": []}

    # ── Runnerのフック ───────────────────────────
    def step(self, outcome) -> list[PlanTask]:
        """実行待ちが無くなるたびに呼ばれる。観測を取り込み→仮説を登録→状態更新→次の実験を1件選ぶ(無ければ終了)。"""
        self._ingest_new()
        if self.stage >= 1:
            self.model.sessions_checked = True
        self._register_new()
        if self.llm is not None:
            if self.stage == 0:
                self._llm_phase("spec")                   # 仕様だけで提案できるもの（探索実験より前に登録する）
            elif self.stage >= 2:
                self._llm_phase("observed")               # 観測した所有/共有関係を踏まえた提案
        self._refresh_states()
        while self.stage < 2:
            self.stage += 1
            tasks = self._discovery_tasks(self.stage)
            if tasks:
                return tasks
        if self.is_stopped():
            self.finish_reason = "stopped"
            return []
        if self.ledger.time_exhausted():
            self.finish_reason = "budget_time_exhausted"
            return []
        if self.ledger.requests_remaining() <= 0:
            self.finish_reason = "budget_requests_exhausted"
            return []
        ranked = self._rank()
        if not ranked:
            self.finish_reason = "frontier_empty"
            return []
        for i, (value, h, exp, purpose) in enumerate(ranked):
            if value < self.min_value:
                break
            problems = validate_experiment(exp, self.model)
            if problems:      # 観測に由来しない引数・未承認の操作は送信しない。理由を残して次の候補へ
                self.journal.append("experiment_rejected", exp_id=exp.exp_id, hypothesis_id=h.hypothesis_id, problems=problems)
                self.experiments[exp.exp_id] = exp
                self.rejected.append({"hypothesis_id": h.hypothesis_id, "exp_id": exp.exp_id, "problems": problems})
                continue
            return [self._plan(exp, purpose, h, value, ranked[i:])]
        self.finish_reason = "no_valuable_hypotheses"
        return []

    def select(self, outcome) -> tuple[str | None, str]:
        pend = [tid for tid, r in outcome.tasks.items() if r.state == TaskState.PENDING]
        if not pend:
            return None, "frontier_empty"
        return pend[0], self.exp_purpose.get(pend[0], "planned")

    # ── 観測 ────────────────────────────────────
    def _ingest_new(self) -> None:
        for exp_id, res in list(self.buffer.items()):
            if exp_id in self._ingested:
                continue
            self._ingested.add(exp_id)
            exp = self.experiments[exp_id]
            notes = self.model.ingest(exp, res)
            self.journal.append("observation_ingested", exp_id=exp_id, role=exp.role, op_id=exp.op_id,
                                status_code=res.status_code, evidence_id=res.evidence_id,
                                body_complete=res.body_complete, notes=notes)

    # ── 仮説の登録（実験より前にジャーナルへ） ──────────────
    def _register_new(self) -> None:
        for h in propose(self.model):
            self._register(h)

    def _register(self, h: Hypothesis) -> bool:
        """検証器（有効な仮説の定義）を通ったものだけを、実験より前にジャーナルへ登録する。"""
        rejected_ids = {r["hypothesis_id"] for r in self.rejected}
        if h.hypothesis_id in self.hyps or h.hypothesis_id in rejected_ids:
            return False
        problems = validate_hypothesis(h, self.model)
        if problems:
            self.rejected.append({"hypothesis_id": h.hypothesis_id, "problems": problems})
            self.journal.append("hypothesis_rejected", hypothesis_id=h.hypothesis_id, problems=problems)
            return False
        h.probe_preexisting = h.probe is not None and h.probe.exp_id in self.model.results
        ev = self.journal.append("hypothesis_registered", prediction_sha=h.prediction_sha(),
                                 probe_preexisting=h.probe_preexisting, **h.registration_dict())
        h.registered_seq = ev["seq"]
        self.hyps[h.hypothesis_id] = h
        return True

    # ── LLM提案（U2）: 提案は検証器を通ったものだけが登録される ─────────
    def _llm_phase(self, phase: str) -> None:
        if phase in self._llm_done:
            return
        self._llm_done.add(phase)
        st = self.llm_stats
        msgs, dropped = research_llm.build_messages(self.case, self.model, phase)
        dec = self.ledger.reserve_llm_call(sum(len(m["content"]) for m in msgs))
        if not dec.ok:
            st["skipped"] += 1
            self.journal.append("llm_proposals", phase=phase, skipped=True, reason=dec.reason,
                                prompt_version=research_llm.PROMPT_VERSION)
            return
        usage: dict = {}
        st["calls"] += 1
        try:
            text = self.llm.complete(msgs, max_tokens=self.llm_max_tokens, usage_out=usage)
        except Exception as e:      # noqa: BLE001 — LLM失敗でも規則による調査は続ける（黙殺せず記録）
            self.ledger.record_llm_usage(None)
            st["parse_failures"] += 1
            self.journal.append("llm_proposals", phase=phase, error=type(e).__name__, prompt_version=research_llm.PROMPT_VERSION)
            return
        self.ledger.record_llm_usage(usage or None)
        st["usage"].append(usage or None)
        items, why = research_llm.parse_reply(text)
        if items is None:
            st["parse_failures"] += 1
            self.journal.append("llm_proposals", phase=phase, parse_error=why, reply_sha=research_llm.reply_sha(text),
                                prompt_version=research_llm.PROMPT_VERSION, dropped=dropped)
            return
        results = []
        for p in items:
            status, reason, h = research_llm.process_proposal(self.case, self.model, p)
            st["proposals"] += 1
            if status == "new":
                if h.hypothesis_id in self.hyps:
                    status, reason = "duplicate_of_llm", ""
                elif self._register(h):
                    st["new_registered"] += 1
                else:
                    status = "rejected"
                    reason = "validator:" + ",".join(next((r["problems"] for r in self.rejected
                                                           if r["hypothesis_id"] == h.hypothesis_id), ["unknown"]))[:120]
            elif status == "duplicate_of_rule" and (h is None or h.hypothesis_id not in self.hyps):
                status, reason = "rejected", "rule_equivalent_not_registered"
            if status == "duplicate_of_rule":
                st["duplicate_of_rule"] += 1
            elif status == "duplicate_of_llm":
                st["duplicate_of_llm"] += 1
            elif status == "rejected":
                st["rejected"][reason] = st["rejected"].get(reason, 0) + 1
            d = {"phase": phase, "check": research_llm.clean_text(p.get("check", ""), 30) if isinstance(p, dict) else "",
                 "op_id": research_llm.clean_text(p.get("op_id", ""), 40) if isinstance(p, dict) else "",
                 "probe_role": research_llm.clean_text(p.get("probe_role", ""), 40) if isinstance(p, dict) else "",
                 "status": status, "reason": reason, "hypothesis_id": h.hypothesis_id if h is not None else ""}
            results.append(d)
            st["details"].append(d)
        self.journal.append("llm_proposals", phase=phase, prompt_version=research_llm.PROMPT_VERSION,
                            reply_sha=research_llm.reply_sha(text), dropped=dropped, usage=usage or None, results=results)

    def _refresh_states(self) -> None:
        for hid, h in self.hyps.items():
            new = hyp_state(h, self.model.results, self.model)
            old = self.states.get(hid)
            if old == new:
                continue
            if old is not None or new[0] != S_REGISTERED:
                based = [e.exp_id for e in (h.probe, h.control) if e is not None and e.exp_id in self.model.results]
                self.journal.append("hypothesis_updated", hypothesis_id=hid, from_state=old[0] if old else "",
                                    to_state=new[0], reason=new[1], based_on=based, prediction_sha=h.prediction_sha())
            self.states[hid] = new

    # ── 計画 ────────────────────────────────────
    def _discovery_tasks(self, stage: int) -> list[PlanTask]:
        """観測の足がかり（仮説の検証ではなく、仮説を具体化するための情報収集実験）。
        段階1: 各アカウントの利用者ID(identity)。段階2: IDを取得できたアカウントだけ、所有オブジェクト一覧(own_list)。
        段階1の結果（認証失敗等）で段階2の実験が変わる＝観測が次の操作を決める。"""
        ops = self.case.operations
        kind = "identity" if stage == 1 else "own_list"
        op_ids = sorted(o.op_id for o in ops.values() if o.method == "GET" and not o.params and (
            o.returns.get("identity") if stage == 1 else o.access["kind"] == "own_list"))
        roles = sorted(self.case.accounts) if stage == 1 else sorted(self.model.identity)
        tasks: list[PlanTask] = []
        for role in roles:
            for op_id in op_ids:
                exp = Experiment(role, op_id)
                if exp.exp_id in self.experiments:
                    continue
                tasks.append(self._to_task(exp))
                self.exp_purpose[exp.exp_id] = f"discovery({kind}): 仮説の対象(ID・ロール・共有関係)を決める観測"
                self._journal_planned(exp, "discovery", [], 0.0, self.exp_purpose[exp.exp_id])
        skipped = sorted(set(self.case.accounts) - set(roles)) if stage == 2 else []
        self.decisions.append({"step": len(self.decisions), "purpose": f"discovery_stage_{stage}",
                               "experiments": [t.task_id for t in tasks], "skipped_roles": skipped,
                               "why": ("各アカウントの利用者IDを観測" if stage == 1 else
                                       "利用者IDを取得できたアカウントだけ、所有/共有オブジェクトを観測")})
        return tasks

    def _to_task(self, exp: Experiment, depends: tuple = ()) -> PlanTask:
        op = self.case.operations[exp.op_id]
        self.experiments[exp.exp_id] = exp
        args = {"url": self.base_url.rstrip("/") + op.path_for(exp.params()), "exp_id": exp.exp_id, "op_id": exp.op_id,
                "role": exp.role, "path_params": exp.params()}
        return PlanTask(exp.exp_id, CAP_ANON if exp.role == "anonymous" else CAP_AUTHED, args,
                        depends_on=depends, auth_context=exp.role)

    def _journal_planned(self, exp: Experiment, purpose: str, serves: list, value: float, why: str) -> None:
        ev = self.journal.append("experiment_planned", exp_id=exp.exp_id, role=exp.role, op_id=exp.op_id,
                                 path_params=exp.params(), purpose=purpose, serves=serves, value=round(value, 4),
                                 why=why[:300])
        self.planned_seq[exp.exp_id] = ev["seq"]

    def _plan(self, exp: Experiment, purpose: str, h: Hypothesis, value: float, ranked: list) -> PlanTask:
        serves = sorted(x.hypothesis_id for x in self.hyps.values()
                        if (x.probe and x.probe.exp_id == exp.exp_id) or (x.control and x.control.exp_id == exp.exp_id))
        why = (f"{h.hypothesis_id}の{purpose}: value={value:.3f}"
               + (" (対照)" if purpose == "control" else ""))
        task = self._to_task(exp)
        self.exp_purpose[exp.exp_id] = why
        self._journal_planned(exp, purpose, serves, value, why)
        self.decisions.append({"step": len(self.decisions), "exp_id": exp.exp_id, "purpose": purpose,
                               "hypothesis_id": h.hypothesis_id, "serves": serves, "value": round(value, 4),
                               "alternatives": [[x[1].hypothesis_id, round(x[0], 4)] for x in ranked[1:4]]})
        self.commit_hid = h.hypothesis_id if purpose == "probe" else None
        return task

    # ── 優先順位 ────────────────────────────────
    def _next_experiment(self, h: Hypothesis) -> tuple[Experiment | None, str]:
        res = self.model.results
        if h.gap is not None or h.probe_preexisting:
            return None, ""
        if h.probe.exp_id not in res:
            return (h.probe, "probe") if h.probe.exp_id not in self.experiments else (None, "")
        out, _, _ = evaluate_check(h.check, res[h.probe.exp_id], self.model)
        if out == INCONCLUSIVE:
            return None, ""                       # 応答が判断不能な実験に対照を重ねても結論は変わらない
        if (h.control_required and h.control is not None and h.control.exp_id not in res
                and h.control.exp_id not in self.experiments):
            return h.control, "control"
        return None, ""

    def _gen_factor(self, h: Hypothesis) -> float:
        sibs = [x for x in self.hyps.values() if x.key == h.key and x.hypothesis_id != h.hypothesis_id]
        st = [self.states[x.hypothesis_id][0] for x in sibs]
        if any(s in (S_SUPPORTED, S_UNVERIFIED) for s in st):
            f = KEY_SUPPORTED
        elif any(s == S_REFUTED for s in st):
            f = KEY_REFUTED
        else:
            untested = sorted(x.hypothesis_id for x in sibs + [h] if x.probe is not None and x.probe.exp_id not in self.model.results)
            f = SAME_KEY_FIRST if untested and untested[0] == h.hypothesis_id else SAME_KEY_OTHERS
        op_level = [x for x in self.hyps.values() if x.family == h.family and x.op_id == h.op_id
                    and x.probe_role != h.probe_role and self.states[x.hypothesis_id][0] == S_SUPPORTED]
        return f * (OP_SUPPORTED if op_level else 1.0)

    def _rank(self) -> list[tuple]:
        out = []
        for h in self.hyps.values():
            exp, purpose = self._next_experiment(h)
            if exp is None:
                continue
            if purpose == "control" and self.commit_hid == h.hypothesis_id:
                out.append((1e9, h, exp, purpose))        # 逸脱/棄却を観測した直後は、同じ仮説の対照を先に完了させる
                continue
            res = self.model.results
            cost = 1 + (1 if (purpose == "probe" and h.control_required and h.control is not None
                              and h.control.exp_id not in res and h.control.exp_id not in self.experiments) else 0)
            v = PRIOR[h.family] * (1.0 if h.grounded else UNGROUNDED_FACTOR) * self._gen_factor(h) / cost
            out.append((v, h, exp, purpose))
        out.sort(key=lambda x: (-x[0], x[1].hypothesis_id))
        return out

    # ── 終了時 ──────────────────────────────────
    def close_unexamined(self) -> None:
        """未検査のまま終わった仮説を、終了理由つきの状態として残す。"""
        for hid, h in self.hyps.items():
            if self.states.get(hid, (S_REGISTERED,))[0] == S_REGISTERED:
                self.journal.append("hypothesis_updated", hypothesis_id=hid, from_state=S_REGISTERED,
                                    to_state="not_examined", reason=self.finish_reason or "not_selected",
                                    based_on=[], prediction_sha=h.prediction_sha())
                self.states[hid] = ("not_examined", self.finish_reason or "not_selected")
