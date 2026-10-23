"""
core/autonomy/research_hypothesis.py — 仮説・予測・反証条件・実験設計・判定（Hypothesis Engine / Experiment Planner / Evidence Evaluator）

人間が案件ファイルに書いていた「仮説・対照・期待値」を、システムが仕様と観測から作る部分。
  1. propose(): 提供仕様(clause)と観測済みのオブジェクト/利用者から、検証可能な仮説を具体化する。
     仮説の**型**(object_authz / function_authz / unauth_access / field_exposure / mutation_authz)は開発者が与えた規則で、
     何を・誰が・どのIDで・どの対照とともに調べるかは対象の観測から決まる。型の外の仮説は作れない(LLM提案は次の単位)。
  2. 予測と反証条件を**実験の前に**機械可読で確定する(registration_dict/prediction_sha。ジャーナルに先に書く)。
  3. validate_hypothesis(): 『有効な仮説』の事前定義。根拠・前提・反証可能な予測・登録済み操作への写像が揃わないものは実験に進めない。
  4. evaluate_check()/hyp_state(): 事前登録した予測だけで応答を判定する。結果を見てから期待値を作らない。

確定の原則(要求仕様 §4.E): 『拒否されるべき』という期待値は、仕様の条項(clause)と観測済みの所有/共有関係に結び付く場合だけ
独立した根拠とみなす(grounded)。仕様が沈黙している操作の期待値は推定(ungrounded)で、逸脱を観測しても候補止まり。
対照が未実施・失敗の逸脱も確定しない。
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field

from core.autonomy.research_case import SpecOperation
from core.autonomy.research_model import (
    ExpResult, Experiment, TargetModel, contains_marker, json_keys,
)

CONFORMS, DEVIATES, INCONCLUSIVE = "conforms", "deviates", "inconclusive"
FAMILIES = ("object_authz", "function_authz", "unauth_access", "field_exposure", "list_scope", "mutation_authz")
PRIOR = {"object_authz": 0.7, "function_authz": 0.6, "list_scope": 0.6, "field_exposure": 0.5, "unauth_access": 0.4, "mutation_authz": 0.0}
RULE_ID = {"object_authz": "IDOR", "function_authz": "ACCESS_CONTROL", "unauth_access": "AUTH_MISSING",
           "field_exposure": "EXCESSIVE_DATA_EXPOSURE", "list_scope": "IDOR", "mutation_authz": "ACCESS_CONTROL"}
SEVERITY_ESTIMATE = {"object_authz": "HIGH", "function_authz": "HIGH", "unauth_access": "HIGH",
                     "field_exposure": "MEDIUM", "list_scope": "HIGH", "mutation_authz": "HIGH"}      # 型からの見積り(影響の測定ではない)
DENY_AUTHED = [403, 404]
DENY_ANON = [401, 403]
CHECK_TYPES = ("deny_expected", "allow_expected", "fields_subset", "list_visibility")

S_REGISTERED, S_SUPPORTED, S_REFUTED = "registered", "supported", "refuted"
S_UNVERIFIED, S_UNDETERMINED, S_UNVERIFIABLE = "unverified_deviation", "undetermined", "unverifiable"
S_NOT_EXAMINED = "not_examined"


@dataclass
class Hypothesis:
    hypothesis_id: str
    family: str
    op_id: str
    probe_role: str
    object_id: str
    claim: str
    basis: list
    preconditions: list
    check: dict                               # 機械可読の判定条件(probeに適用)
    prediction_if_true: str                   # 仮説が正しいなら観測されるはずのこと
    falsification: str                        # 仮説を棄却する観測
    probe: Experiment | None
    control: Experiment | None
    control_required: bool
    control_reason: str                       # 対照が無い/不要の理由
    control_check: dict | None
    grounded: bool
    ungrounded_reason: str = ""
    needed_observations: list = field(default_factory=list)
    gap: dict | None = None                   # 検証不能の理由と必要な能力
    registered_seq: int = 0                   # ジャーナルでの登録イベントのseq(実験より前でなければならない)
    probe_preexisting: bool = False           # 登録時点で既にprobe相当の結果があった(予測の事前登録にならない)
    key: tuple = ()                           # 一般化の単位 (family, op_id, probe_role)
    source: str = "rule"                      # 仮説の出どころ: rule(開発者の規則) / llm(LLM提案を検証器が採用)
    llm_rationale: str = ""                   # LLMの説明（無害化済み・追跡用。判定や報告の根拠には使わない）

    # ── 事前登録 ────────────────────────────────
    def registration_dict(self) -> dict:
        return {
            "hypothesis_id": self.hypothesis_id, "family": self.family, "op_id": self.op_id,
            "probe_role": self.probe_role, "object_id": self.object_id, "claim": self.claim,
            "basis": self.basis, "preconditions": self.preconditions,
            "unconfirmed_assumptions": [p["text"] for p in self.preconditions if p["status"] == "unverified"],
            "prediction_if_true": self.prediction_if_true, "falsification": self.falsification, "check": self.check,
            "control_check": self.control_check, "control_required": self.control_required,
            "control_reason": self.control_reason, "grounded": self.grounded, "ungrounded_reason": self.ungrounded_reason,
            "probe": _exp_dict(self.probe), "control": _exp_dict(self.control),
            "needed_observations": self.needed_observations, "gap": self.gap, "source": self.source,
            "llm_rationale": self.llm_rationale,
        }

    def prediction_sha(self) -> str:
        core = {k: v for k, v in self.registration_dict().items()}
        return hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


def _exp_dict(e: Experiment | None) -> dict | None:
    return None if e is None else {"exp_id": e.exp_id, "role": e.role, "op_id": e.op_id, "path_params": dict(e.path_params)}


# ── 判定 ─────────────────────────────────────────
def _marker_present(marker: dict, res: ExpResult) -> bool:
    if marker.get("mode") == "object_key":
        return contains_marker(res.json, marker["key"], marker["value"])
    return bool(res.json)            # nonempty_json: 空でないJSON(オブジェクト/配列)


def evaluate_check(check: dict, res: ExpResult | None, model: TargetModel | None = None) -> tuple[str, str, list]:
    """事前登録した判定条件で応答を判定する。戻り値: (outcome, reason, detail)。detailは項目名だけ(値は含めない)。"""
    if res is None:
        return INCONCLUSIVE, "not_run", []
    code = res.status_code
    if code is None:
        return INCONCLUSIVE, res.reason or "no_response", []
    t = check["type"]
    if t == "deny_expected":
        if code in check["deny_status"]:
            return CONFORMS, "denied", []
        if code == 200:
            if _marker_present(check["marker"], res):
                return DEVIATES, "access_granted", []
            return INCONCLUSIVE, "body_incomplete" if not res.body_complete else "200_without_marker", []
        return INCONCLUSIVE, "auth_failed" if code == 401 else f"status_{code}", []
    if t == "allow_expected":
        if code == 200:
            if _marker_present(check["marker"], res):
                return CONFORMS, "allowed", []
            return (INCONCLUSIVE, "body_incomplete", []) if not res.body_complete else (DEVIATES, "200_without_marker", [])
        if code in (403, 404):
            return DEVIATES, f"unexpectedly_denied_{code}", []
        return INCONCLUSIVE, "auth_failed" if code == 401 else f"status_{code}", []
    if t == "fields_subset":
        if code != 200 or res.json is None:
            return INCONCLUSIVE, f"status_{code}" if code != 200 else "no_json", []
        extra = sorted(json_keys(res.json) - set(check["allowed"]))
        if extra:
            return DEVIATES, "fields_beyond_spec", extra
        return (INCONCLUSIVE, "body_incomplete", []) if not res.body_complete else (CONFORMS, "within_spec", [])
    if t == "list_visibility":
        return _eval_list_visibility(check, res, model)
    raise ValueError(f"未知のcheck type: {t}")


def _eval_list_visibility(check: dict, res: ExpResult, model: TargetModel | None) -> tuple[str, str, list]:
    """一覧の各要素が、呼出し者に見えるはずのもの（所有者本人か共有先）だけかを、応答自身の所有者/共有先の項目で判定する。
    detailは件数だけ（IDや本文を含めない）。呼出し者の利用者IDは観測（me）から得るので、観測が無ければ判断しない。"""
    if res.status_code != 200 or not isinstance(res.json, list):
        return INCONCLUSIVE, "no_list" if res.status_code == 200 else f"status_{res.status_code}", []
    if model is None or check["role"] not in model.identity:
        return INCONCLUSIVE, "identity_unknown", []
    uid = model.identity[check["role"]]["user_id"]
    o = model.case.objects[check["object"]]
    ownf, shf = o.get("owner_field"), o.get("shared_field")
    items = [x for x in res.json if isinstance(x, dict)]
    if not items:
        return (INCONCLUSIVE, "body_incomplete", []) if not res.body_complete else (CONFORMS, "empty_list_visible_only", [])
    if any(ownf not in x for x in items):
        return INCONCLUSIVE, "owner_field_missing", []
    foreign = [x for x in items if x.get(ownf) != uid and uid not in (x.get(shf) or [])]
    if foreign:
        return DEVIATES, "foreign_items_listed", [f"foreign_items={len(foreign)}"]
    return (INCONCLUSIVE, "body_incomplete", []) if not res.body_complete else (CONFORMS, "only_visible_items", [])


def control_state(h: Hypothesis, results: dict) -> tuple[str, str]:
    """passed / failed / inconclusive / not_run / not_required / unavailable"""
    if not h.control_required:
        return "not_required", h.control_reason
    if h.control is None:
        return "unavailable", h.control_reason
    res = results.get(h.control.exp_id)
    if res is None:
        return "not_run", ""
    out, why, _ = evaluate_check(h.control_check, res)
    return {CONFORMS: "passed", DEVIATES: "failed", INCONCLUSIVE: "inconclusive"}[out], why


def hyp_state(h: Hypothesis, results: dict, model: TargetModel | None = None) -> tuple[str, str]:
    """(状態, 理由コード)。状態: registered / supported / refuted / unverified_deviation / undetermined / unverifiable。"""
    if h.gap is not None:
        return S_UNVERIFIABLE, h.gap["reason_code"]
    res = results.get(h.probe.exp_id)
    if res is None:
        return S_REGISTERED, "probe_not_run"
    out, why, _ = evaluate_check(h.check, res, model)
    if out == INCONCLUSIVE:
        return S_UNDETERMINED, f"probe_{why}"
    ctl, cwhy = control_state(h, results)
    if h.probe_preexisting:      # 登録前に得ていた結果は、事前登録した予測の検証にならない
        return (S_UNVERIFIED, "probe_preexisting") if out == DEVIATES else (S_UNDETERMINED, "probe_preexisting")
    if out == DEVIATES:
        if ctl in ("passed", "not_required"):
            if not h.grounded:
                return S_UNVERIFIED, "ungrounded_expectation"
            return S_SUPPORTED, ("grounded_deviation_control_passed" if ctl == "passed" else "grounded_deviation_control_not_required")
        if ctl == "not_run":
            return S_UNVERIFIED, "control_not_run"
        if ctl == "unavailable":
            return S_UNVERIFIED, "control_unavailable"
        return S_UNDETERMINED, f"control_{ctl}:{cwhy}"
    if ctl in ("passed", "not_required"):
        return S_REFUTED, "prediction_falsified_with_control"
    return S_UNDETERMINED, f"control_{ctl}"


# ── 有効な仮説の事前定義(7.4) ─────────────────────────
def validate_hypothesis(h: Hypothesis, model: TargetModel) -> list[str]:
    """『有効な仮説』= (1)根拠が実在する (2)前提の確認状態が明示 (3)反証可能な予測 (4)登録済み操作への写像 (5)対照/不要/不能の理由。
    戻り値は問題点(空なら有効)。実験に進めるのはこれを満たしたものだけ。"""
    case, p = model.case, []
    if h.family not in FAMILIES:
        p.append("family_unknown")
    if not h.claim or len(h.claim) > 600:
        p.append("claim_missing_or_too_long")
    if not h.basis:
        p.append("basis_missing")
    for b in h.basis:
        if b.get("kind") == "spec":
            if not any(o.access["clause"] == b.get("clause") for o in case.operations.values()):
                p.append(f"basis_spec_clause_unknown:{b.get('clause')}")
        elif b.get("kind") == "observation":
            if b.get("exp_id") not in model.results:
                p.append(f"basis_observation_missing:{b.get('exp_id')}")
        elif b.get("kind") == "assumption":
            if not b.get("text"):
                p.append("basis_assumption_empty")
        else:
            p.append("basis_kind_unknown")
    if any(x.get("status") not in ("spec", "observed", "unverified") for x in h.preconditions):
        p.append("precondition_status_invalid")
    if h.gap is not None:                                 # 検証不能の仮説: 必要な能力と理由が必須
        if not (h.gap.get("needed_capability") and h.gap.get("reason_code")):
            p.append("gap_incomplete")
        return p
    if not h.prediction_if_true or not h.falsification:
        p.append("prediction_or_falsification_missing")
    chk = h.check or {}
    if chk.get("type") not in CHECK_TYPES:
        p.append("check_type_invalid")
    elif chk["type"] == "deny_expected" and not chk.get("deny_status"):
        p.append("check_not_falsifiable")                 # 棄却できる観測が定義されていない
    elif chk["type"] == "fields_subset" and not chk.get("allowed"):
        p.append("check_not_falsifiable")
    elif chk["type"] == "list_visibility" and not (chk.get("role") in case.accounts and chk.get("object") in case.objects):
        p.append("check_not_falsifiable")
    if h.control_required and h.control is None and not h.control_reason:
        p.append("control_unavailable_without_reason")
    if not h.control_required and not h.control_reason:
        p.append("control_not_required_without_reason")
    for e in (h.probe, h.control):
        if e is not None:
            p += validate_experiment(e, model)
    if h.probe is None:
        p.append("probe_missing")
    return p


def validate_experiment(e: Experiment, model: TargetModel) -> list[str]:
    case, p = model.case, []
    op = case.operations.get(e.op_id)
    if op is None:
        return [f"experiment_op_unknown:{e.op_id}"]
    if op.method != "GET":
        p.append(f"experiment_method_not_approved:{op.method}")
    if e.role != "anonymous" and e.role not in case.accounts:
        p.append(f"experiment_role_unknown:{e.role}")
    if set(dict(e.path_params)) != set(op.params):
        p.append("experiment_params_mismatch")
    for name, val in e.path_params:
        otype = op.params.get(name, {}).get("object")
        known = ({i["user_id"] for i in model.identity.values()} if otype == "user"
                 else {o.object_id for o in model.objects_of(otype)})
        if val not in known:
            p.append(f"experiment_param_not_observed:{name}")      # 観測していないIDは使えない(推測・生成を許さない)
    if any(op.path.startswith(x) for x in case.excluded_paths):
        p.append("experiment_path_excluded")
    return p


# ── 仮説の具体化（Hypothesis Engine） ──────────────────────
def _spec_basis(op: SpecOperation) -> dict:
    return {"kind": "spec", "clause": op.access["clause"], "op_id": op.op_id, "text": op.access["text"]}


def _marker(op: SpecOperation, oid: str | None) -> dict:
    key = op.returns.get("object_key")
    return {"mode": "object_key", "key": key, "value": oid} if (key and oid) else {"mode": "nonempty_json"}


def _failed_roles(model: TargetModel) -> set:
    """観測に失敗したロール(期限切れ等)。以後の実験に使わない。"""
    return {u["what"].split(":")[0] for u in model.unknowns if u["what"].endswith(":identity")}


def _usable_accounts(model: TargetModel) -> list[str]:
    bad = _failed_roles(model)
    return sorted(r for r in model.case.accounts if r not in bad)


def _actor(model: TargetModel, privilege: str | None = None) -> str | None:
    for r in _usable_accounts(model):
        if privilege is None or model.case.accounts[r].privilege == privilege:
            return r
    return None


def propose(model: TargetModel) -> list[Hypothesis]:
    """現在のTarget Modelから、まだ作れる全ての仮説を決定論的に具体化する(IDで冪等)。"""
    out: list[Hypothesis] = []
    for op in sorted(model.case.operations.values(), key=lambda o: o.op_id):
        kind = op.access["kind"]
        if op.method != "GET":
            if kind != "public":
                out.append(_mutation_gap(op))
            continue
        if kind == "public":
            continue                                       # 仕様上の公開操作は『未認証でも成功する』のが期待。仮説にしない
        if kind in ("owner_or_shared", "owner_only") or (kind == "unspecified" and op.params and _sibling_grounded(model, op)):
            out += _object_authz(model, op)
        if kind == "role" and model.sessions_checked:      # どのアカウントのセッションが有効かを観測してから、ロールを選ぶ
            out += _function_authz(model, op)
        out += _unauth(model, op)
        if op.returns.get("fields"):
            out += _field_exposure(model, op)
    for h in out:
        h.key = (h.family, h.op_id, h.probe_role)
    return out


def _sibling_grounded(model: TargetModel, op: SpecOperation) -> bool:
    otype = op.access.get("object")
    return any(o.access["kind"] == "owner_or_shared" and o.access.get("object") == otype and o.method == "GET"
               for o in model.case.operations.values() if o.op_id != op.op_id)


def _mutation_gap(op: SpecOperation) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=f"h:mutation_authz:{op.op_id}", family="mutation_authz", op_id=op.op_id, probe_role="", object_id="",
        claim=f"{op.op_id}({op.method} {op.path})は仕様({op.access['clause']})どおり認可を強制している",
        basis=[_spec_basis(op)], preconditions=[], check={}, prediction_if_true="", falsification="",
        probe=None, control=None, control_required=False, control_reason="not_testable",
        control_check=None, grounded=True,
        gap={"reason_code": f"no_approved_operation:{op.method}", "needed_capability": f"{op.method}を送る操作部品(T3・操作ごとの個別承認が必須)",
             "detail": "状態を変える操作は自律調査に公開していない。承認済みの操作部品が無いため検証不能として残す"})


def _object_authz(model: TargetModel, op: SpecOperation) -> list[Hypothesis]:
    out: list[Hypothesis] = []
    otype = op.access["object"]
    grounded = op.access["kind"] in ("owner_or_shared", "owner_only")
    sib = next((o for o in model.case.operations.values() if o.access["kind"] == "owner_or_shared"
                and o.access.get("object") == otype and o.op_id != op.op_id), None)
    usable = _usable_accounts(model)
    for o in model.objects_of(otype):
        owner_role = model.role_of_user(o.owner_user) if o.owner_user else None
        if o.owner_user is None:
            continue
        for role in usable:
            ident = model.identity.get(role)
            if ident is None or ident["user_id"] == o.owner_user:
                continue
            shared = ident["user_id"] in o.shared_with
            if shared and op.access["kind"] == "owner_or_shared":
                continue          # 共有先は読めるのが仕様。検証対象にしない(正常な挙動を不備と誤認しない)
            probe = Experiment(role, op.op_id, ((op.access["param"], o.object_id),))
            control = Experiment(owner_role, op.op_id, probe.path_params) if owner_role else None
            listing = o.seen_via[0][1] if o.seen_via else None
            basis = [_spec_basis(op) if grounded else
                     {"kind": "assumption", "text": f"{op.op_id}のアクセス条件は仕様に記載がない。同じ{otype}を扱う{sib.op_id}({sib.access['clause']})と同じと推定"}]
            if not grounded:
                basis.append(_spec_basis(sib))
            basis += [{"kind": "observation", "exp_id": listing, "what": f"{otype}の所有者/共有先"},
                      {"kind": "observation", "exp_id": ident["exp_id"], "what": f"{role}の利用者ID"}]
            pre = [{"id": "p1", "text": f"{otype}は{role}以外の利用者が所有している", "status": "observed", "ref": listing},
                   {"id": "p2", "text": f"{role}は共有先に含まれない" if op.access["kind"] == "owner_or_shared" else f"{role}は所有者ではない",
                    "status": "observed", "ref": listing},
                   {"id": "p3", "text": f"所有者は同じ操作でこの{otype}に到達できる(対照で確認)", "status": "unverified",
                    "verified_by": control.exp_id if control else None},
                   {"id": "p4", "text": f"{role}のセッションは有効", "status": "observed", "ref": ident["exp_id"]}]
            if not grounded:
                pre.append({"id": "p5", "text": "未記載の操作も他の操作と同じアクセス条件のはず", "status": "unverified"})
            ctl_reason = "" if control else "所有者に対応するアカウントが無く、対照を実行できない"
            out.append(Hypothesis(
                hypothesis_id=f"h:object_authz:{op.op_id}:{role}:{o.object_id}", family="object_authz", op_id=op.op_id,
                probe_role=role, object_id=o.object_id,
                claim=f"{role}は、権限を持たない{otype} {o.object_id}を{op.op_id}で取得できる(仕様{op.access['clause']}: {op.access['text']})",
                basis=basis, preconditions=pre,
                check={"type": "deny_expected", "deny_status": DENY_AUTHED, "marker": _marker(op, o.object_id)},
                prediction_if_true=f"{role}の{op.op_id}が200で、対象{otype}のデータ(マーカー)を含む",
                falsification=f"{role}の{op.op_id}が{DENY_AUTHED}のいずれかで拒否される",
                probe=probe, control=control, control_required=True, control_reason=ctl_reason,
                control_check={"type": "allow_expected", "allow_status": [200], "marker": _marker(op, o.object_id)},
                grounded=grounded,
                ungrounded_reason="" if grounded else "仕様にアクセス条件の記載がなく、期待値は推定",
                needed_observations=["対照(所有者の同一操作)の結果"]))
    return out


def _function_authz(model: TargetModel, op: SpecOperation) -> list[Hypothesis]:
    out: list[Hypothesis] = []
    allowed = set(op.access["roles"])
    usable = _usable_accounts(model)
    ctl_role = next((r for r in usable if model.case.accounts[r].privilege in allowed), None)
    for role in usable:
        if model.case.accounts[role].privilege in allowed:
            continue
        control = Experiment(ctl_role, op.op_id) if ctl_role else None
        out.append(Hypothesis(
            hypothesis_id=f"h:function_authz:{op.op_id}:{role}", family="function_authz", op_id=op.op_id, probe_role=role,
            object_id="",
            claim=f"権限のない{role}が、{'/'.join(sorted(allowed))}専用の{op.op_id}を実行できる(仕様{op.access['clause']}: {op.access['text']})",
            basis=[_spec_basis(op)],
            preconditions=[{"id": "p1", "text": f"{role}の権限区分は{model.case.accounts[role].privilege}(案件設定)", "status": "spec"},
                           {"id": "p2", "text": f"{ctl_role}は同じ操作に到達できる(対照で確認)", "status": "unverified",
                            "verified_by": control.exp_id if control else None}],
            check={"type": "deny_expected", "deny_status": DENY_AUTHED, "marker": {"mode": "nonempty_json"}},
            prediction_if_true=f"{role}の{op.op_id}が200でデータを返す", falsification=f"{role}の{op.op_id}が{DENY_AUTHED}で拒否される",
            probe=Experiment(role, op.op_id), control=control, control_required=True,
            control_reason="" if control else "許可された権限のアカウントが無く、対照を実行できない",
            control_check={"type": "allow_expected", "allow_status": [200], "marker": {"mode": "nonempty_json"}}, grounded=True,
            needed_observations=["対照(許可された権限の同一操作)の結果"]))
    return out


def _unauth(model: TargetModel, op: SpecOperation) -> list[Hypothesis]:
    kind = op.access["kind"]
    pp: tuple = ()
    oid = None
    ctl_role = None
    if op.params:
        pname = next(iter(op.params))
        otype = op.params[pname]["object"]
        if otype == "user":
            users = model.known_user_objects()
            if not users:
                return []
            oid, ctl_role = users[0], _actor(model, "user") or _actor(model)
        else:
            objs = model.objects_of(otype)
            if not objs:
                return []
            owned = [o for o in objs if o.owner_user and model.role_of_user(o.owner_user)]
            pick = (owned or objs)[0]
            oid = pick.object_id
            ctl_role = model.role_of_user(pick.owner_user) if pick.owner_user else _actor(model)
        pp = ((pname, oid),)
    elif kind == "role":
        ctl_role = next((r for r in _usable_accounts(model) if model.case.accounts[r].privilege in op.access["roles"]), None)
    else:
        ctl_role = _actor(model, "user") or _actor(model)
    grounded = kind != "unspecified"
    control = Experiment(ctl_role, op.op_id, pp) if ctl_role else None
    marker = _marker(op, oid)
    return [Hypothesis(
        hypothesis_id=f"h:unauth_access:{op.op_id}:{oid or '-'}", family="unauth_access", op_id=op.op_id, probe_role="anonymous",
        object_id=oid or "",
        claim=f"未認証の利用者が{op.op_id}を実行できる(仕様{op.access['clause']}: {op.access['text']})",
        basis=[_spec_basis(op)] if grounded else [{"kind": "assumption", "text": f"{op.op_id}は認証を要すると推定(仕様に記載なし)"}, _spec_basis(op)],
        preconditions=[{"id": "p1", "text": "この操作は公開(認証不要)と仕様に書かれていない", "status": "spec"},
                       {"id": "p2", "text": "認証済みの利用者は同じ操作に到達できる(対照で確認)", "status": "unverified",
                        "verified_by": control.exp_id if control else None}],
        check={"type": "deny_expected", "deny_status": DENY_ANON, "marker": marker},
        prediction_if_true=f"認証なしの{op.op_id}が200でデータを返す", falsification=f"認証なしの{op.op_id}が{DENY_ANON}で拒否される",
        probe=Experiment("anonymous", op.op_id, pp), control=control, control_required=True,
        control_reason="" if control else "認証済みアカウントが無く、対照を実行できない",
        control_check={"type": "allow_expected", "allow_status": [200], "marker": marker}, grounded=grounded,
        ungrounded_reason="" if grounded else "仕様にアクセス条件の記載がなく、期待値は推定",
        needed_observations=["対照(認証済みの同一操作)の結果"])]


def _field_exposure(model: TargetModel, op: SpecOperation) -> list[Hypothesis]:
    kind = op.access["kind"]
    allowed_fields = list(op.returns["fields"])
    if op.params:
        pname = next(iter(op.params))
        otype = op.params[pname]["object"]
        if otype == "user":
            users = model.known_user_objects()
            role = _actor(model, "user") or _actor(model)
            if not role or not users:
                return []
            me = model.identity.get(role, {}).get("user_id")
            target = next((u for u in users if u != me), users[0])        # 他人のプロフィールを読む
            pp = ((pname, target),)
        else:
            objs = [o for o in model.objects_of(otype) if o.owner_user and model.role_of_user(o.owner_user)]
            if not objs:
                return []
            role, pp = model.role_of_user(objs[0].owner_user), ((pname, objs[0].object_id),)   # 所有者が自分の文書を読む
    else:
        role = _actor(model, "admin") if kind == "role" else (_actor(model, "user") or _actor(model))
        pp = ()
    if not role:
        return []
    return [Hypothesis(
        hypothesis_id=f"h:field_exposure:{op.op_id}:{role}", family="field_exposure", op_id=op.op_id, probe_role=role,
        object_id=pp[0][1] if pp else "",
        claim=f"{op.op_id}の応答が、仕様({op.access['clause']})の返却項目{allowed_fields}を超える項目を含む",
        basis=[{"kind": "spec", "clause": op.access["clause"], "op_id": op.op_id, "text": f"返却項目: {allowed_fields}"}],
        preconditions=[{"id": "p1", "text": f"{role}は正当な利用者として{op.op_id}を呼べる", "status": "unverified"}],
        check={"type": "fields_subset", "allowed": allowed_fields},
        prediction_if_true="応答のJSONキーに、仕様に無い項目が含まれる", falsification="応答のJSONキーが全て仕様の返却項目に含まれる",
        probe=Experiment(role, op.op_id, pp), control=None, control_required=False,
        control_reason="同じ応答の項目比較で自己完結する(別の対照は不要)。HTTP成功が前提",
        control_check=None, grounded=True, needed_observations=[])]


def build_list_scope(model: TargetModel, op: SpecOperation, role: str) -> tuple[Hypothesis | None, str]:
    """一覧操作が、呼出し者に見えるはずのない要素を含むか（list_visibility）。規則5型は提案しない型で、LLM提案からだけ作られる。
    戻り値: (仮説, 却下理由)。期待値は仕様の own_list 条項に結び付く（LLMが『根拠あり』と言っても使わない）。"""
    if op.method != "GET" or op.params or op.access["kind"] != "own_list" or not op.returns.get("object"):
        return None, "op_not_list_scope"
    if role not in model.case.accounts:
        return None, "role_unknown"
    if role in _failed_roles(model):
        return None, "role_session_invalid"
    otype = op.returns["object"]
    o = model.case.objects.get(otype, {})
    if not (o.get("owner_field") and o.get("shared_field")):
        return None, "object_schema_lacks_owner_or_shared"
    return Hypothesis(
        hypothesis_id=f"h:list_scope:{op.op_id}:{role}", family="list_scope", op_id=op.op_id, probe_role=role, object_id="",
        claim=f"{op.op_id}が、{role}に見えるはずのない{otype}（所有者でも共有先でもないもの）を一覧に含める(仕様{op.access['clause']}: {op.access['text']})",
        basis=[_spec_basis(op)],
        preconditions=[{"id": "p1", "text": f"{role}の利用者IDを観測している(identity)", "status": "unverified"},
                       {"id": "p2", "text": f"{role}のセッションは有効", "status": "unverified"}],
        check={"type": "list_visibility", "role": role, "object": otype},
        prediction_if_true=f"{role}の{op.op_id}の応答に、{role}が所有者でも共有先でもない{otype}が含まれる",
        falsification=f"{role}の{op.op_id}の応答の全要素が、{role}の所有または{role}への共有",
        probe=Experiment(role, op.op_id), control=None, control_required=False,
        control_reason="応答自身の所有者/共有先の項目との照合で自己完結（別の対照は不要）。HTTP成功と利用者IDの観測が前提",
        control_check=None, grounded=True, needed_observations=[],
        key=("list_scope", op.op_id, role)), ""
