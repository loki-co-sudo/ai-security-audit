"""
core/autonomy/actions.py — 型付きAction・Capability・承認の契約

設計: docs/AUTONOMOUS_PHASE_A_DESIGN.md §3.1 / §11。LLM(Planner)は将来ここで定義した
Action を「提案」するだけで、実行可否は policy_gate.PolicyGate が決定論で判断する。

  - CapabilitySpec: 実行できる診断能力の宣言。`mutating=True` はT3(個別承認)以外に宣言できない
    (登録時に検証)。T0(ローカル)は送信しない。
  - Action: capability + 具体的な引数。引数に秘密値そのものを入れない(認証は参照名のみ)。
  - ApprovalGrant: 特定Action(引数ハッシュ)への一回限りの明示承認。期限付き。LLMや他エージェントは
    発行できず、Runnerの開始引数としてユーザーが渡す。
"""

from __future__ import annotations
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum

from core import redaction
from core.findings import new_id
from core.http_transport import normalize_origin


class SideEffect(str, Enum):
    T0_LOCAL = "T0"              # ローカル解析・LLM推論・レポート。送信しない
    T1_OBSERVE = "T1"            # 許可originへの読取り観測(GET)。副作用なしの保証ではない
    T2_DIFFERENTIAL = "T2"       # 非破壊の差分再観測
    T3_NEEDS_APPROVAL = "T3"     # 状態を変え得る/認証情報の送信など。個別承認が必須


_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
_ARG_TYPES = {"str": str, "int": int, "bool": bool, "list": list, "dict": dict}


@dataclass(frozen=True)
class CapabilitySpec:
    name: str                              # "web.crawl" など
    side_effect: SideEffect
    mutating: bool = False
    # 引数名 -> {"type": "str|int|bool|list|dict", "required": bool}
    args_schema: dict = field(default_factory=dict)
    target_arg: str | None = None          # 送信先URLを持つ引数名。T0以外は必須
    max_requests: int | None = None        # 情報用の上限(Phase Aでは拒否に使わない。設計 §11.3)。None=送信しない
    uses_llm: str | None = None            # "strong" | "fast" | None
    llm_calls: int = 0                     # このcapabilityが呼び得るLLM回数の上限(事前確認に使う)
    enabled: bool = True                   # Falseは登録のみで実行不可(例: web.fuzz_post_points)
    session_scoped: bool = False           # プロセス内のセッション状態を作る(認証など)。再開時は再適用が必要

    def __post_init__(self):
        if not _NAME_RE.match(self.name):
            raise ValueError(f"不正なcapability名です: {self.name!r}")
        if self.mutating and self.side_effect != SideEffect.T3_NEEDS_APPROVAL:
            raise ValueError("mutating=True のcapabilityはT3でのみ宣言できます")
        sends = self.max_requests is not None
        if self.side_effect == SideEffect.T0_LOCAL:
            if sends or self.target_arg:
                raise ValueError("T0(ローカル)のcapabilityは送信先・送信数を持てません")
        elif not self.target_arg:
            raise ValueError("T0以外のcapabilityは target_arg(送信先を持つ引数名)が必須です")
        if self.target_arg and self.target_arg not in self.args_schema:
            raise ValueError("target_arg は args_schema に含まれる必要があります")
        if self.uses_llm not in (None, "strong", "fast"):
            raise ValueError("uses_llm は strong / fast / None のいずれかです")
        if self.llm_calls < 0 or (self.llm_calls > 0 and not self.uses_llm):
            raise ValueError("llm_calls は uses_llm を指定した場合のみ正の値にできます")
        for arg, spec in self.args_schema.items():
            if spec.get("type") not in _ARG_TYPES:
                raise ValueError(f"args_schema[{arg!r}] の type が不正です")
            if arg.lower() in redaction.SENSITIVE_PARAM_NAMES:
                raise ValueError(f"秘密値を直接受ける引数名は使えません(参照名を使う): {arg!r}")

    @property
    def sends(self) -> bool:
        return self.max_requests is not None


class CapabilityRegistry:
    def __init__(self):
        self._specs: dict[str, CapabilitySpec] = {}

    def register(self, spec: CapabilitySpec) -> CapabilitySpec:
        if spec.name in self._specs:
            raise ValueError(f"capabilityが重複しています: {spec.name}")
        self._specs[spec.name] = spec
        return spec

    def get(self, name: str) -> CapabilitySpec | None:
        return self._specs.get(name)

    def names(self) -> list[str]:
        return sorted(self._specs)


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def args_hash(capability: str, args: dict) -> str:
    """承認・監査用の引数ハッシュ(capability名と全引数に結び付く)。"""
    return hashlib.sha256(canonical_json({"capability": capability, "args": args}).encode()).hexdigest()


@dataclass(frozen=True)
class Action:
    action_id: str
    task_id: str
    capability: str
    args: dict
    auth_context: str
    dedupe_key: str


def make_action(spec: CapabilitySpec, task_id: str, args: dict, *, auth_context: str = "anonymous",
                action_id: str | None = None) -> Action:
    """重複キー = hash(capability, 正規化した引数, 認証context, 対象origin)。"""
    origin = ""
    if spec.target_arg and isinstance(args.get(spec.target_arg), str):
        o = normalize_origin(args[spec.target_arg])
        origin = str(o) if o else ""
    key = hashlib.sha256(canonical_json(
        {"c": spec.name, "a": args, "auth": auth_context, "origin": origin}).encode()).hexdigest()
    return Action(action_id=action_id or new_id("act"), task_id=task_id, capability=spec.name,
                  args=dict(args), auth_context=auth_context, dedupe_key=key)


def validate_args(spec: CapabilitySpec, args: dict) -> list[str]:
    """引数がスキーマに適合するか。問題の説明を返す(空なら適合)。秘密値らしい引数名は拒否する。"""
    problems: list[str] = []
    if not isinstance(args, dict):
        return ["引数がdictではありません"]
    for name in args:
        if name not in spec.args_schema:
            problems.append(f"未知の引数: {name}")
        if str(name).lower() in redaction.SENSITIVE_PARAM_NAMES:
            problems.append(f"秘密値を直接渡せません(参照名を使う): {name}")
    for name, rule in spec.args_schema.items():
        if name not in args:
            if rule.get("required", False):
                problems.append(f"必須引数がありません: {name}")
            continue
        py = _ARG_TYPES[rule["type"]]
        v = args[name]
        if not isinstance(v, py) or (py is int and isinstance(v, bool)):
            problems.append(f"引数の型が不正です: {name} は {rule['type']}")
    return problems


@dataclass
class ActionResult:
    status: str                            # "done" | "failed" | "exhausted" | "skipped"
    summary: dict = field(default_factory=dict)   # マスク済みの要約のみ(対象由来の生テキストは入れない)
    evidence_ids: list[str] = field(default_factory=list)
    requests_used: int = 0                 # 実測(transport計数の差)
    llm_usage: dict | str = "unknown"      # 取得不能は0ではなく "unknown"
    outputs: dict = field(default_factory=dict)   # 後続タスク/再開用の出力。**呼び出し側がマスク済みにして渡す**


@dataclass(frozen=True)
class GateDecision:
    verdict: str                           # "allow" | "deny" | "needs_approval"
    reason_codes: tuple[str, ...] = ()
    detail: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


@dataclass(frozen=True)
class ApprovalGrant:
    """特定Action(capability+引数ハッシュ)への一回限りの承認。LLMは発行できない。"""
    grant_id: str
    capability: str
    args_hash: str
    expires_at: float                      # epoch秒。タイムアウトは常にdeny(allowにはならない)
    issued_by: str = "user"


def new_grant(capability: str, args: dict, *, expires_at: float, grant_id: str | None = None) -> ApprovalGrant:
    return ApprovalGrant(grant_id=grant_id or new_id("grant"), capability=capability,
                         args_hash=args_hash(capability, args), expires_at=expires_at)
