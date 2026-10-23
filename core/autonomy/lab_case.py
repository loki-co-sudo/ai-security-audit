"""
core/autonomy/lab_case.py — ローカル模擬診断案件の設定契約(公開側。正解ラベルは含まない)

設計: docs/LOCAL_LAB_EVAL.md。案件設定は「何を・どの範囲で・どの固定テスト操作で・どの予算で」診断してよいかの
正本で、確定後に自動で拡張しない(設定に無い操作は許可しない)。次を満たさない設定は読み込み時に拒否する。
  - 固定テスト操作はGETのみ・パスは"/"始まりの相対パス(絶対URL・userinfo・`..`不可)。外部originへ送れない。
  - 認証情報の秘密値は持たない。アカウントは参照名(`cred:<name>`)だけ。
  - 正解ラベル(脆弱か否か)に相当するキーを持たない(評価専用の情報は、診断ワークフローが参照しない別ディレクトリ側にある)。
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass, field

SCHEMA = "ai-security-audit-lab-case"
SCHEMA_VERSION = "1"

_ID_RE = re.compile(r"^[a-z][a-z0-9_\-]{1,63}$")
_REF_RE = re.compile(r"^cred:[a-z][a-z0-9_]{0,31}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./~%]*$")
_PARAM_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,40}$")
_CAP_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_SIDE = {"T1", "T2"}
# 評価専用の情報が案件設定へ紛れ込むのを防ぐ(正解ラベル・解法)。キー名で拒否する。
_FORBIDDEN_KEYS = frozenset({"expected_vulnerable", "is_vulnerable", "ground_truth", "truth", "solution",
                             "answer", "flaw", "decoy", "is_decoy", "secret", "password", "token", "api_key"})
DEFAULT_INCONCLUSIVE = (401, 408, 429, 502, 503, 504)


class LabCaseError(ValueError):
    pass


@dataclass(frozen=True)
class LabTest:
    test_id: str
    feature: str
    hypothesis: str
    role: str                      # "anonymous" または accounts のキー
    path: str
    params: tuple                  # ((name, value), ...) 順序固定
    cost: int                      # 想定リクエスト数(予算の事前確認用。実測は別に数える)
    info_value: float              # 情報価値の事前評価(0〜1)。公開設定であり正解ではない
    purpose: str
    kind: str                      # "probe" | "control"(環境の健全性確認) | "navigation"(後続テストを選択可能にする観測。裏付けには数えない)
    expect: dict                   # status(int|list) / body_contains / body_not_contains / header_*
    inconclusive_statuses: tuple
    unlocked_by: dict | None       # {"test_id":..., "body_contains":...}: 先行テストの観測で選択可能になる
    corroborates: bool             # 所見を裏付ける追加テスト(所見が出た後で価値が上がる)

    def query(self) -> str:
        return "&".join(f"{k}={v}" for k, v in self.params)    # 表示用(送信にはparamsをそのまま渡す)


@dataclass(frozen=True)
class LabHypothesis:
    hypothesis_id: str
    feature: str
    rule_id: str
    title: str
    prior_value: float
    severity_hint: str
    remediation: str
    provides: tuple = ()           # この不備が事実なら攻撃者が得る能力の語(連鎖規則の入力。正解ではなく仮説に付く静的な注釈)


@dataclass
class LabCase:
    case_id: str
    split: str                     # "dev" | "holdout"
    title: str
    target_ref: str
    allowed_hosts: tuple
    excluded_paths: tuple
    side_effects: frozenset
    accounts: dict                 # role -> cred_ref
    features: dict                 # feature_id -> {title, description}
    hypotheses: dict               # hypothesis_id -> LabHypothesis
    tests: dict                    # test_id -> LabTest (宣言順を保つ)
    normal_behavior: tuple
    budget: dict
    stop_conditions: dict
    evidence: dict
    notes: tuple = field(default_factory=tuple)
    out_of_scope: tuple = field(default_factory=tuple)   # 固定テスト操作では検査できない領域(未検査として報告する)

    def test_order(self) -> list[str]:
        return list(self.tests)

    def public_dict(self) -> dict:
        return json.loads(json.dumps(self._raw, ensure_ascii=False))

    _raw: dict = field(default_factory=dict, repr=False)


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise LabCaseError(msg)


def _scan_forbidden(obj, where: str = "") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _need(str(k).lower() not in _FORBIDDEN_KEYS, f"案件設定に評価専用/秘密のキーは置けません: {where}{k}")
            _scan_forbidden(v, f"{where}{k}.")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_forbidden(v, f"{where}{i}.")


def _num01(v, name: str) -> float:
    _need(isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1, f"{name}は0〜1の数値です")
    return float(v)


def _caps(v, hid: str) -> tuple:
    v = v or []
    _need(isinstance(v, list) and all(isinstance(x, str) and _CAP_RE.match(x) for x in v), f"{hid}: providesは能力語のリストです")
    return tuple(v)


def parse_case(doc: dict) -> LabCase:
    _need(isinstance(doc, dict), "案件設定はオブジェクトです")
    _need(doc.get("schema") == SCHEMA and doc.get("schema_version") == SCHEMA_VERSION, "schemaが不正です")
    _scan_forbidden(doc)
    cid = doc.get("case_id")
    _need(isinstance(cid, str) and _ID_RE.match(cid), "case_idが不正です")
    split = doc.get("split", "dev")
    _need(split in ("dev", "holdout"), "splitはdev/holdoutです")

    scope = doc.get("scope") or {}
    hosts = tuple(scope.get("allowed_hosts") or ())
    _need(hosts and all(isinstance(h, str) and h in ("127.0.0.1", "localhost", "::1") for h in hosts),
          "allowed_hostsはローカル(127.0.0.1/localhost)のみ指定できます")
    excl = tuple(scope.get("excluded_paths") or ())
    _need(all(isinstance(p, str) and _PATH_RE.match(p) for p in excl), "excluded_pathsの形式が不正です")

    side = frozenset(doc.get("side_effects_allowed") or ())
    _need(side and side <= _SIDE, "side_effects_allowedはT1/T2のみです(状態を変える操作は対象外)")

    accounts = {"anonymous": ""}
    for role, ref in (doc.get("accounts") or {}).items():
        _need(isinstance(role, str) and _ID_RE.match(role.replace("_", "-")), f"アカウント名が不正です: {role}")
        _need(role != "anonymous", "anonymousは予約名です")
        _need(isinstance(ref, str) and _REF_RE.match(ref), f"{role}: 認証情報は`cred:<名前>`の参照名で指定します")
        accounts[role] = ref

    feats = {}
    for f in doc.get("features") or []:
        _need(isinstance(f.get("feature_id"), str) and _ID_RE.match(f["feature_id"]), "feature_idが不正です")
        feats[f["feature_id"]] = {"title": str(f.get("title", "")), "description": str(f.get("description", ""))}
    _need(feats, "featuresが空です")

    hyps: dict[str, LabHypothesis] = {}
    for h in doc.get("hypotheses") or []:
        hid = h.get("hypothesis_id")
        _need(isinstance(hid, str) and _ID_RE.match(hid) and hid not in hyps, f"hypothesis_idが不正/重複: {hid}")
        _need(h.get("feature") in feats, f"{hid}: featureが未定義です")
        _need(h.get("severity_hint") in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), f"{hid}: severity_hintが不正です")
        hyps[hid] = LabHypothesis(hid, h["feature"], str(h.get("rule_id", "")), str(h.get("title", "")),
                                  _num01(h.get("prior_value", 0.5), f"{hid}.prior_value"),
                                  h["severity_hint"], str(h.get("remediation", "")),
                                  _caps(h.get("provides"), hid))
    _need(hyps, "hypothesesが空です")

    tests: dict[str, LabTest] = {}
    for t in doc.get("tests") or []:
        tid = t.get("test_id")
        _need(isinstance(tid, str) and _ID_RE.match(tid) and tid not in tests, f"test_idが不正/重複: {tid}")
        _need(t.get("method", "GET") == "GET", f"{tid}: 固定テスト操作はGETのみです")
        path = t.get("path")
        _need(isinstance(path, str) and _PATH_RE.match(path) and ".." not in path and "//" not in path,
              f"{tid}: pathは相対パス(/始まり)で指定します")
        _need(not any(path == e or path.startswith(e.rstrip("/") + "/") for e in excl), f"{tid}: 除外範囲のpathです")
        params = t.get("params") or {}
        _need(isinstance(params, dict) and all(_PARAM_RE.match(str(k)) and isinstance(v, (str, int))
                                               for k, v in params.items()), f"{tid}: paramsが不正です")
        role = t.get("role", "anonymous")
        _need(role in accounts, f"{tid}: 未定義のroleです: {role}")
        _need(role == "anonymous" or "T2" in side, f"{tid}: 認証付き操作にはT2の許可が必要です")
        _need(t.get("feature") in feats and t.get("hypothesis") in hyps, f"{tid}: feature/hypothesisが未定義です")
        cost = t.get("cost", 1)
        _need(isinstance(cost, int) and not isinstance(cost, bool) and 1 <= cost <= 5, f"{tid}: costは1〜5の整数です")
        exp = t.get("expect") or {}
        _need(isinstance(exp, dict) and exp, f"{tid}: expect(期待される正常動作)が必要です")
        _need(set(exp) <= {"status", "body_contains", "body_not_contains", "header_absent", "header_contains"},
              f"{tid}: expectのキーが不正です")
        inc = tuple(t.get("inconclusive_statuses", DEFAULT_INCONCLUSIVE))
        unl = t.get("unlocked_by")
        if unl is not None:
            _need(isinstance(unl, dict) and set(unl) == {"test_id", "body_contains"}, f"{tid}: unlocked_byが不正です")
        kind = t.get("kind", "probe")
        _need(kind in ("probe", "control", "navigation"), f"{tid}: kindはprobe/control/navigationです")
        tests[tid] = LabTest(tid, t["feature"], t["hypothesis"], role, path,
                             tuple((str(k), str(v)) for k, v in params.items()), cost,
                             _num01(t.get("info_value", 0.5), f"{tid}.info_value"), str(t.get("purpose", "")),
                             kind, dict(exp), inc, dict(unl) if unl else None, bool(t.get("corroborates", False)))
    _need(tests, "testsが空です")
    for t in tests.values():
        if t.unlocked_by:
            _need(t.unlocked_by["test_id"] in tests and t.unlocked_by["test_id"] != t.test_id,
                  f"{t.test_id}: unlocked_byの参照先がありません")
    for hid in hyps:
        _need(any(t.hypothesis == hid and t.kind == "probe" for t in tests.values()),
              f"{hid}: probeが1件もありません(検査不能な仮説は設定に置かない)")

    b = doc.get("budget") or {}
    _need(isinstance(b.get("max_requests"), int) and 1 <= b["max_requests"] <= 200, "budget.max_requestsが不正です")
    _need(isinstance(b.get("max_seconds"), (int, float)) and 1 <= b["max_seconds"] <= 3600, "budget.max_secondsが不正です")
    _need(isinstance(b.get("max_llm_calls"), int) and 0 <= b["max_llm_calls"] <= 50, "budget.max_llm_callsが不正です")
    _need(isinstance(b.get("max_llm_input_chars", 8000), int), "budget.max_llm_input_charsが不正です")
    for o in doc.get("out_of_scope") or []:
        _need(isinstance(o, dict) and o.get("feature") in feats and o.get("reason"), "out_of_scopeの形式が不正です")
    ev = doc.get("evidence") or {}
    _need(isinstance(ev.get("save", True), bool), "evidence.saveはboolです")
    return LabCase(cid, split, str(doc.get("title", cid)), str(doc.get("target_ref", "")), hosts, excl, side,
                   accounts, feats, hyps, tests, tuple(doc.get("normal_behavior") or ()), dict(b),
                   dict(doc.get("stop_conditions") or {}), dict(ev), tuple(doc.get("notes") or ()),
                   tuple(dict(o) for o in (doc.get("out_of_scope") or [])), _raw=json.loads(json.dumps(doc)))


def load_case(path: str) -> LabCase:
    with open(path, encoding="utf-8") as f:
        return parse_case(json.load(f))
