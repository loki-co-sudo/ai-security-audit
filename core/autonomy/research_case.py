"""
core/autonomy/research_case.py — 自律調査(Stage 1)の案件設定: 公開仕様＋アカウント＋範囲＋予算だけ

従来のlab_case(仮説・固定テスト・期待値を人間が書く)と違い、ここには**仮説も検査手順も期待値も置けない**。
置けるのは、通常のAPI仕様書に相当する情報(操作・パス・アクセス条件の記述・返却項目)と、実行を許可する範囲だけ。
アクセス条件(`access.kind`)は閉じた語彙で、調査側はこの条項(clause)を『拒否されるべき』という期待値の
独立した根拠として引用する。正解ラベル・秘密値・解法に見えるキーは拒否する。
設計・位置付け: docs/AUTONOMOUS_DISCOVERY_STAGE1.md
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field

from core.autonomy.lab_case import LabCaseError, _need, _scan_forbidden

SCHEMA = "ai-security-audit-blind-case"
SCHEMA_VERSION = "1"

_ID = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_PATH = re.compile(r"^/[A-Za-z0-9_\-./{}]*$")
_PARAM = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
_REF = re.compile(r"^cred:[a-z][a-z0-9_]{0,31}$")
_CLAUSE = re.compile(r"^S-[0-9]{1,3}$")
_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
_SIDE = {"T1", "T2"}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
ACCESS_KINDS = ("public", "authenticated", "own_list", "owner_or_shared", "owner_only", "role", "unspecified")


@dataclass(frozen=True)
class SpecOperation:
    op_id: str
    method: str
    path: str
    params: dict                    # パラメータ名 -> {"object": 型名}
    access: dict                    # {"clause","kind","text",["object","param","roles"]}
    returns: dict                   # {"object","list","fields","object_key","identity"}

    def path_for(self, values: dict) -> str:
        out = self.path
        for name, v in values.items():
            out = out.replace("{" + name + "}", str(v))
        return out


@dataclass(frozen=True)
class Account:
    name: str
    ref: str
    privilege: str


@dataclass(frozen=True)
class BlindCase:
    case_id: str
    split: str
    title: str
    target_ref: str
    allowed_hosts: tuple
    excluded_paths: tuple
    side_effects: tuple
    accounts: dict                  # name -> Account
    objects: dict                   # 型名 -> {"id_field","fields",["owner_field","shared_field"]}
    operations: dict                # op_id -> SpecOperation
    budget: dict
    stop_conditions: dict
    spec_title: str = ""
    _raw: dict = field(default_factory=dict, compare=False, repr=False)

    def public_dict(self) -> dict:
        return json.loads(json.dumps(self._raw, ensure_ascii=False))


def parse_blind_case(doc: dict) -> BlindCase:
    _need(isinstance(doc, dict), "案件設定はオブジェクトです")
    _need(doc.get("schema") == SCHEMA and doc.get("schema_version") == SCHEMA_VERSION, "schemaが不正です")
    _scan_forbidden(doc)
    for k in ("hypotheses", "tests", "expect", "probes", "controls"):
        _need(k not in doc, f"自律調査の案件設定に{k}は置けません(仮説・検査手順・期待値は調査側が作る)")
    cid = doc.get("case_id")
    _need(isinstance(cid, str) and _ID.match(cid.replace("-", "_")), "case_idが不正です")
    _need(doc.get("split") in ("dev", "holdout"), "splitはdev/holdoutです")
    scope = doc.get("scope") or {}
    hosts = tuple(scope.get("allowed_hosts") or ())
    _need(hosts and all(h in ("127.0.0.1", "localhost", "::1") for h in hosts),
          "allowed_hostsはローカル(127.0.0.1/localhost)のみ指定できます")
    excl = tuple(scope.get("excluded_paths") or ())
    _need(all(isinstance(p, str) and _PATH.match(p) for p in excl), "excluded_pathsは'/'で始まるパスです")
    side = tuple(doc.get("side_effects_allowed") or ())
    _need(side and set(side) <= _SIDE, "side_effects_allowedはT1/T2のみ(T3は自律調査に公開しない)")
    accounts: dict[str, Account] = {}
    for name, a in (doc.get("accounts") or {}).items():
        _need(_ID.match(name) and isinstance(a, dict), f"アカウント名が不正です: {name}")
        _need(isinstance(a.get("ref"), str) and _REF.match(a["ref"]), f"{name}: 認証情報は`cred:<名前>`の参照名で指定します")
        _need(a.get("privilege") in ("user", "admin"), f"{name}: privilegeはuser/adminです")
        accounts[name] = Account(name, a["ref"], a["privilege"])
    _need(accounts, "アカウントが必要です")
    spec = doc.get("spec") or {}
    objects = spec.get("objects") or {}
    for oname, o in objects.items():
        _need(_ID.match(oname) and isinstance(o, dict) and o.get("id_field") in (o.get("fields") or []),
              f"objects.{oname}: id_fieldはfieldsに含めます")
        _need(all(isinstance(f, str) and _FIELD.match(f) for f in o["fields"]), f"objects.{oname}: field名が不正です")
    ops: dict[str, SpecOperation] = {}
    clauses: set[str] = set()
    for raw in spec.get("operations") or []:
        oid = raw.get("op_id")
        _need(isinstance(oid, str) and _ID.match(oid) and oid not in ops, f"op_idが不正または重複です: {oid}")
        method, path = raw.get("method"), raw.get("path")
        _need(method in METHODS, f"{oid}: methodが不正です")
        _need(isinstance(path, str) and _PATH.match(path), f"{oid}: pathが不正です(相対パスのみ)")
        params = raw.get("params") or {}
        in_path = set(re.findall(r"\{([a-z][a-z0-9_]*)\}", path))
        _need(in_path == set(params), f"{oid}: pathの{{}}とparamsが一致しません")
        _need(len(params) <= 1, f"{oid}: パスパラメータは1操作に1つまでです（入れ子のリソースは未対応。対象ごとに複数の経路が要る設計は、"
                                "仮説が検証器で却下され、静かに検査範囲が減るため案件の読込時に拒否します）")
        for pn, pd in params.items():
            _need(_PARAM.match(pn) and pd.get("object") in objects, f"{oid}: paramsの型がobjectsにありません: {pn}")
        acc = raw.get("access") or {}
        _need(acc.get("kind") in ACCESS_KINDS, f"{oid}: access.kindが語彙外です: {acc.get('kind')}")
        _need(isinstance(acc.get("clause"), str) and _CLAUSE.match(acc["clause"]) and acc["clause"] not in clauses,
              f"{oid}: access.clauseが不正または重複です")
        clauses.add(acc["clause"])
        _need(isinstance(acc.get("text"), str) and acc["text"], f"{oid}: access.textが必要です")
        if acc["kind"] in ("owner_or_shared", "owner_only"):
            _need(acc.get("param") in params and acc.get("object") in objects, f"{oid}: 対象オブジェクトとparamが必要です")
        if acc["kind"] == "role":
            _need(acc.get("roles") and set(acc["roles"]) <= {"user", "admin"}, f"{oid}: rolesが不正です")
        rets = raw.get("returns") or {}
        if rets.get("object"):
            _need(rets["object"] in objects, f"{oid}: returns.objectがobjectsにありません")
        if acc["kind"] == "own_list":
            vt = acc.get("visible_to")
            if vt is not None:                    # 一覧の閲覧条件（任意。省略は『共有先を持つ型では条件が仕様に明記されていない』を意味する）
                _need(vt in ("owner", "owner_or_shared"), f"{oid}: access.visible_to は owner / owner_or_shared のいずれかです")
                otype = rets.get("object")
                _need(otype in objects and objects[otype].get("owner_field"), f"{oid}: visible_to には returns.object の型に owner_field が要ります")
                if vt == "owner_or_shared":
                    _need(objects[otype].get("shared_field"), f"{oid}: owner_or_shared には returns.object の型に shared_field が要ります")
        else:
            _need("visible_to" not in acc, f"{oid}: access.visible_to は own_list の操作だけに指定できます")
        if "fields" in rets:
            _need(all(isinstance(f, str) and _FIELD.match(f) for f in rets["fields"]), f"{oid}: returns.fieldsが不正です")
        ops[oid] = SpecOperation(oid, method, path, dict(params), dict(acc), dict(rets))
    _need(ops, "operationsが必要です")
    _need(any(o.method == "GET" and not o.params and o.returns.get("identity") for o in ops.values()),
          "利用者自身のIDを返すGET操作（パラメータなし・returns.identity: true）が1つ以上必要です（ロールと利用者IDを観測できないと仮説を作れません）")
    b = doc.get("budget") or {}
    for k in ("max_requests", "max_seconds"):
        _need(isinstance(b.get(k), (int, float)) and b[k] >= 0, f"budget.{k}が必要です")
    budget = {"max_requests": int(b["max_requests"]), "max_seconds": float(b["max_seconds"]),
              "max_llm_calls": int(b.get("max_llm_calls", 0)), "max_llm_input_chars": int(b.get("max_llm_input_chars", 8000))}
    return BlindCase(case_id=cid, split=doc["split"], title=str(doc.get("title", "")), target_ref=str(doc.get("target_ref", "")),
                     allowed_hosts=hosts, excluded_paths=excl, side_effects=side, accounts=accounts, objects=dict(objects),
                     operations=ops, budget=budget, stop_conditions=dict(doc.get("stop_conditions") or {}),
                     spec_title=str(spec.get("title", "")), _raw=doc)


def load_blind_case(path: str) -> BlindCase:
    with open(path, encoding="utf-8") as f:
        return parse_blind_case(json.load(f))
