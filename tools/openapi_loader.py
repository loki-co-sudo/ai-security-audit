"""P4.1: ローカルのOpenAPI 3.0/3.1 JSONを読み、検査候補(読み取り用GET+query parameter)へ変換する。

通信は一切しない(ファイル読み取りのみ)。`servers` のURLもoperation一覧も送信許可ではない: 注入点の送信先は呼び出し側が
与える対象URL(同一origin・許可対象の検査はWebFuzzer/Policy Gate側)で、本モジュールはserversを参照しない。
自動探索の対象にしないもの: JSON body、path parameterの生成、GET以外(POST等)、path parameterを含むpath。
securitySchemesは「この操作に認証が要る」という表示のためだけに読み、認証値は扱わない(認証は--auth-fileの役割別承認)。
GETだけで非破壊とは限らないため、選択はユーザーが明示したoperationだけに限る。YAMLは非対応(明示エラー)。
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

MAX_BYTES = 2 * 1024 * 1024
MAX_REF_DEPTH = 16
MAX_OPERATIONS = 500
MAX_PARAMS_PER_OPERATION = 50
_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_PATH_PARAM = re.compile(r"\{[^}]+\}")


class OpenApiError(Exception):
    pass


@dataclass
class QueryParam:
    name: str
    required: bool
    type: str
    sample: str


@dataclass
class Operation:
    operation_id: str          # operationIdが無い場合は "GET /path"
    method: str
    path: str
    summary: str = ""
    deprecated: bool = False
    query_params: list[QueryParam] = field(default_factory=list)
    selectable: bool = False
    reason: str = ""           # selectableでない理由(自動探索の対象外)
    auth: list = field(default_factory=list)   # 要求される認証(scheme名・種類のみ。値は持たない)

    def to_dict(self) -> dict:
        return {"operation_id": self.operation_id, "method": self.method, "path": self.path,
                "summary": self.summary, "deprecated": self.deprecated, "selectable": self.selectable,
                "reason": self.reason, "auth": self.auth, "query_params": [vars(q) for q in self.query_params]}


class _Resolver:
    def __init__(self, doc: dict):
        self.doc = doc

    def deref(self, node, stack: tuple = ()):
        """ローカル$ref(#/...)を深さ・循環制限付きで解決する。外部$refは明示エラー。"""
        seen = list(stack)
        while isinstance(node, dict) and "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                raise OpenApiError("外部または不正な$refは非対応です(ローカルの#/...のみ)")
            if ref in seen:
                raise OpenApiError(f"循環する$refです: {ref}")
            if len(seen) >= MAX_REF_DEPTH:
                raise OpenApiError("$refの深さが上限を超えました")
            seen.append(ref)
            cur = self.doc
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(cur, dict) or part not in cur:
                    raise OpenApiError(f"$refの参照先が存在しません: {ref}")
                cur = cur[part]
            node = cur
        return node


def _load_yaml(raw: bytes) -> dict:
    """JSONで読めなかった場合のYAML。safe_loadのみ・alias/anchorは拒否(展開による膨張を防ぐ)・ローカル文字列のみ。"""
    try:
        import yaml
    except ImportError:
        raise OpenApiError("JSONとして読めません(YAMLにはPyYAMLが必要です)")
    try:
        text = raw.decode("utf-8")
        if any(isinstance(e, yaml.AliasEvent) for e in yaml.parse(text, Loader=yaml.SafeLoader)):
            raise OpenApiError("YAMLのalias(*)は使えません。展開済みのYAMLかJSONにしてください")
        doc = yaml.load(text, Loader=yaml.SafeLoader)
    except OpenApiError:
        raise
    except (yaml.YAMLError, UnicodeDecodeError, RecursionError):
        raise OpenApiError("JSONまたはYAMLとして読めません")
    return doc


def load_openapi(path: str) -> dict:
    """ローカルのJSONを読み、OpenAPI 3.0/3.1であることを確認して返す(リンク先は読まない)。"""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError as e:
        raise OpenApiError(f"ファイルを読めません: {e.strerror or type(e).__name__}")
    if len(raw) > MAX_BYTES:
        raise OpenApiError("OpenAPIファイルが大きすぎます")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        doc = _load_yaml(raw)
    if not isinstance(doc, dict) or not str(doc.get("openapi", "")).startswith(("3.0", "3.1")):
        raise OpenApiError("OpenAPI 3.0/3.1のドキュメントではありません")
    if not isinstance(doc.get("paths"), dict):
        raise OpenApiError("pathsがありません")
    return doc


_FORMAT_SAMPLES = {"uuid": "00000000-0000-4000-8000-000000000000", "date": "2026-01-01",
                   "date-time": "2026-01-01T00:00:00Z", "email": "test@example.com", "uri": "http://example.com/"}


def _first_example(res: _Resolver, holder: dict):
    """example → examples(3.1の配列 / 3.0のmap。値はvalue) の順で最初の値を返す。無ければ(False, None)。"""
    if "example" in holder:
        return True, holder["example"]
    ex = holder.get("examples")
    if isinstance(ex, list) and ex:
        return True, ex[0]
    if isinstance(ex, dict) and ex:
        first = res.deref(next(iter(ex.values())))
        if isinstance(first, dict) and "value" in first:
            return True, first["value"]
    return False, None


def _type_of(schema: dict) -> str:
    t = schema.get("type", "string")
    if isinstance(t, list):                       # 3.1: ["string", "null"]
        t = next((x for x in t if x != "null"), "string")
    return str(t)


def _flatten(res: _Resolver, schema, depth: int = 0) -> dict:
    """allOfは統合、oneOf/anyOfは先頭の分岐を採る(サンプル値を作るためだけの近似)。"""
    schema = res.deref(schema)
    if not isinstance(schema, dict) or depth > 8:
        return {}
    out = {k: v for k, v in schema.items() if k not in ("allOf", "oneOf", "anyOf")}
    for key in ("allOf",):
        for sub in schema.get(key) or []:
            for k, v in _flatten(res, sub, depth + 1).items():
                out.setdefault(k, v)
    for key in ("oneOf", "anyOf"):
        branches = schema.get(key)
        if isinstance(branches, list) and branches:
            for k, v in _flatten(res, branches[0], depth + 1).items():
                out.setdefault(k, v)
    return out


def _sample(res: _Resolver, param: dict, schema, depth: int = 0) -> tuple[str, str]:
    """(型, サンプル値)。parameter側のexampleを優先し、schemaのexample/default/enum/format/最小値の順に使う。"""
    for holder in (param, _flatten(res, schema)):
        ok, value = _first_example(res, holder)
        if ok and not isinstance(value, (dict, list)):
            return _type_of(_flatten(res, schema)), str(value)
    flat = _flatten(res, schema)
    ptype = _type_of(flat)
    if "default" in flat and not isinstance(flat["default"], (dict, list)):
        return ptype, str(flat["default"])
    if isinstance(flat.get("enum"), list) and flat["enum"]:
        return ptype, str(flat["enum"][0])
    if ptype == "array" and depth < 4:
        return ptype, _sample(res, {}, flat.get("items") or {}, depth + 1)[1]     # 要素1個だけのqueryにする
    if ptype in ("integer", "number"):
        lo = flat.get("minimum")
        return ptype, str(lo) if isinstance(lo, (int, float)) and not isinstance(lo, bool) and lo > 1 else "1"
    if ptype == "boolean":
        return ptype, "true"
    return ptype, _FORMAT_SAMPLES.get(str(flat.get("format")), "test")


def _auth_requirements(res: _Resolver, op: dict) -> list[dict]:
    """操作に適用されるsecurity要件をscheme名・種類だけで返す。op.securityが空配列なら認証不要(globalを打ち消す)。"""
    req = op["security"] if "security" in op else res.doc.get("security")
    if not isinstance(req, list):
        return []
    schemes = ((res.doc.get("components") or {}).get("securitySchemes") or {})
    out, seen = [], set()
    for alt in req:
        for name in (alt.keys() if isinstance(alt, dict) else []):
            if not isinstance(name, str) or name in seen:
                continue
            seen.add(name)
            try:
                sch = res.deref(schemes.get(name)) if name in schemes else None
            except OpenApiError:
                sch = None
            sch = sch if isinstance(sch, dict) else {}
            kind = str(sch.get("type", "unknown"))[:30]
            detail = str(sch.get("scheme") or sch.get("in") or "")[:30]
            out.append({"scheme": name[:60], "type": kind, "detail": detail})
    return out


def list_operations(doc: dict) -> list[Operation]:
    res = _Resolver(doc)
    ops: list[Operation] = []
    for path, item in doc["paths"].items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise OpenApiError(f"pathが不正です: {path!r}")
        item = res.deref(item)
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            if method not in item:
                continue
            if len(ops) >= MAX_OPERATIONS:
                raise OpenApiError(f"operation数が上限({MAX_OPERATIONS})を超えました")
            op = res.deref(item[method])
            if not isinstance(op, dict):
                continue
            ops.append(_to_operation(res, path, method, item.get("parameters"), op))
    ids = [o.operation_id for o in ops]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise OpenApiError(f"operationIdが重複しています: {', '.join(dup)}")
    return ops


def _to_operation(res: _Resolver, path: str, method: str, shared, op: dict) -> Operation:
    raw_params = list(shared or []) + list(op.get("parameters") or [])
    if len(raw_params) > MAX_PARAMS_PER_OPERATION:
        raise OpenApiError(f"parameter数が上限({MAX_PARAMS_PER_OPERATION})を超えました: {method.upper()} {path}")
    merged: dict[tuple[str, str], dict] = {}        # operation側が同名(in,name)のpath-item側を上書きする
    for p in raw_params:
        p = res.deref(p)
        if isinstance(p, dict) and isinstance(p.get("name"), str) and p.get("in") in ("query", "path", "header", "cookie"):
            merged[(p["in"], p["name"])] = p
    query = []
    for (loc, name), p in merged.items():
        if loc != "query":
            continue
        ptype, sample = _sample(res, p, p.get("schema") or {})
        query.append(QueryParam(name=name, required=bool(p.get("required")), type=ptype, sample=sample))
    oid = op.get("operationId") if isinstance(op.get("operationId"), str) and op["operationId"] else f"{method.upper()} {path}"
    reason = ""
    if method != "get":
        reason = "GET以外は自動探索の対象外"
    elif _PATH_PARAM.search(path) or any(loc == "path" for loc, _ in merged):
        reason = "path parameterを含む(値の生成は行わない)"
    elif op.get("requestBody"):
        reason = "リクエストbodyを持つ"
    elif not query:
        reason = "query parameterが無い"
    return Operation(operation_id=oid, method=method.upper(), path=path, summary=str(op.get("summary", ""))[:200],
                     deprecated=bool(op.get("deprecated")), query_params=query, selectable=not reason, reason=reason,
                     auth=_auth_requirements(res, op))


def select_points(ops: list[Operation], selected: list[str], base_url: str, exclude: list[str] | None = None
                  ) -> list[dict]:
    """明示選択されたoperationだけを、WebFuzzerの注入点形式(GET・query)へ変換する。

    selected は operation_id。exclude(operation_id)は選択より優先。存在しない/選択不可のidは黙って無視せずエラー。
    送信先は base_url(呼び出し側が与えた対象)で、OpenAPIのserversは使わない。
    """
    if not selected:
        raise OpenApiError("検査するoperationを明示してください(全operationの自動選択はしません)")
    by_id = {o.operation_id: o for o in ops}
    excluded = set(exclude or [])
    for oid in [*selected, *excluded]:
        if oid not in by_id:
            raise OpenApiError(f"存在しないoperationです: {oid}")
    u = urlsplit(base_url if "://" in base_url else "http://" + base_url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise OpenApiError("対象URLが不正です")
    origin = f"{u.scheme}://{u.netloc}"
    points, seen = [], set()
    for oid in selected:
        if oid in excluded or oid in seen:
            continue
        seen.add(oid)
        op = by_id[oid]
        if not op.selectable:
            raise OpenApiError(f"選択できないoperationです: {oid} ({op.reason})")
        fields = {q.name: q.sample for q in op.query_params}
        for q in op.query_params:
            points.append({"url": origin + op.path, "method": "GET", "where": "query", "param": q.name,
                           "fields": dict(fields), "source": f"openapi:{oid}"})
    return points
