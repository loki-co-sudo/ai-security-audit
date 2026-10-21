"""案件(engagement)設定の検証。現時点ではIDORの期待権限表のみ(P3.1の一部)。秘密値は含めない。"""
from __future__ import annotations

_ACCESS = ("allow", "deny")
_KEYS = {"path", "param", "value", "a", "b"}


class EngagementError(ValueError):
    pass


def parse_idor_expectations(rows) -> list[dict]:
    """期待権限表 [{"path": "/account", "param": "id", "value": "1", "a": "allow", "b": "deny"}] を検証して返す。

    path はURLのパス部のみ(クエリ・origin・ワイルドカードは不可)、value は省略可(省略時は同path・paramの全値)。
    a/b は セッションA/Bの期待権限(allow|deny)。同じ(path,param,value)の重複は曖昧なため拒否する。
    """
    if rows is None:
        return []
    if not isinstance(rows, list):
        raise EngagementError("idor_expectationsは配列で指定してください")
    out, seen = [], set()
    for i, r in enumerate(rows):
        if not isinstance(r, dict) or set(r) - _KEYS or not {"path", "param", "a", "b"} <= set(r):
            raise EngagementError(f"idor_expectations[{i}]の形式が不正です(path/param/a/bが必須)")
        path, param = r["path"], r["param"]
        if not (isinstance(path, str) and path.startswith("/") and not any(c in path for c in "?#*") and "://" not in path):
            raise EngagementError(f"idor_expectations[{i}].pathはクエリ・originなしのパス(例: /account)で指定してください")
        if not (isinstance(param, str) and param):
            raise EngagementError(f"idor_expectations[{i}].paramが不正です")
        value = r.get("value")
        if value is not None and not isinstance(value, str):
            raise EngagementError(f"idor_expectations[{i}].valueは文字列で指定してください")
        for k in ("a", "b"):
            if r[k] not in _ACCESS:
                raise EngagementError(f"idor_expectations[{i}].{k}はallowまたはdenyです")
        key = (path, param, value)
        if key in seen:
            raise EngagementError(f"idor_expectations[{i}]が重複しています: {path} {param}")
        seen.add(key)
        out.append({"path": path, "param": param, "value": value, "a": r["a"], "b": r["b"]})
    return out
