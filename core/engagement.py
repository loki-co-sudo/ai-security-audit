"""案件(engagement)設定の検証。現時点ではIDORの期待権限表のみ(P3.1の一部)。秘密値は含めない。"""
from __future__ import annotations

import re

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


def parse_expectation_lines(text: str) -> list[dict]:
    """GUI入力用の1行1ルール形式を期待権限表へ変換して検証する(行ごとにparse_idor_expectationsと同じ検証)。

    形式: `PATH PARAM [VALUE] a=allow|deny b=allow|deny`(空行と`#`始まりの行は無視)。例: `/account id 1 a=allow b=deny`
    エラーは行番号つきのEngagementError。秘密値を入れる欄ではない(path/param/期待権限のみ)。
    """
    out, seen = [], set()
    for no, raw in enumerate(str(text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pos, opts = [], {}
        for tok in line.split():
            if tok[:2] in ("a=", "b="):
                if tok[0] in opts:
                    raise EngagementError(f"{no}行目: {tok[0]}=... が複数あります")
                opts[tok[0]] = tok[2:]
            else:
                pos.append(tok)
        if len(pos) not in (2, 3) or set(opts) != {"a", "b"}:
            raise EngagementError(f"{no}行目: `PATH PARAM [VALUE] a=allow|deny b=allow|deny` の形式で指定してください")
        row = {"path": pos[0], "param": pos[1], "a": opts["a"], "b": opts["b"]}
        if len(pos) == 3:
            row["value"] = pos[2]
        try:
            parsed = parse_idor_expectations([row])[0]
        except EngagementError as e:
            raise EngagementError(f"{no}行目: " + re.sub(r"^idor_expectations\[0\]\.?", "", str(e)))
        key = (parsed["path"], parsed["param"], parsed["value"])
        if key in seen:
            raise EngagementError(f"{no}行目: 同じpath・param・valueが重複しています")
        seen.add(key)
        out.append(parsed)
    return out


def format_expectation_lines(rows: list[dict] | None) -> str:
    """期待権限表をGUI入力用の1行1ルール形式へ戻す(parse_expectation_linesの逆)。"""
    return "\n".join(" ".join([r["path"], r["param"], *([r["value"]] if r.get("value") else []),
                              f"a={r['a']}", f"b={r['b']}"]) for r in rows or [])
