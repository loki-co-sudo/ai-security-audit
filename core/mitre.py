"""MITRE ATT&CK テクニックIDの確認(P4.3)。LLMが書いたIDを、既知の集合に無ければ確定タグとして出力しない。

KNOWN_TECHNIQUES は本ツールが扱うWeb/ログ分析に関係する代表的なEnterpriseテクニックの部分集合で、網羅的でも権威ある一覧でもない。
集合に無いIDは「未確認」として表示し、削除はしない(実在するが未収録の可能性があるため)。オフラインで検証でき、LLMの幻覚IDを確定タグにしない。
"""
from __future__ import annotations
import re

KNOWN_TECHNIQUES = frozenset("""
T1005 T1018 T1021 T1027 T1036 T1041 T1046 T1055 T1059 T1059.004 T1059.006 T1068 T1070 T1071 T1071.001 T1078 T1082
T1083 T1087 T1105 T1110 T1110.001 T1110.003 T1110.004 T1133 T1140 T1189 T1190 T1203 T1204 T1212 T1498 T1498.001
T1499 T1499.002 T1505.003 T1552 T1552.001 T1566 T1590 T1592 T1595 T1595.001 T1595.002
""".split())
_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def split_ttp(raw: str) -> tuple[list[str], list[str]]:
    """(確認済みID, 未確認ID)。テンプレートの残骸('[T-code if applicable]'やN/A)からはIDを拾わない。"""
    ids = list(dict.fromkeys(_ID.findall(str(raw or "").upper())))
    return [i for i in ids if i in KNOWN_TECHNIQUES], [i for i in ids if i not in KNOWN_TECHNIQUES]


def format_ref(raw: str) -> str:
    ok, unknown = split_ttp(raw)
    return ", ".join([*ok, *[f"未確認:{i}" for i in unknown]])
