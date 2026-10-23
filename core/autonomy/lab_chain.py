"""
core/autonomy/lab_chain.py — 小さな不備の組合せ(連鎖)の候補を決定論ルールで作る(docs/LOCAL_LAB_EVAL.md §9 ステップ2.5)

仮説は `provides`(不備が事実なら得られる能力の語)を持てる。規則は「どの能力の組合せが、より重大な問題になるか」を
案件に依存せず定義する。連鎖は**仮説**であり、実行も確認もしない(各メンバーが`supported`=必要な対照も通った裏付けありであることだけを条件にする。対照未確認の逸脱 `unverified_deviation` は材料にせず、検査途中として扱う)。
  - candidate: 規則の必要能力を、全て別々の`supported`な仮説が満たしている。state="hypothesized"。
  - open: 一部だけ`supported`で、残りの能力を満たしうる仮説が未判定。検査を進めると連鎖になりうるものとして報告する。
メンバーに未判定・反証の仮説を含めて連鎖と断定しない。深刻度は規則の固定値で、測定ではなく見積り。
"""
from __future__ import annotations
import itertools
from dataclasses import dataclass

STATE_HYPOTHESIZED = "hypothesized"
MAX_COMBOS_PER_RULE = 8        # 組合せ爆発の上限


@dataclass(frozen=True)
class ChainRule:
    rule_id: str
    title: str
    needs: tuple
    severity: str
    rationale: str
    remediation: str


RULES = (
    ChainRule("session_theft", "反射型XSSとスクリプトから読めるCookieの組合せによるセッション窃取",
              ("xss_reflected", "cookie_script_readable"), "HIGH",
              "注入された断片でセッションCookieを読み出せる条件が揃う(どちらか単独は中程度)",
              "XSSの出力エスケープと、セッションCookieのHttpOnly付与の両方を行う"),
    ChainRule("targeted_data_exposure", "利用者識別子の公開と他人のデータ参照不備の組合せによる網羅的な情報露出",
              ("exposes_user_identifier", "read_other_user_object"), "CRITICAL",
              "公開された識別子を使って他人のデータ参照を大量に繰り返せる(参照不備単独は個別の推測が要る)",
              "識別子の公開を止める、またはデータ取得時に所有者を照合する"),
    ChainRule("hidden_function_exposure", "内部パスの開示と機能の認可不備の組合せによる隠し機能の露出",
              ("reveals_internal_path", "missing_function_authz"), "HIGH",
              "開示されたパスが認可なしで使える機能を指し、発見されにくい前提が崩れる",
              "内部パスを開示しない、かつ機能に認可検査を追加する"),
)


def _providers(case, token: str) -> list[str]:
    return [h.hypothesis_id for h in case.hypotheses.values() if token in h.provides]


def find_chains(case, status_of) -> tuple[list[dict], list[dict]]:
    """status_of(hypothesis_id) -> 状態文字列。戻り値: (連鎖候補, 検査途中の連鎖)。入力が同じなら出力も同じ。"""
    cands, opens = [], []
    for rule in RULES:
        sup_by = [[h for h in _providers(case, tok) if status_of(h) == "supported"] for tok in rule.needs]
        missing = [tok for tok, sup in zip(rule.needs, sup_by) if not sup]
        base = {"rule_id": rule.rule_id, "title": rule.title, "severity": rule.severity, "rationale": rule.rationale,
                "remediation": rule.remediation, "severity_is_estimate": True}
        if not missing:
            seen = set()
            for combo in itertools.product(*sup_by):
                if len(set(combo)) < len(combo) or frozenset(combo) in seen:
                    continue                                   # 同じ仮説で複数の必要能力を満たす連鎖は作らない
                seen.add(frozenset(combo))
                cands.append({**base, "state": STATE_HYPOTHESIZED, "members": list(combo),
                              "needs": dict(zip(rule.needs, combo))})
                if len(seen) >= MAX_COMBOS_PER_RULE:
                    break
            continue
        members = sorted({h for sup in sup_by for h in sup})
        if not members:
            continue
        pending = {t: [h for h in _providers(case, t) if status_of(h) in ("untested", "partially_tested", "undetermined", "unverified_deviation")]
                   for t in missing}
        if all(pending.values()):
            opens.append({**base, "state": "open", "members_supported": members, "missing": pending})
    return cands, opens


def chain_gain_hypotheses(case, status_of) -> set[str]:
    """検査すると連鎖が完成しうる仮説(優先順位付けの加点に使う)。

    規則の必要能力のうち、一部が裏付けあり(supported)または対照未確認の逸脱(unverified_deviation)で揃い、
    残りを満たしうる未判定の仮説がある場合、(a) その未判定の仮説と、(b) 対照が通れば材料になる
    unverified_deviation の仮説を返す(対照の確認を後回しにしないため)。"""
    out: set[str] = set()
    pending_st = ("untested", "partially_tested", "undetermined")
    for rule in RULES:
        have = [[h for h in _providers(case, tok) if status_of(h) in ("supported", "unverified_deviation")]
                for tok in rule.needs]
        missing = [tok for tok, hs in zip(rule.needs, have) if not hs]
        if not any(have):
            continue
        pend = {t: [h for h in _providers(case, t) if status_of(h) in pending_st] for t in missing}
        if missing and not all(pend.values()):
            continue
        out.update(h for hs in pend.values() for h in hs)
        out.update(h for hs in have for h in hs if status_of(h) == "unverified_deviation")
    return out
