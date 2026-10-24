"""
core/autonomy/research_llm.py — LLMによる仮説提案の入口（U2）

LLMは**提案する**だけで、実行権限も期待値の判断も持たない（要求仕様 §5）:
  - 提案は閉じた語彙の構造化JSON（check型・操作・ロール・観測済みID・根拠の条項）。拒否ステータス・マーカー・対照は
    LLMが指定できず、決定論のコードが仕様の条項と観測した所有関係から導く。LLMが『根拠あり』と言っても採用しない。
  - 提案は既存の `validate_hypothesis`（有効な仮説の定義）を通ったものだけが登録され、実験前にジャーナルへ書かれる。
    規則が既に作る仮説と同じものは `duplicate_of_rule`（新規ではない）。通らないものは理由コードつきで却下し数える。
  - プロンプトは案件の静的文言（仕様・アカウント名）と、安全な形式のID・ロール名だけ。対象の応答本文は渡さない。
    LLMの説明文（rationale）は無害化して追跡用にジャーナルへ残すだけで、レポートの根拠・判定には使わない。
  - LLM呼出は事前にBudgetLedgerで予約する（回数・入力文字数）。失敗・不正な返答でも規則による調査は変わらず続く。
"""
from __future__ import annotations
import hashlib
import json
import re

from core.autonomy.research_case import BlindCase
from core.autonomy.research_hypothesis import Hypothesis, build_list_scope, propose
from core.autonomy.research_model import TargetModel

PROMPT_VERSION = "research-propose/1"
MAX_PROPOSALS = 8
CHECKS = ("deny_expected", "list_visibility", "fields_subset")
_ID_OK = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S)


def clean_text(s, limit: int = 200) -> str:
    """LLM由来の文字列を無害化する（制御文字・改行を除き長さを制限）。判定や報告の根拠には使わない。"""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(s))[:limit].strip()


def _safe_id(v) -> str | None:
    return v if isinstance(v, str) and _ID_OK.match(v) else None


def build_messages(case: BlindCase, model: TargetModel, phase: str) -> tuple[list[dict], dict]:
    """戻り値: (messages, 無害化の記録)。phase='spec'は仕様だけ、'observed'は観測した所有/共有関係つき。"""
    dropped = {"unsafe_ids": 0}
    ops = []
    for o in case.operations.values():
        ops.append(f"- {o.op_id}: {o.method} {o.path} / 条項{o.access['clause']}[{o.access['kind']}] {o.access['text']}"
                   + (f" / 返却項目={o.returns['fields']}" if o.returns.get("fields") else "")
                   + (f" / パラメータ={sorted(o.params)}" if o.params else ""))
    accts = [f"- {a.name}: 権限区分={a.privilege}" for a in sorted(case.accounts.values(), key=lambda a: a.name)] + ["- anonymous: 未認証"]
    if phase == "observed":
        obs = []
        for (t, oid), ob in sorted(model.objects.items()):
            sid = _safe_id(oid)
            if sid is None:
                dropped["unsafe_ids"] += 1
                continue
            owner = model.role_of_user(ob.owner_user) if ob.owner_user else None
            shared = sorted(r for r in (model.role_of_user(u) for u in ob.shared_with) if r)
            obs.append(f"- {t} {sid}: 所有者={owner or '不明'}, 共有先={shared}")
        for uid_role, ident in sorted(model.identity.items()):
            if _safe_id(ident["user_id"]) is None:
                dropped["unsafe_ids"] += 1
                continue
            obs.append(f"- 利用者 {ident['user_id']} = {uid_role}")
        bad = sorted({u["what"].split(":")[0] for u in model.unknowns if u["what"].endswith(":identity")})
        obs_text = "観測済み:\n" + ("\n".join(obs) or "- なし") + (f"\n- セッションが無効だったアカウント: {bad}" if bad else "")
        id_note = "パスパラメータには上の観測済みIDだけを使える。"
    else:
        obs_text = "観測済み: まだ無い（IDは不明）"
        id_note = "IDが未観測なので、パスパラメータの無い操作だけを提案する。"
    system = ("あなたはWeb APIの認可・情報露出の調査を補助する。仕様を読み、検証する価値のある仮説を提案する。"
              "あなたに実行権限は無く、提案は検証器が検査する（拒否されるべきかの判断も検証器が仕様から行う）。出力はJSONだけ。")
    user = "\n".join([
        f"## 仕様 ({case.spec_title})", *ops, "", "## アカウント", *accts, "", f"## {obs_text}", "",
        "## 提案に使えるcheck（この3つだけ）",
        "- deny_expected: 権限の無いロールが、その操作に到達できてはならない（拒否されるべき）という仮説。",
        "- list_visibility: 一覧操作(own_list)の応答に、呼出し者が所有者でも共有先でもない要素が含まれるという仮説。",
        "- fields_subset: 応答に、仕様の返却項目に無い項目が含まれるという仮説。",
        "", "## 制約",
        f"- 読取り(GET)の操作だけ。{id_note} 最大{MAX_PROPOSALS}件。basis_clauseには、その操作の条項ID(S-数字)を必ず書く。",
        "- 既に自明なものを並べるのでなく、仕様の文言を読んで検証価値が高い順に選ぶ。", "",
        "## 出力形式（JSONだけ）",
        '{"proposals":[{"check":"deny_expected|list_visibility|fields_subset","op_id":"...","probe_role":"アカウント名またはanonymous",'
        '"path_params":{"名前":"観測済みID"},"basis_clause":"S-n","rationale":"短い理由"}]}'])
    return [{"role": "system", "content": system}, {"role": "user", "content": user}], dropped


def _is_truncated(t: str) -> bool:
    """JSONらしい文字列が、途中で切れている（文字列・括弧が閉じないまま終わる）か。文字列内の括弧は数えない。"""
    depth, in_str, esc = 0, False, False
    for ch in t:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
    return in_str or depth > 0


def _salvage_truncated(t: str) -> list:
    """出力上限で途中まで切れた返答から、完全に解析できる提案オブジェクトだけを順に取り出す（最後の不完全な提案は捨てる）。
    切れていない不正な返答には使わない（呼出し側が _is_truncated で確認する）。取り出したオブジェクトも、通常の提案と同じ検証を通る。"""
    m = re.search(r'"proposals"\s*:\s*\[', t)
    if not m and t.lstrip().startswith("{"):
        return []                                    # proposals 以外の配列から取り出さない
    start = m.end() if m else (t.find("[") + 1 if "[" in t else 0)
    if start <= 0:
        return []
    dec, pos, items = json.JSONDecoder(), start, []
    while pos < len(t):
        while pos < len(t) and t[pos] in " \t\r\n,":
            pos += 1
        if pos >= len(t) or t[pos] != "{":
            break
        try:
            obj, pos = dec.raw_decode(t, pos)
        except ValueError:
            break                                    # ここから先は不完全（切れた提案）。捨てる
        if isinstance(obj, dict):
            items.append(obj)
    return items


def parse_reply(text: str) -> tuple[list | None, str]:
    """返答からproposals配列を取り出す。戻り値: (配列, 理由)。形式が違えば(None, 理由)。
    出力上限で途中まで切れた返答は、完全に書かれていた提案だけを救済し、理由を `salvaged_truncated:<件数>` にする（0件なら従来どおり失敗）。"""
    t = (text or "").strip()
    if not t:
        return None, "empty_reply"
    m = _FENCE.search(t)
    if m:
        t = m.group(1).strip()
    i, j = t.find("{"), t.rfind("}")
    if i < 0 or j < i:
        k, l_ = t.find("["), t.rfind("]")
        if k < 0 or l_ < k:
            return None, "no_json"
        i, j = k, l_
    try:
        doc = json.loads(t[i:j + 1])
    except ValueError:
        if _is_truncated(t[i:]):
            items = _salvage_truncated(t[i:])[:MAX_PROPOSALS]
            if items:
                return items, f"salvaged_truncated:{len(items)}"
        return None, "invalid_json"
    items = doc.get("proposals") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        return None, "proposals_not_a_list"
    return items[:MAX_PROPOSALS], ""


def process_proposal(case: BlindCase, model: TargetModel, p) -> tuple[str, str, Hypothesis | None]:
    """1件の提案を検査して振り分ける。戻り値: (status, reason, hypothesis)。
    status: new（登録候補）/ duplicate_of_rule（規則が作る仮説と同じ）/ rejected。"""
    if not isinstance(p, dict):
        return "rejected", "proposal_not_an_object", None
    chk, role = p.get("check"), p.get("probe_role")
    if chk not in CHECKS:
        return "rejected", "check_unknown", None
    op = case.operations.get(p.get("op_id")) if isinstance(p.get("op_id"), str) else None
    if op is None:
        return "rejected", "op_unknown", None
    if op.method != "GET":
        return "rejected", "op_method_not_approved", None
    if p.get("basis_clause") != op.access["clause"]:
        return "rejected", "basis_clause_mismatch", None      # 根拠は、その操作自身の仕様条項でなければならない
    if not isinstance(role, str) or (role != "anonymous" and role not in case.accounts):
        return "rejected", "role_unknown", None
    pp = p.get("path_params") or {}
    if not isinstance(pp, dict) or set(pp) != set(op.params) or not all(isinstance(v, str) for v in pp.values()):
        return "rejected", "params_mismatch", None
    rationale = clean_text(p.get("rationale", ""))
    if chk == "list_visibility":
        h, why = build_list_scope(model, op, role)
        if h is None:
            return "rejected", why, None
        h.source, h.llm_rationale = "llm", rationale
        return "new", "", h
    want_fields = chk == "fields_subset"
    for x in propose(model):         # 期待値は規則と同じ決定論の判定器が出す。LLMの指定は使わない
        if (x.probe is not None and x.op_id == op.op_id and x.probe_role == role
                and (x.family == "field_exposure") == want_fields and dict(x.probe.path_params) == pp):
            return "duplicate_of_rule", "", x
    if pp:
        otype = next(iter(op.params.values()))["object"]
        known = ({i["user_id"] for i in model.identity.values()} if otype == "user"
                 else {o.object_id for o in model.objects_of(otype)})
        if not set(pp.values()) <= known:
            return "rejected", "param_not_observed", None
    return "rejected", "expectation_not_supported_by_spec_or_observation", None


def reply_sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()[:16]
