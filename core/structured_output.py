"""ローカルOllama向けの構造化出力(JSONスキーマ制約)モード。設定 `llm_structured` が真のときだけ使う(既定OFF)。

小型モデルは、プロンプトで指定した所見マーカー(---VULN_START--- 等)を守れず、実質のある分析が出ても所見0件になることがある。
Ollamaのネイティブ API(/api/chat)の `format` にJSONスキーマを渡すと、生成の段階で出力形式を制約できる(huginnと同じ手法)。
制約されたJSONは `render()` で既存のマーカー形式へ変換して返すので、下流(レポート・所見・証拠ID・状態判定)は変わらない。

注意: 形式が保証されるだけで、**内容の正しさは保証されない**(小型モデルは事実の誤りや誤検知を出す)。
Ollamaの `num_ctx` を明示する(OpenAI互換エンドポイントでは指定できず、入力が黙って切り詰められるため)。
モデルが出力した文字列に含まれるマーカーは無害化する(下流のパーサーを欺くマーカー注入を避ける)。
"""
from __future__ import annotations

import json
import re

KINDS = ("vuln", "threat", "finding")
_SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_MARKER = re.compile(r"---\s*(?:VULN|FINDING|THREAT|EXPLOIT)_(?:START|END)\s*---", re.I)
_EVIDENCE_IDS = {"type": "array", "items": {"type": "string"},
                 "description": "evidence_id values literally given in the input that support this item; empty if none"}


class StructuredOutputError(Exception):
    """構造化出力の取得に失敗した(接続・非対応・不正なJSON・入力の切り詰め)。メッセージに秘密値を含めない。"""


def _obj(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required}


SCHEMAS = {
    "vuln": _obj({"findings": {"type": "array", "items": _obj({
        "name": {"type": "string"}, "severity": {"type": "string", "enum": _SEV},
        "cwe": {"type": "string", "description": "CWE-ID such as CWE-89, or 'Novel'"},
        "lines": {"type": "string", "description": "affected line numbers or range, or URL + parameter"},
        "snippet": {"type": "string"}, "attack": {"type": "string"}, "fix": {"type": "string"},
        "evidence_ids": _EVIDENCE_IDS},
        ["name", "severity", "cwe", "lines", "snippet", "attack", "fix"])}}, ["findings"]),
    "threat": _obj({"threats": {"type": "array", "items": _obj({
        "severity": {"type": "string", "enum": _SEV}, "threat_type": {"type": "string"},
        "mitre_ttp": {"type": "string", "description": "ATT&CK technique ID only if certain, otherwise N/A"},
        "attacker_ip": {"type": "string"}, "timeline": {"type": "string"}, "analysis": {"type": "string"},
        "immediate_actions": {"type": "string"}, "evidence_ids": _EVIDENCE_IDS},
        ["severity", "threat_type", "mitre_ttp", "attacker_ip", "timeline", "analysis", "immediate_actions"])}}, ["threats"]),
    "finding": _obj({"findings": {"type": "array", "items": _obj({
        "title": {"type": "string"}, "severity": {"type": "string", "enum": _SEV},
        "category": {"type": "string", "enum": ["Network", "Web", "Config", "AuthLogic", "InfoDisclosure"]},
        "evidence": {"type": "string"}, "attack_scenario": {"type": "string"}, "recommended_action": {"type": "string"},
        "evidence_ids": _EVIDENCE_IDS},
        ["title", "severity", "category", "evidence", "attack_scenario", "recommended_action"])}}, ["findings"]),
}

_HINT = ("\n\nRespond ONLY with JSON that matches the provided schema. Use an empty list when there is no credible "
         "finding. Report only issues that are actually supported by the input; do not report code or events that are safe.")


def schema_for(kind: str) -> dict:
    if kind not in SCHEMAS:
        raise StructuredOutputError(f"未対応の種類です: {kind}")
    return SCHEMAS[kind]


def with_hint(messages: list[dict]) -> list[dict]:
    """最後のuserメッセージの末尾に、JSONだけで答える指示を足す(元のリストは変更しない)。"""
    out = [dict(m) for m in messages]
    for m in reversed(out):
        if m.get("role") == "user":
            m["content"] = str(m.get("content", "")) + _HINT
            break
    return out


_FIELD_LINE = re.compile(r"(?im)^(\s*)(NAME|SEVERITY|CWE|LINES|SNIPPET|ATTACK|FIX|EVIDENCE_IDS|CONFIDENCE|TITLE|CATEGORY|EVIDENCE|"
                         r"ATTACK_SCENARIO|RECOMMENDED_ACTION|THREAT_TYPE|MITRE_TTP|ATTACKER_IP|TIMELINE|ANALYSIS|IMMEDIATE_ACTIONS)\s*:")
NO_FINDINGS = "(構造化出力) モデルは、入力から裏付けられる所見は無いと回答しました。"   # 「所見なし」は正当な回答で、LLMの失敗ではない


def _clean(value, multiline: bool = False) -> str:
    """文字列化して、所見マーカーと、パーサーが欄として読む `KEY:` 行を無害化する。

    1行の欄は改行を空白にする(改行で `SEVERITY: CRITICAL` のような行を仕込めないように)。複数行の欄は、
    行頭の `KEY:` を `> KEY:` にし、コードフェンス(```)も崩して、後続の欄・ブロックを偽装できないようにする。
    """
    s = _MARKER.sub("[marker removed]", str(value if value is not None else "")).strip()
    if not multiline:
        return re.sub(r"\s*[\r\n]+\s*", " ", s)
    return _FIELD_LINE.sub(lambda m: f"{m.group(1)}> {m.group(2)}:", s).replace("```", "` ` `")


def _ids(item: dict) -> str:
    raw = item.get("evidence_ids")
    return ", ".join(_clean(x) for x in raw if str(x).strip()) if isinstance(raw, list) else ""


def _sev(item: dict) -> str:
    s = str(item.get("severity", "")).upper()
    return s if s in _SEV else "LOW"


def render(kind: str, data: dict) -> str:
    """スキーマに沿ったJSON(dict)を既存のマーカー形式のテキストへ変換する。項目が無ければ空文字。"""
    if not isinstance(data, dict):
        raise StructuredOutputError("JSONのトップレベルがオブジェクトではありません")
    blocks = []
    if kind == "vuln":
        for f in data.get("findings") or []:
            ids = _ids(f)
            blocks.append(
                "---VULN_START---\n"
                f"NAME: {_clean(f.get('name'))}\nSEVERITY: {_sev(f)}\nCWE: {_clean(f.get('cwe'))}\nLINES: {_clean(f.get('lines'))}\n"
                + (f"EVIDENCE_IDS: {ids}\n" if ids else "")
                + f"SNIPPET:\n```\n{_clean(f.get('snippet'), True)}\n```\nATTACK:\n{_clean(f.get('attack'), True)}\n"
                  f"FIX:\n```\n{_clean(f.get('fix'), True)}\n```\n---VULN_END---")
    elif kind == "threat":
        for t in data.get("threats") or []:
            ids = _ids(t)
            blocks.append(
                "---THREAT_START---\n"
                f"SEVERITY: {_sev(t)}\nTHREAT_TYPE: {_clean(t.get('threat_type'))}\nMITRE_TTP: {_clean(t.get('mitre_ttp')) or 'N/A'}\n"
                f"ATTACKER_IP: {_clean(t.get('attacker_ip'))}\n" + (f"EVIDENCE_IDS: {ids}\n" if ids else "")
                + f"TIMELINE: {_clean(t.get('timeline'))}\nANALYSIS:\n{_clean(t.get('analysis'), True)}\n"
                  f"IMMEDIATE_ACTIONS:\n{_clean(t.get('immediate_actions'), True)}\n---THREAT_END---")
    elif kind == "finding":
        for f in data.get("findings") or []:
            ids = _ids(f)
            blocks.append(
                "---FINDING_START---\n"
                f"TITLE: {_clean(f.get('title'))}\nSEVERITY: {_sev(f)}\nCATEGORY: {_clean(f.get('category'))}\n"
                + (f"EVIDENCE_IDS: {ids}\n" if ids else "")
                + f"EVIDENCE: {_clean(f.get('evidence'))}\nATTACK_SCENARIO:\n{_clean(f.get('attack_scenario'), True)}\n"
                  f"RECOMMENDED_ACTION:\n{_clean(f.get('recommended_action'), True)}\n---FINDING_END---")
    else:
        raise StructuredOutputError(f"未対応の種類です: {kind}")
    return "\n\n".join(blocks) if blocks else NO_FINDINGS


def native_base(base_url: str) -> str:
    """OpenAI互換のbase_url(.../v1)からOllamaネイティブAPIのベースURLを得る。"""
    return re.sub(r"/v1/?$", "", base_url.rstrip("/"))


def chat_json(base_url: str, model: str, messages: list[dict], schema: dict, *, num_ctx: int = 12288,
              timeout: float = 600, post=None) -> tuple[dict, dict]:
    """Ollamaの/api/chatへformat(JSONスキーマ)つきで1回問い合わせ、(パース済みJSON, メタ情報)を返す。

    thinkは無効・stream無し・temperature 0。入力がnum_ctxに達していれば切り詰められた可能性として例外にする
    (黙って一部だけを見た結果を返さない)。`post`はテスト用の差し替え(requests.postと同じ形)。
    """
    import requests  # noqa: PLC0415
    body = {"model": model, "stream": False, "think": False, "format": schema, "messages": messages,
            "options": {"num_ctx": int(num_ctx), "temperature": 0}}
    try:
        resp = (post or requests.post)(native_base(base_url) + "/api/chat", json=body, timeout=timeout)
    except requests.RequestException as e:
        raise StructuredOutputError(f"Ollamaに接続できません({type(e).__name__})")
    if resp.status_code == 404:
        raise StructuredOutputError("/api/chat が見つかりません。llm_structuredはOllama専用です(base_urlを確認してください)")
    if resp.status_code >= 400:
        raise StructuredOutputError(f"Ollamaがエラーを返しました(HTTP {resp.status_code})")
    try:
        raw = resp.json()
        data = json.loads(raw["message"]["content"])
    except (ValueError, KeyError, TypeError):
        raise StructuredOutputError("応答をJSONとして読めません(出力が途中で切れた可能性)")
    meta = {"prompt_tokens": raw.get("prompt_eval_count"), "output_tokens": raw.get("eval_count"),
            "done_reason": raw.get("done_reason")}
    if isinstance(meta["prompt_tokens"], int) and meta["prompt_tokens"] >= int(num_ctx) - 8:
        raise StructuredOutputError(
            f"入力がnum_ctx({num_ctx})に達しており、一部が切り詰められた可能性があります(llm_structured_num_ctxを増やしてください)")
    return data, meta
