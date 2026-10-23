"""
core/autonomy/research_model.py — 自律調査のTarget Model(仕様＋観測を、出典と確認状態つきで保持する)

Run/案件内の観測・不明点の保持だけを担う(案件をまたぐ記憶は持たない)。事実は2種類:
  spec      提供された仕様書の記述(clause付き)。調査側が作った期待値ではない
  observed  実験の応答から読み取った値(experiment idと証拠IDで出典を辿れる)
応答の本文そのものはここに保持しない(オブジェクトID・所有者・共有先・利用者IDなど、仕様が定義した項目だけを抽出する)。
読み取れなかったもの・失敗した観測は `unknowns` に残す(黙って捨てない)。
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field

from core.autonomy.research_case import BlindCase


@dataclass(frozen=True)
class Experiment:
    """登録済みの操作部品(読取りGET)を、ロール・操作・観測済みの引数で具体化したもの。"""
    role: str                      # アカウント名 or "anonymous"
    op_id: str
    path_params: tuple = ()        # ((名前, 値), ...) 名前順

    @property
    def exp_id(self) -> str:
        tail = ":".join(f"{v}" for _, v in self.path_params)
        return f"x:{self.op_id}:{self.role}" + (f":{tail}" if tail else "")

    def params(self) -> dict:
        return dict(self.path_params)


@dataclass
class ExpResult:
    exp_id: str
    status_code: int | None
    json: object = None            # 解析できたJSON(評価専用。ジャーナル・LLMへは出さない)
    body_complete: bool = True
    incomplete_reason: str | None = None
    evidence_id: str | None = None
    reason: str = ""               # 通信失敗・認証情報なし等
    obs_seq: int = 0               # 結果を取り込んだ順(同一Run内の時系列)


@dataclass
class ObservedObject:
    type: str
    object_id: str
    owner_user: str | None
    shared_with: tuple
    seen_via: list = field(default_factory=list)       # [(role, exp_id)]


def _items(js):
    if isinstance(js, dict):
        return [js]
    if isinstance(js, list):
        return [x for x in js if isinstance(x, dict)]
    return []


def json_keys(js) -> set:
    out: set = set()
    for it in _items(js):
        out |= set(it.keys())
    return out


def contains_marker(js, key: str, value: str) -> bool:
    return any(it.get(key) == value for it in _items(js))


class TargetModel:
    def __init__(self, case: BlindCase):
        self.case = case
        self.identity: dict[str, dict] = {}          # role -> {"user_id", "exp_id", "evidence_id"}
        self.objects: dict[tuple, ObservedObject] = {}   # (type, id) -> ...
        self.unknowns: list[dict] = []
        self.results: dict[str, ExpResult] = {}
        self._seq = 0
        self.sessions_checked = False        # 各アカウントのセッション有効性を観測し終えたか（ロールを選ぶ仮説の前提）

    # ── 仕様由来の事実 ─────────────────────────────
    def spec_facts(self) -> list[dict]:
        out = []
        for op in self.case.operations.values():
            out.append({"kind": "spec", "clause": op.access["clause"], "op_id": op.op_id, "access_kind": op.access["kind"],
                        "text": op.access["text"], "status": "confirmed"})
        return out

    def privilege_of(self, role: str) -> str | None:
        a = self.case.accounts.get(role)
        return a.privilege if a else None

    def user_ids(self) -> dict[str, str]:
        return {r: i["user_id"] for r, i in self.identity.items()}

    def role_of_user(self, user_id: str) -> str | None:
        for r, i in self.identity.items():
            if i["user_id"] == user_id:
                return r
        return None

    # ── 観測の取り込み ────────────────────────────
    def ingest(self, exp: Experiment, res: ExpResult) -> list[str]:
        """実験結果を取り込み、仕様が定義した項目だけを事実にする。戻り値: 追加された観測の説明(静的文言＋ID類)。"""
        self._seq += 1
        res.obs_seq = self._seq
        self.results[exp.exp_id] = res
        notes: list[str] = []
        op = self.case.operations[exp.op_id]
        if res.status_code != 200 or res.json is None:
            if exp.role != "anonymous" and (op.returns.get("identity") or op.access["kind"] == "own_list"):
                what = f"{exp.role}:identity" if op.returns.get("identity") else f"{exp.role}:{exp.op_id}"
                self.unknowns.append({"what": what, "why": f"observation_failed(status={res.status_code}, {res.reason or 'no_json'})",
                                      "exp_id": exp.exp_id})
            return notes
        if op.returns.get("identity"):
            idf = self.case.objects.get("user", {}).get("id_field", "id")
            items = _items(res.json)
            if len(items) == 1 and isinstance(items[0].get(idf), str):
                self.identity[exp.role] = {"user_id": items[0][idf], "exp_id": exp.exp_id, "evidence_id": res.evidence_id}
                notes.append(f"identity:{exp.role}")
            else:
                self.unknowns.append({"what": f"{exp.role}:identity", "why": "unparseable_identity", "exp_id": exp.exp_id})
        if op.access["kind"] == "own_list" and op.returns.get("object"):
            otype = op.returns["object"]
            spec_o = self.case.objects[otype]
            idf, ownf, shf = spec_o["id_field"], spec_o.get("owner_field"), spec_o.get("shared_field")
            n = 0
            for it in _items(res.json):
                oid = it.get(idf)
                if not isinstance(oid, str):
                    continue
                owner = it.get(ownf) if ownf and isinstance(it.get(ownf), str) else None
                shared = it.get(shf) if shf else []
                shared = tuple(x for x in shared if isinstance(x, str)) if isinstance(shared, list) else ()
                key = (otype, oid)
                if key not in self.objects:
                    self.objects[key] = ObservedObject(otype, oid, owner, shared)
                    n += 1
                self.objects[key].seen_via.append((exp.role, exp.exp_id))
            notes.append(f"objects:{otype}:{n}new")
        return notes

    # ── 問い合わせ ──────────────────────────────
    def objects_of(self, otype: str) -> list[ObservedObject]:
        return sorted((o for (t, _), o in self.objects.items() if t == otype), key=lambda o: o.object_id)

    def known_user_objects(self) -> list[str]:
        return sorted(i["user_id"] for i in self.identity.values())

    def summary(self) -> dict:
        return {"identities": {r: i["user_id"] for r, i in sorted(self.identity.items())},
                "objects": [{"type": o.type, "id": o.object_id, "owner": o.owner_user, "shared_with": list(o.shared_with)}
                            for t in sorted({k[0] for k in self.objects}) for o in self.objects_of(t)],
                "unknowns": list(self.unknowns)}


def safe_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None
