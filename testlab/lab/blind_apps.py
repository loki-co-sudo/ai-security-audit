"""自律調査(Stage 1)用の被験環境 TeamDocs(127.0.0.1のみ・標準ライブラリのみ・実行ごとに初期化)。

固定テストを選ぶ従来のlab(apps.py)と違い、案件設定には『どの操作が危ないか』も『期待値』も置かない。調査側が見られるのは
公開仕様(blind_cases/*.json の spec)と、アカウント経由の観測だけ。ID(文書・利用者)は起動ごとにランダムで、
調査側は観測からしか知れない。**どれが不備かのラベルはここに置かない**(正解は truth/ に分離)。`flaws` は環境側の挙動の
切替で、案件ごとの不備の集合を作るためだけに使う(調査側には渡らない)。
"""
from __future__ import annotations
import random
import secrets

from testlab.lab.apps import LabApp, _json

# 環境が実装している不備の種類(truthのflaw_idと対応)。空集合なら全操作が仕様どおり(正常な対象)。
ALL_FLAWS = frozenset({"comments_bola", "user_exposure", "audit_bfla", "export_bola"})
V2_FLAWS = ALL_FLAWS | {"list_leak"}       # list_leak: 管理者の一覧が全員分（仕様は『所有または共有のみ』）


class DocsApp(LabApp):
    roles = ("alice", "bob", "carol", "admin", "user_expired")
    _NAMES = {"alice": "Alice", "bob": "Bob", "carol": "Carol", "admin": "Admin", "user_expired": "Erin"}

    def __init__(self, canary=None, flaws=ALL_FLAWS, seed=None):
        super().__init__(canary)
        self.flaws = frozenset(flaws)
        rnd = random.Random(seed) if seed is not None else None       # seed指定時はIDだけ決定論（tokenは常にランダム）
        hexid = (lambda n: "%0*x" % (n, rnd.getrandbits(4 * n))) if rnd else (lambda n: secrets.token_hex(n // 2))
        self.users = {r: {"id": "u_" + hexid(8), "name": self._NAMES[r],
                          "email": f"{r}@example.test", "phone": "090-" + hexid(4)}
                      for r in self.roles}
        uid = {r: u["id"] for r, u in self.users.items()}
        mk = lambda owner, title, shared: {"id": "d_" + hexid(8), "title": title,  # noqa: E731
                                           "owner": uid[owner], "shared_with": [uid[s] for s in shared],
                                           "body": f"body of {title}"}
        docs = [mk("alice", "alice-plan", ["bob"]), mk("alice", "alice-private", []),
                mk("bob", "bob-notes", []), mk("carol", "carol-draft", [])]
        self.docs = {d["id"]: d for d in docs}
        self.comments = {d["id"]: [{"doc_id": d["id"], "author": d["owner"], "text": "note on " + d["title"]}]
                         for d in docs}
        self._by_uid = {u["id"]: r for r, u in self.users.items()}

    # 調査側が知らない環境の事実(採点・試験用)。診断ワークフローへは渡さない
    def doc_ids_by_title(self) -> dict[str, str]:
        return {d["title"]: d["id"] for d in self.docs.values()}

    def _can_read(self, role, doc) -> bool:
        uid = self.users[role]["id"]
        return doc["owner"] == uid or uid in doc["shared_with"]

    def route(self, path, q, role, n_prev):
        parts = [p for p in path.split("/") if p]
        if parts == ["api", "health"]:
            return 200, {}, _json({"status": "ok"})
        if role is None:
            return 401, {}, _json({"error": "authentication required"})
        if parts == ["api", "me"]:
            u = self.users[role]
            return 200, {}, _json({"id": u["id"], "name": u["name"], "email": u["email"]})
        if parts == ["api", "docs"]:
            vis = [{k: d[k] for k in ("id", "title", "owner", "shared_with")}
                   for d in self.docs.values() if self._can_read(role, d) or (role == "admin" and "list_leak" in self.flaws)]
            return 200, {}, _json(vis)
        if len(parts) >= 3 and parts[:2] == ["api", "docs"]:
            doc = self.docs.get(parts[2])
            tail = parts[3:]
            if doc is None:
                return 404, {}, _json({"error": "not found"})
            allowed = self._can_read(role, doc)
            if not tail:
                if not allowed:
                    return 403, {}, _json({"error": "forbidden"})
                return 200, {}, _json(doc)
            if tail == ["comments"]:
                if not allowed and "comments_bola" not in self.flaws:
                    return 403, {}, _json({"error": "forbidden"})
                return 200, {}, _json(self.comments[doc["id"]])
            if tail == ["export"]:
                owner_only = doc["owner"] == self.users[role]["id"]
                if not owner_only and "export_bola" not in self.flaws:
                    return 403, {}, _json({"error": "forbidden"})
                return 200, {}, _json({"doc_id": doc["id"], "format": "md", "content": doc["body"]})
            return 404, {}, _json({"error": "not found"})
        if len(parts) == 3 and parts[:2] == ["api", "users"]:
            r = self._by_uid.get(parts[2])
            if r is None:
                return 404, {}, _json({"error": "not found"})
            u = self.users[r]
            out = {"id": u["id"], "name": u["name"]}
            if "user_exposure" in self.flaws:
                out.update({"email": u["email"], "phone": u["phone"]})
            return 200, {}, _json(out)
        if parts == ["api", "admin", "stats"]:
            if role != "admin":
                return 403, {}, _json({"error": "forbidden"})
            return 200, {}, _json({"documents": len(self.docs), "users": len(self.users)})
        if parts == ["api", "admin", "audit"]:
            if role != "admin" and "audit_bfla" not in self.flaws:
                return 403, {}, _json({"error": "forbidden"})
            return 200, {}, _json([{"event": "login", "user": u["id"]} for u in self.users.values()])
        return 404, {}, _json({"error": "not found"})
