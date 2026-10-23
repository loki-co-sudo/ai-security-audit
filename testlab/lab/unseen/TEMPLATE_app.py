"""【テンプレート】未使用ケース用の被験環境の最小例（図書の貸出API）。これをコピーして書き換えて使う。

規約（tools/research_case_check.py が検査する）:
  - testlab.lab.apps.LabApp を継承する（リクエストの記録・トークン・起動/停止が共通化される）
  - クラス変数 roles = 案件ファイルの accounts のキー名（アカウント名）をすべて含む。名前が "user_expired" のアカウントは常に401を返す
  - コンストラクタは (canary=None, flaws=frozenset(), seed=None)。flaws は『有効にする欠陥の名前』の集合（空なら全操作が仕様どおりの正常な環境）
  - seed を渡すとIDだけ決定論的に作り、渡さなければランダム。IDは起動ごとに変える（調査側は観測でしかIDを知れない）
  - route(path, q, role, n_prev) は (status, headers, body_str) を返す。role は認証済みなら roles の名前、未認証なら None
  - 欠陥のラベル（コメントや変数名を含む）は、公開側の案件ファイルには出さない。この環境のコード自体は調査側からは読めない
  - 外部への通信・ファイル書込み・秘密値の利用はしない。loopback(127.0.0.1)だけで動く
"""
from __future__ import annotations
import json
import random
import secrets

from testlab.lab.apps import LabApp


def _json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


class App(LabApp):
    roles = ("reader1", "reader2", "librarian", "user_expired")
    _NAMES = {"reader1": "Reader One", "reader2": "Reader Two", "librarian": "Librarian", "user_expired": "Expired"}

    def __init__(self, canary=None, flaws=frozenset(), seed=None):
        super().__init__(canary)
        self.flaws = frozenset(flaws)
        rnd = random.Random(seed) if seed is not None else None
        hexid = (lambda n: "%0*x" % (n, rnd.getrandbits(4 * n))) if rnd else (lambda n: secrets.token_hex(n // 2))
        self.members = {r: {"id": "m_" + hexid(8), "name": self._NAMES[r]} for r in self.roles}
        self.loans = {}
        for r, title in (("reader1", "book-a"), ("reader1", "book-b"), ("reader2", "book-c")):
            lid = "l_" + hexid(8)
            self.loans[lid] = {"id": lid, "member": self.members[r]["id"], "title": title, "due": "2026-12-01"}

    def _role_of(self, member_id):
        return next((r for r, m in self.members.items() if m["id"] == member_id), None)

    def route(self, path, q, role, n_prev):
        parts = [p for p in path.split("/") if p]
        if parts == ["api", "catalog"]:
            return 200, {}, _json([{"title": "book-a"}, {"title": "book-b"}, {"title": "book-c"}])
        if role is None:
            return 401, {}, _json({"error": "authentication required"})
        if parts == ["api", "me"]:
            return 200, {}, _json(self.members[role])
        if parts == ["api", "loans"]:
            return 200, {}, _json([l for l in self.loans.values() if l["member"] == self.members[role]["id"]])
        if len(parts) == 3 and parts[:2] == ["api", "loans"]:
            loan = self.loans.get(parts[2])
            if loan is None:
                return 404, {}, _json({"error": "not found"})
            if loan["member"] != self.members[role]["id"] and "loan_idor" not in self.flaws:
                return 403, {}, _json({"error": "forbidden"})
            return 200, {}, _json(loan)
        if parts == ["api", "staff", "report"]:
            if role != "librarian":
                return 403, {}, _json({"error": "forbidden"})
            return 200, {}, _json({"loans": len(self.loans)})
        return 404, {}, _json({"error": "not found"})
