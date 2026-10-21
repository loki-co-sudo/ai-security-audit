"""証拠の最小由来情報(content_sha256/action_id/masking_version/truncated)と verify() の固定試験。"""
import hashlib
import json
import os
import tempfile
import unittest

from core import redaction
from core.evidence_store import EvidenceStore, content_digest


class EvidenceProvenanceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def _store(self, **kw):
        return EvidenceStore("scan_prov", root=self.root, **kw)

    def _read(self, store, eid):
        with open(os.path.join(store.dir, f"{eid}.json"), encoding="utf-8") as f:
            return json.load(f)

    def _save_all(self, store, action_id="act_1"):
        return {
            "http": store.save_http_evidence(method="GET", url="http://x/?q=1", status=200, body="b",
                                             action_id=action_id),
            "code": store.save_code_evidence(path="a.py", line_start=1, line_end=2, excerpt="x = 1",
                                             source="ast_prescan", action_id=action_id),
            "log": store.save_log_evidence(source="a.log", line="GET /", patterns=["p"],
                                           action_id=action_id),
            "obs": store.save_observation_evidence(category="port", target_ref="h:80", detail="open",
                                                   action_id=action_id),
        }

    def test_all_kinds_carry_provenance(self):
        store = self._store()
        for kind, eid in self._save_all(store).items():
            with self.subTest(kind):
                d = self._read(store, eid)
                self.assertEqual(d["action_id"], "act_1")
                self.assertEqual(d["masking_version"], redaction.MASKING_VERSION)
                self.assertIs(d["truncated"], False)
                self.assertRegex(d["content_sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(store.verify(eid), (True, "ok"))

    def test_hash_is_over_saved_masked_data(self):
        store = self._store()
        secret = "PROV_DUMMY_SECRET_77"
        eid = store.save_http_evidence(method="GET", url=f"http://x/?token={secret}", status=200,
                                       body=f"body {secret}", known_secrets={secret})
        d = self._read(store, eid)
        self.assertNotIn(secret, json.dumps(d))
        body = {k: v for k, v in d.items() if k != "content_sha256"}
        canon = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        self.assertEqual(d["content_sha256"], hashlib.sha256(canon.encode()).hexdigest())
        self.assertEqual(d["content_sha256"], content_digest(d))

    def test_action_id_defaults_to_empty(self):
        store = self._store()
        eid = store.save_http_evidence(method="GET", url="http://x/", status=200)
        self.assertEqual(self._read(store, eid)["action_id"], "")

    def test_truncation_is_flagged(self):
        store = self._store(max_item_bytes=300)
        long = "A" * 1000
        e_http = store.save_http_evidence(method="GET", url="http://x/", status=200, body=long)
        e_code = store.save_code_evidence(path="a.py", line_start=1, line_end=1, excerpt=long,
                                          source="ast_prescan")
        e_log = store.save_log_evidence(source="a.log", line=long, patterns=[])
        e_obs = store.save_observation_evidence(category="web_headers", target_ref="x", detail=long)
        for eid in (e_http, e_code, e_log, e_obs):
            d = self._read(store, eid)
            self.assertIs(d["truncated"], True, d)
            self.assertEqual(store.verify(eid), (True, "ok"))  # ハッシュ一致でも全文ではない

    def test_shrink_path_marks_truncated(self):
        store = self._store(max_item_bytes=400)
        # 本文は上限内だが、ヘッダー込みの1件が上限を超える -> 本文省略
        eid = store.save_http_evidence(method="GET", url="http://x/", status=200,
                                       headers={f"X-H{i}": "v" * 50 for i in range(10)}, body="b" * 100)
        d = self._read(store, eid)
        self.assertIs(d["truncated"], True)
        self.assertTrue(d["omitted_reason"])
        self.assertEqual(store.verify(eid), (True, "ok"))

    def test_verify_detects_tamper_missing_legacy_and_bad_id(self):
        store = self._store()
        eid = store.save_http_evidence(method="GET", url="http://x/", status=200, body="orig")
        path = os.path.join(store.dir, f"{eid}.json")
        d = self._read(store, eid)
        d["body_excerpt"] = "tampered"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(d, f)
        self.assertEqual(store.verify(eid), (False, "hash_mismatch"))
        legacy = dict(d)
        legacy.pop("content_sha256")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(legacy, f)
        self.assertEqual(store.verify(eid), (False, "no_hash"))
        os.remove(path)
        self.assertEqual(store.verify(eid), (False, "missing"))
        for bad in ("../../etc/passwd", "", "a/b", None):
            self.assertEqual(store.verify(bad if bad is not None else ""), (False, "missing"))

    def test_existing_fields_unchanged(self):
        store = self._store()
        eid = store.save_http_evidence(method="POST", url="http://x/a", status=201,
                                       headers={"Content-Type": "text/html"}, body="hi",
                                       baseline_body="base")
        d = self._read(store, eid)
        for k in ("evidence_id", "method", "url", "status", "headers", "body_excerpt",
                  "baseline_excerpt", "timestamp", "omitted_reason"):
            self.assertIn(k, d)
        self.assertEqual((d["method"], d["status"], d["body_excerpt"], d["baseline_excerpt"]),
                         ("POST", 201, "hi", "base"))


if __name__ == "__main__":
    unittest.main()
