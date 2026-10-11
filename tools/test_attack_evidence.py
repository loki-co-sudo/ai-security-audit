"""ATTACK MODEの偵察観測の証拠保存・サマリーへのID埋め込み・マスキングを検証する(P1.2)。"""
import json
import tempfile
import unittest
from pathlib import Path

from agents.recon_agent import ReconAgent, _EVIDENCE_INSTRUCTION
from core import redaction
from core.event_bus import EventBus
from core.evidence_store import EvidenceStore
from tools import report_generator as reports

COOKIE_SECRET = "SETCOOKIE_SECRET_Qw81"
RECON = {
    "target": "http://t.local", "host": "t.local", "ip": "10.0.0.5",
    "ports": [{"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.9"},
              {"port": 80, "service": "http", "banner": ""}],
    "udp_ports": [{"port": 53, "service": "dns", "banner": ""}],
    "subdomains": ["dev.t.local"],
    "web": {"url": "http://t.local/", "headers": {"Server": "nginx/1.18",
                                                  "Set-Cookie": f"sid={COOKIE_SECRET}; HttpOnly"},
            "technologies": ["nginx"], "missing_headers": ["Content-Security-Policy"],
            "found_paths": [{"path": "/admin", "status": 403}]},
}


def _agent():
    return ReconAgent(EventBus(), None)


class AttackEvidenceTest(unittest.TestCase):
    def test_saves_observations_and_tags_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore("scan_aaaaaaaaaaaa", root=str(Path(tmp) / "ev"))
            a = _agent()
            ids = a._save_recon_evidence(store, RECON)
            self.assertEqual(set(ids), {("tcp", 22), ("tcp", 80), ("udp", 53), "headers",
                                        ("path", "/admin"), ("sub", "dev.t.local")})
            self.assertEqual(store.count, 6)
            raw = "".join(p.read_text(encoding="utf-8") for p in (Path(tmp) / "ev").rglob("*.json"))
            self.assertNotIn(COOKIE_SECRET, raw)  # Set-Cookieは保存前にマスク
            self.assertIn("SSH-2.0-OpenSSH_8.9", raw)  # 通常のバナーは残る
            d = json.loads((Path(tmp) / "ev" / "scan_aaaaaaaaaaaa" / f"{ids[('tcp', 22)]}.json").read_text(encoding="utf-8"))
            self.assertEqual((d["kind"], d["category"], d["target_ref"]), ("observation", "port", "t.local:22/tcp"))
            summary = a._build_recon_summary(RECON, None, ids)
            for eid in ids.values():
                self.assertIn(f"evidence_id={eid}", summary)
            # 証拠保存OFF相当(ids空)ではタグが付かない
            self.assertNotIn("evidence_id=", a._build_recon_summary(RECON, None, {}))
            self.assertNotIn("evidence_id=", a._build_recon_summary(RECON, None))

    def test_summary_masked_before_llm(self):
        masked = redaction.mask_log_line(_agent()._build_recon_summary(RECON))
        self.assertNotIn(COOKIE_SECRET, masked)
        self.assertIn("nginx/1.18", masked)

    def test_cited_ids_adopted_unknown_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore("scan_aaaaaaaaaaaa", root=str(Path(tmp) / "ev"))
            ids = _agent()._save_recon_evidence(store, RECON)
            real = ids[("tcp", 22)]
            text = ("---FINDING_START---\nTITLE: Old SSH\nSEVERITY: MEDIUM\nCATEGORY: Network\n"
                    f"EVIDENCE_IDS: {real}, evidence_bogus_9\nEVIDENCE: SSH banner\n"
                    "ATTACK_SCENARIO:\nx\nRECOMMENDED_ACTION:\ny\n---FINDING_END---\n")
            parsed, _ = reports._findings_and_counts("ATTACK MODE", text)
            rej = []
            f = ReconAgent._findings_from_markers(parsed, corroborated=False,
                                                  known_evidence_ids=set(ids.values()),
                                                  rejected_evidence_ids=rej)[0]
            self.assertEqual(f.evidence_ids, [real])
            self.assertTrue(any("evidence_bogus_9" in r for r in rej))
            self.assertEqual(f.location, "SSH banner")  # 既存のEVIDENCE欄の解釈は不変

    def test_cap_overflow_is_reported_and_instruction_is_conditional(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore("scan_aaaaaaaaaaaa", root=str(Path(tmp) / "ev"), max_items=2)
            ids = _agent()._save_recon_evidence(store, RECON)
            self.assertEqual(len(ids), 2)
            self.assertTrue(any("件数上限" in o for o in store.omissions))
        self.assertIn("EVIDENCE_IDS", _EVIDENCE_INSTRUCTION)

    def test_report_links_observation_evidence(self):
        from core.findings import Finding, new_scan_result
        with tempfile.TemporaryDirectory() as tmp:
            r = new_scan_result("ATTACK", "http://t.local")
            store = EvidenceStore(r.scan_id, root=str(Path(tmp) / "evidence"))
            ids = _agent()._save_recon_evidence(store, RECON)
            r.findings = [Finding("f", "Network", "SSH banner", "MEDIUM", evidence_ids=[ids[("tcp", 22)]],
                                  description="Old SSH")]
            html = reports.generate("ATTACK MODE", "x", "", scan_result=r)
            self.assertIn(f"evidence/{r.scan_id}/{ids[('tcp', 22)]}.json", html)


if __name__ == "__main__":
    unittest.main()
