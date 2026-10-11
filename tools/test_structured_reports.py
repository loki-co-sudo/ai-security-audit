"""確定所見から各レポートとGUI出力への配線を検証する。"""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from core.findings import Finding, new_scan_result
from core.evidence_store import EvidenceStore
from core import event_bus as ev
from tools import report_generator as reports


class StructuredReportsTest(unittest.TestCase):
    def test_final_findings_and_references(self):
        result = new_scan_result('WEB FUZZ', 'original-target')
        result.state = 'partial'
        result.errors = ['budget exhausted']
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(result.scan_id, root=str(Path(tmp) / 'evidence'))
            eid = store.save_http_evidence(method='GET', url='http://localhost/', status=200)
            result.findings = [Finding('f', 'CWE-79', '/q', 'HIGH', evidence_ids=[eid, '../../bad'],
                                       description='<script>alert(1)</script>', snippet='code sample',
                                       analysis='analysis sample')]
            raw = 'DRAFT_SENTINEL\n---VULN_START---\nNAME: duplicate\nSEVERITY: CRITICAL\n---VULN_END---'
            args = dict(mode='changed', target='changed', raw_text=raw, scan_result=result)
            html = reports.generate(**args)
            md = reports.generate_markdown(**args)
            for output in (html, md):
                self.assertNotIn('DRAFT_SENTINEL', output)
                self.assertNotIn('../../bad', output)
                self.assertNotIn('<script>', output)
                self.assertIn('original-target' if output == html else r'original\-target', output)
                self.assertIn('partial', output)
                self.assertIn('budget exhausted', output)
                self.assertIn('code sample', output)
                self.assertIn('analysis sample', output)
                self.assertIn(f'evidence/{result.scan_id}/{eid}.json', output)
            self.assertTrue((Path(tmp) / 'evidence' / result.scan_id / f'{eid}.json').is_file())
            with patch('tools.pdf_writer.render', return_value=b'pdf') as render:
                reports.generate_pdf(**args)
                data = render.call_args.kwargs
                self.assertEqual(data['counts']['CRITICAL'], 0)
                self.assertEqual(data['counts']['HIGH'], 1)
                self.assertEqual(data['findings'][0]['evidence_refs'][0][0], eid)
                self.assertIn('partial', data['raw_text'])
            self.assertTrue(reports.generate_pdf(**args).startswith(b'%PDF'))
            result.findings = []
            self.assertNotIn('duplicate', reports.generate(**args))
            self.assertNotIn('duplicate', reports.generate_markdown(**args))

    def test_panels_forward_result(self):
        from gui.panels.audit_panel import AuditPanel
        from gui.panels.attack_panel import AttackPanel
        from gui.panels.fuzz_panel import FuzzPanel
        from gui.panels.defense_panel import DefensePanel
        for panel in (AuditPanel, AttackPanel, FuzzPanel, DefensePanel):
            obj = SimpleNamespace(_path=Mock(), _target_entry=Mock(), _log_path=Mock(),
                                  _out_box=Mock(), _llm=Mock(), _steps_widget=Mock(), _sys_log=Mock())
            payload = new_scan_result('test', 'target').to_dict()
            panel.dispatch(obj, ev.Event(ev.RESULT, payload))
            self.assertIs(obj._scan_result, payload)
            for method, exporter in (('_export_report', 'export_html'),
                                     ('_export_pdf', 'export_pdf'),
                                     ('_export_markdown', 'export_markdown'),
                                     ('_export_json', 'export_json')):
                with patch('gui.export_util.' + exporter) as output:
                    getattr(panel, method)(obj)
                    self.assertIs(output.call_args.kwargs['scan_result'], payload)

    def test_common_export_and_legacy(self):
        from gui import export_util
        result = new_scan_result('AUDIT', 'source.py')
        with patch('gui.export_util._open'), patch.object(reports, 'save', return_value='report.html'), patch.object(reports, 'generate', return_value='html') as generate:
            export_util.export_html('old', 'old', 'draft', 'model', 'slug', Mock(), scan_result=result)
            self.assertIs(generate.call_args.kwargs['scan_result'], result)
        legacy = '---VULN_START---\nNAME: legacy\nSEVERITY: LOW\n---VULN_END---'
        self.assertIn('legacy', reports.generate('AUDIT', 'target', legacy))
        self.assertIn('unknown (legacy report)', reports.generate('AUDIT', 'target', legacy))

    def test_json_report(self):
        import json
        result = new_scan_result('WEB FUZZ', 'http://t.local')
        result.state = 'partial'
        result.errors = ['budget exhausted']
        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(result.scan_id, root=str(Path(tmp) / 'evidence'))
            eid = store.save_http_evidence(method='GET', url='http://t.local/', status=200)
            result.findings = [Finding('f1', 'CWE-79', '/q', 'HIGH', evidence_ids=[eid, '../../bad'],
                                       description='<script>x</script>', snippet='snip',
                                       analysis='ana', remediation='fix it')]
            doc = json.loads(reports.generate_json('changed', 'changed', 'DRAFT_SENTINEL', scan_result=result))
            self.assertEqual((doc['schema'], doc['schema_version'], doc['legacy']), ('ai-security-audit-report', '1', False))
            self.assertEqual((doc['mode'], doc['target'], doc['state']), ('WEB FUZZ', 'http://t.local', 'partial'))
            self.assertEqual(doc['errors'], ['budget exhausted'])
            self.assertEqual(doc['counts']['HIGH'], 1)
            self.assertEqual(doc['suppressed'], 0)
            f = doc['findings'][0]
            self.assertEqual((f['rule_id'], f['snippet'], f['analysis'], f['remediation']),
                             ('CWE-79', 'snip', 'ana', 'fix it'))
            # 検証を通った証拠参照だけが出る（不正IDは出さない）。下書きは再集計しない
            self.assertEqual(f['evidence'], [{'evidence_id': eid, 'path': f'evidence/{result.scan_id}/{eid}.json'}])
            self.assertNotIn('DRAFT_SENTINEL', json.dumps(doc))
            self.assertNotIn('../../bad', json.dumps(doc))
            path = reports.save_json(json.dumps(doc), 'WEB FUZZ', reports_dir=str(Path(tmp) / 'reports'))
            self.assertTrue(path.endswith('.json') and Path(path).is_file())

    def test_json_report_legacy(self):
        import json
        legacy = '---VULN_START---\nNAME: legacy\nSEVERITY: LOW\n---VULN_END---'
        doc = json.loads(reports.generate_json('AUDIT', 'target', legacy))
        self.assertTrue(doc['legacy'])
        self.assertEqual(doc['evidence_coverage'], 'unknown')
        self.assertEqual(doc['findings'][0]['description'], 'legacy')
        self.assertEqual(doc['findings'][0]['evidence'], [])


if __name__ == '__main__':
    unittest.main()
