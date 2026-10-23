"""確定所見から各レポートとGUI出力への配線を検証する。"""
import json
import os
import shutil
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
            self.assertEqual(f['evidence'], [{'evidence_id': eid, 'path': f'evidence/{result.scan_id}/{eid}.json',
                                          # 保存先を指定しない生成は検査不能(旧契約のid/pathに、検査結果の3項目を追加)
                                          'integrity': 'unchecked', 'completeness': 'unknown',
                                          'reason': 'evidence_root_not_specified'},
                                         # 形式不正の参照('../../bad')は、リンクは作らないが不正な参照があった事実を残す(旧: 黙って消えた)
                                         {'evidence_id': '??????bad', 'path': None,
                                          'integrity': 'invalid_reference', 'completeness': 'unknown',
                                          'reason': 'bad_id_format'}])
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


class EvidenceIntegrityReportTest(unittest.TestCase):
    """通常レポートの証拠健全性: 保存物の整合性(integrity)と取得内容の完全性(completeness)を別軸で、全形式に同じ意味で出す。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = str(Path(self.tmp.name) / 'evidence')
        self.result = new_scan_result('WEB FUZZ', 'http://localhost/')
        self.store = EvidenceStore(self.result.scan_id, root=self.root)
        self.ids = {}
        self.ids['ok'] = self.store.save_http_evidence(method='GET', url='http://localhost/a', status=200, body='full')
        self.ids['truncated'] = self.store.save_http_evidence(method='GET', url='http://localhost/b', status=200, body='p',
                                                               source_incomplete='response:read_error')
        self.ids['mismatch'] = self.store.save_http_evidence(method='GET', url='http://localhost/c', status=200, body='x')
        self.ids['nohash'] = self.store.save_http_evidence(method='GET', url='http://localhost/d', status=200, body='y')
        self.ids['corrupt'] = self.store.save_http_evidence(method='GET', url='http://localhost/e', status=200, body='z')
        self.ids['missing'] = 'evidence_000000000000'
        self.ids['symlink'] = 'evidence_111111111111'
        d = Path(self.root) / self.result.scan_id
        p = d / f"{self.ids['mismatch']}.json"
        data = json.loads(p.read_text(encoding='utf-8'))
        data['body_excerpt'] = 'TAMPERED'
        p.write_text(json.dumps(data), encoding='utf-8')
        p = d / f"{self.ids['nohash']}.json"
        data = json.loads(p.read_text(encoding='utf-8'))
        data.pop('content_sha256')
        p.write_text(json.dumps(data), encoding='utf-8')
        (d / f"{self.ids['corrupt']}.json").write_text('{not json', encoding='utf-8')
        outside = Path(self.tmp.name) / 'outside.json'
        outside.write_text('{}', encoding='utf-8')
        os.symlink(outside, d / f"{self.ids['symlink']}.json")
        self.result.findings = [Finding('f%d' % i, 'CWE-79', '/q%d' % i, 'HIGH', evidence_ids=[eid], description='d%d' % i)
                                for i, eid in enumerate(self.ids.values())]
        self.expected = {'ok': ('ok', 'complete'), 'truncated': ('ok', 'truncated'), 'mismatch': ('hash_mismatch', 'unknown'),
                         'nohash': ('no_hash', 'unknown'), 'corrupt': ('unreadable', 'unknown'),
                         'missing': ('missing', 'unknown'), 'symlink': ('invalid_reference', 'unknown')}

    def _snapshot(self):
        out = {}
        for p in sorted(Path(self.tmp.name).rglob('*')):
            if p.is_file() and not p.is_symlink():
                out[str(p)] = (p.stat().st_mtime_ns, p.read_bytes())
            else:
                out[str(p)] = ('link' if p.is_symlink() else 'dir',)
        return out

    def _args(self, root):
        return dict(mode='m', target='t', raw_text='', scan_result=self.result, evidence_root=root)

    def test_every_state_is_reported_the_same_way_in_all_formats(self):
        before = self._snapshot()
        args = self._args(self.root)
        html_out, md = reports.generate(**args), reports.generate_markdown(**args)
        doc = json.loads(reports.generate_json(**args))
        with patch('tools.pdf_writer.render', return_value=b'pdf') as render:
            reports.generate_pdf(**args)
            pdf_findings = render.call_args.kwargs['findings']
        self.assertEqual(len(doc['findings']), len(self.ids))                 # 欠落・改変があっても所見は消さない
        for key, (integrity, completeness) in self.expected.items():
            eid = self.ids[key]
            label = f'integrity={integrity}; completeness={completeness}'
            self.assertIn(label, html_out, key)
            self.assertIn(label, md, key)
            j = next(e for f in doc['findings'] for e in f['evidence'] if e['evidence_id'] == eid)
            self.assertEqual((j['integrity'], j['completeness']), (integrity, completeness), key)
            pc = next(c for f in pdf_findings for c in f['evidence_checks'] if c['evidence_id'] == eid)
            self.assertEqual((pc['integrity'], pc['completeness']), (integrity, completeness), key)
        self.assertTrue(doc['evidence_inspection']['performed'])
        self.assertTrue(doc['evidence_inspection']['checked_at'])
        self.assertIn('Evidence inspection: performed at', md)
        self.assertEqual(self._snapshot(), before)                            # 読み取り専用: 作成・修復・書換えをしない
        self.assertFalse((Path(self.root) / self.result.scan_id / f"{self.ids['missing']}.json").exists())
        for out in (md, json.dumps(doc, ensure_ascii=False)):
            self.assertNotIn(self.tmp.name, out)                               # 保存先の絶対パスを出力へ出さない

    def test_hash_ok_is_not_presented_as_semantic_correctness_or_full_text(self):
        md = reports.generate_markdown(**self._args(self.root))
        self.assertIn(f"integrity=ok; completeness=truncated", md)            # ハッシュ一致でも切り詰めはあり得る
        self.assertIn('does NOT mean the finding is correct or that the full original text exists', md)

    def test_unspecified_root_is_unchecked_not_ok(self):
        args = self._args(None)
        doc = json.loads(reports.generate_json(**args))
        self.assertFalse(doc['evidence_inspection']['performed'])
        self.assertIsNone(doc['evidence_inspection']['checked_at'])
        self.assertTrue(all(e['integrity'] == 'unchecked' and e['completeness'] == 'unknown'
                            for f in doc['findings'] for e in f['evidence']))
        md = reports.generate_markdown(**args)
        self.assertIn('Evidence inspection: not performed', md)
        self.assertNotIn('integrity=ok', md)

    def test_moved_report_uses_the_explicit_root_not_cwd(self):
        moved = str(Path(self.tmp.name) / 'moved')
        shutil.copytree(self.root, moved, symlinks=True)
        shutil.rmtree(self.root)
        cwd_before = os.getcwd()
        doc = json.loads(reports.generate_json(**self._args(moved)))
        self.assertEqual(os.getcwd(), cwd_before)
        first = doc['findings'][0]['evidence'][0]
        self.assertEqual((first['integrity'], first['completeness']), ('ok', 'complete'))
        gone = json.loads(reports.generate_json(**self._args(self.root)))     # 旧い場所を指定すれば missing
        self.assertEqual(gone['findings'][0]['evidence'][0]['integrity'], 'missing')

    def test_inspect_rejects_malformed_references_without_touching_disk(self):
        from core.evidence_store import inspect_evidence
        for scan, eid in ((self.result.scan_id, '../../bad'), ('../x', self.ids['ok']), ('', ''), (None, None)):
            r = inspect_evidence(self.root, scan, eid)
            self.assertEqual(r['integrity'], 'invalid_reference', (scan, eid))

    def test_pdf_renders_with_checks(self):
        data = reports.generate_pdf(**self._args(self.root))
        self.assertTrue(data.startswith(b'%PDF'))

    def test_malformed_references_are_reported_as_invalid_not_silently_dropped(self):
        bad_ids = ['../../bad', 'evidence_ZZZZ', '', 'x' * 200 + '<script>']
        self.result.findings = [Finding('fx', 'CWE-79', '/q', 'HIGH', evidence_ids=[self.ids['ok']] + bad_ids,
                                        description='with bad refs')]
        args = self._args(self.root)
        html_out, md = reports.generate(**args), reports.generate_markdown(**args)
        doc = json.loads(reports.generate_json(**args))
        ev = doc['findings'][0]['evidence']
        self.assertEqual(len(ev), 1 + len(bad_ids))                          # 不正な参照も件数に残る
        invalid = [e for e in ev if e['integrity'] == 'invalid_reference']
        self.assertEqual(len(invalid), len(bad_ids))
        self.assertTrue(all(e['path'] is None and e['completeness'] == 'unknown' for e in invalid))
        self.assertTrue(all(len(e['evidence_id']) <= 40 for e in invalid))
        self.assertEqual(ev[0]['integrity'], 'ok')                          # 正しい参照の検査は影響を受けない
        for out in (html_out, md):
            self.assertEqual(out.count('integrity=invalid_reference; completeness=unknown]'), len(bad_ids))   # 各所見の証拠欄(要約行の分は含めない)
            self.assertNotIn('../../bad', out)                              # 元の文字列(パス区切り・タグ)は出さずリンクも作らない
            self.assertNotIn('<script>', out)
        with patch('tools.pdf_writer.render', return_value=b'pdf') as render:
            reports.generate_pdf(**args)
            checks = render.call_args.kwargs['findings'][0]['evidence_checks']
        self.assertEqual([c['integrity'] for c in checks].count('invalid_reference'), len(bad_ids))

    def test_inspect_distinguishes_bad_format_from_symlink_escape(self):
        from core.evidence_store import inspect_evidence
        fmt = inspect_evidence(self.root, self.result.scan_id, '../../bad')
        link = inspect_evidence(self.root, self.result.scan_id, self.ids['symlink'])
        self.assertEqual((fmt['integrity'], fmt['reason']), ('invalid_reference', 'bad_id_format'))
        self.assertEqual((link['integrity'], link['reason']), ('invalid_reference', 'outside_root_or_symlink'))


class ResultNoticeTest(unittest.TestCase):
    """GUI: partial・証拠不足などの注意が、レポートを開かなくても出力欄に出る(実装レビュー再指摘)。"""

    def _result(self, state, errors, coverage=()):
        r = new_scan_result('WEB FUZZ', 'http://localhost/').to_dict()
        r.update(state=state, errors=list(errors), coverage=list(coverage))
        return r

    def test_pure_notice_for_partial_with_evidence_warnings(self):
        from gui import result_notice
        lines = result_notice.notice_lines(self._result(
            'partial', ['証拠の本文が不完全: GET http://x/?token=***', '検査単位2件が未完了です'],
            [{'status': 'skipped'}, {'status': 'tested'}]))
        text = ''.join(t for t, _ in lines)
        self.assertIn('一部完了(partial)・注意2件', text)
        self.assertIn('未検査/失敗の検査単位1件', text)
        self.assertIn('証拠の本文が不完全', text)
        self.assertEqual(lines[0][1], 'high')

    def test_clean_completion_and_non_dict_show_nothing_and_many_errors_are_summarised(self):
        from gui import result_notice
        self.assertEqual(result_notice.notice_lines(self._result('completed', [])), [])
        self.assertEqual(result_notice.notice_lines(None), [])
        many = result_notice.notice_lines(self._result('failed', [f'e{i}' for i in range(20)]))
        self.assertIn('ほか12件', ''.join(t for t, _ in many))
        self.assertIn('失敗(failed)', many[0][0])

    def test_dummy_secret_does_not_appear_in_the_notice(self):
        from gui import result_notice
        text = ''.join(t for t, _ in result_notice.notice_lines(self._result(
            'partial', ['request failed: http://x/a?token=DUMMY_SECRET_9&q=1'])))
        self.assertNotIn('DUMMY_SECRET_9', text)

    def test_all_four_panels_append_the_notice_on_result(self):
        from gui.panels.audit_panel import AuditPanel
        from gui.panels.attack_panel import AttackPanel
        from gui.panels.fuzz_panel import FuzzPanel
        from gui.panels.defense_panel import DefensePanel
        for panel in (AuditPanel, AttackPanel, FuzzPanel, DefensePanel):
            obj = SimpleNamespace(_path=Mock(), _target_entry=Mock(), _log_path=Mock(),
                                  _out_box=Mock(), _llm=Mock(), _steps_widget=Mock(), _sys_log=Mock())
            payload = self._result('partial', ['証拠の本文が不完全: x'])
            panel.dispatch(obj, ev.Event(ev.RESULT, payload))
            shown = ''.join(c.args[0] for c in obj._out_box.append.call_args_list)
            self.assertIn('注意1件', shown, panel.__name__)
            self.assertIn('証拠の本文が不完全', shown, panel.__name__)
            self.assertIs(obj._scan_result, payload)


if __name__ == '__main__':
    unittest.main()
