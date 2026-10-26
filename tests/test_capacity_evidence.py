import copy
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('capacity_evidence', Path(__file__).resolve().parents[1] / 'scripts/capacity_evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceTests(unittest.TestCase):
    def test_seed_frontier_accepts_actual_libtest_output_and_rejects_ambiguity(self):
        actual = ("\nrunning 1 test\n"
                  "test capacity_measurements::capacity_worker ... KAN_CAPACITY_FRONTIER=40139\n"
                  "ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                  "95 filtered out; finished in 185.70s\n")
        self.assertEqual(evidence.seed_frontier(actual.splitlines()), 40139)
        self.assertEqual(evidence.seed_frontier(['KAN_CAPACITY_FRONTIER=40139']), 40139)
        for lines in ([], ['KAN_CAPACITY_FRONTIER='], ['KAN_CAPACITY_FRONTIER=-1'],
                      ['KAN_CAPACITY_FRONTIER=40139junk'],
                      ['KAN_CAPACITY_FRONTIER=40139', 'KAN_CAPACITY_FRONTIER=40139'],
                      ['KAN_CAPACITY_FRONTIER=1 KAN_CAPACITY_FRONTIER=2']):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                evidence.seed_frontier(lines)

    def test_nested_attempt_logs_survive_without_copying_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'fixture'; root.mkdir()
            out = Path(temp) / 'results'
            (root / 'attempts' / 'one').mkdir(parents=True)
            (root / 'attempts' / 'one' / 'append.log').write_text('sample')
            (root / 'archive').mkdir()
            (root / 'archive' / 'archive.sqlite').write_bytes(b'not evidence')
            (root / 'archive' / 'ignored.json').write_text('also not evidence')
            (root / 'report.json').write_text('{}')
            evidence.retain_logs(root, out)
            self.assertEqual((out / 'attempts' / 'one' / 'append.log').read_text(), 'sample')
            self.assertTrue((out / 'report.json').exists())
            self.assertFalse((out / 'archive').exists())

    def test_full_read_detects_changed_missing_and_extra_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            file = root / 'archive'; file.write_bytes(b'original')
            expected = evidence.snapshot(root)
            self.assertEqual(evidence.verify_snapshot(root, expected)['bytes_read'], 8)
            file.write_bytes(b'changed!')
            with self.assertRaises(ValueError): evidence.verify_snapshot(root, expected)
            file.unlink()
            with self.assertRaises(ValueError): evidence.verify_snapshot(root, expected)
            file.write_bytes(b'original'); (root / 'extra').write_bytes(b'extra')
            with self.assertRaises(ValueError): evidence.verify_snapshot(root, expected)

    def test_symlinks_cannot_substitute_external_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'link').symlink_to('/etc/hosts')
            with self.assertRaises(ValueError): evidence.snapshot(root)

    def test_missing_duplicate_and_excess_rss_samples_rejected(self):
        report = {'status':'complete', 'opaque_payload_gib':100, 'samples_per_operation':8,
                  'chunk_bytes':1024**2, 'fixture_file_bytes':100*evidence.GIB,
                  'samples':[{'operation':op, 'process_peak_rss_kib':1024}
                             for op in ('open','append','page','source') for _ in range(8)]}
        evidence.validate_report(report,100,8)
        for mutation in ('missing','duplicate','rss','nonfinite','small','failed'):
            bad = copy.deepcopy(report)
            if mutation == 'missing': bad['samples'].pop()
            if mutation == 'duplicate': bad['samples'][0]['operation']='append'
            if mutation == 'rss': bad['samples'][0]['process_peak_rss_kib']=512*1024+1
            if mutation == 'nonfinite': bad['samples'][0]['process_peak_rss_kib']=float('nan')
            if mutation == 'small': bad['fixture_file_bytes']=1
            if mutation == 'failed': bad['status']='failed'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                evidence.validate_report(bad,100,8)

    def test_archive_counts_bytes_and_uncheckpointed_wal(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'archive.sqlite'
            with sqlite3.connect(path) as db:
                db.executescript('CREATE TABLE commits(sequence INTEGER); CREATE TABLE objects(bytes BLOB);')
                db.execute('INSERT INTO commits VALUES (1)');db.execute('INSERT INTO objects VALUES (?)',(b'payload',))
            self.assertEqual(evidence.inspect_archive(path,1,7)['objects'],1)
            for count,size in [(2,7),(1,8)]:
                with self.assertRaises(ValueError): evidence.inspect_archive(path,count,size)
            Path(str(path)+'-wal').write_bytes(b'pending')
            with self.assertRaises(ValueError): evidence.inspect_archive(path,1,7)


class PeakAccountingTests(unittest.TestCase):
    source = 'getrusage(RUSAGE_CHILDREN).ru_maxrss:linux-kib:fresh-supervisor'

    def test_external_peak_cannot_replace_native_or_missing_evidence(self):
        sample = {'rss_source':'pending-external-rusage','process_peak_rss_kib':None}
        usage = {'status':'complete','source':self.source,'returncode':0,
                 'calibration':False,'process_peak_rss_kib':512*1024}
        good = dict(sample); evidence.attach_peak(good,usage)
        self.assertEqual(good['process_peak_rss_kib'],512*1024)
        for key,value in [('status','failed'),('returncode',101),('source','current-rss'),
                          ('calibration',True),('process_peak_rss_kib',0),
                          ('process_peak_rss_kib',None),('process_peak_rss_kib',512*1024+1)]:
            with self.subTest(key=key,value=value), self.assertRaises(ValueError):
                evidence.attach_peak(dict(sample),dict(usage,**{key:value}))
        with self.assertRaises(ValueError): evidence.attach_peak(good,usage)

    def test_calibration_requires_allocation_release_and_retained_peak(self):
        probe = {'before_rss_kib':16000,'during_rss_kib':81536,'after_rss_kib':16000,
                 'during_peak_kib':81536,'after_peak_kib':81536}
        report = {'source':self.source,'returncode':0,'calibration':True,
                  'process_peak_rss_kib':81536,'allocation_probe':probe}
        evidence.validate_peak_calibration(report)
        for key,value in [('during_rss_kib',16000),('after_rss_kib',81536),
                          ('after_peak_kib',16000),('during_peak_kib',0)]:
            bad = copy.deepcopy(report);bad['allocation_probe'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): evidence.validate_peak_calibration(bad)
        with self.assertRaises(ValueError): evidence.validate_peak_calibration({})

    @unittest.skipUnless(__import__('sys').platform == 'linux', 'Linux kernel RSS units required')
    def test_supervisor_calibrates_then_isolates_next_child(self):
        import json, subprocess, sys
        script=Path(__file__).resolve().parents[1]/'scripts/capacity_rss.py'
        with tempfile.TemporaryDirectory() as temp:
            first=Path(temp)/'calibration.json';second=Path(temp)/'small.json'
            subprocess.run([sys.executable,str(script),'--output',str(first),'--calibrate'],check=True)
            subprocess.run([sys.executable,str(script),'--output',str(second),'--',sys.executable,'-c','pass'],check=True)
            big=json.loads(first.read_text());small=json.loads(second.read_text())
            evidence.validate_peak_calibration(big)
            self.assertGreater(big['process_peak_rss_kib']-small['process_peak_rss_kib'],32*1024)


class ResumeTests(unittest.TestCase):
    def test_incomplete_attempt_preserved_and_revision_mismatch_rejected(self):
        import json
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old = {'source_revision':'a'*40, 'opaque_payload_gib':100,
                   'samples_per_operation':32, 'status':'running',
                   'samples':[{'operation':'append'}]}
            evidence.atomic_json(root/'report.json',old)
            attempt = evidence.prepare_attempt(root,'a'*40,100,32,True)
            self.assertEqual(json.loads((attempt/'prior-report.json').read_text()),old)
            self.assertEqual(json.loads((root/'report.json').read_text()),old)
            with self.assertRaises(ValueError): evidence.prepare_attempt(root,'b'*40,100,32,True,True)
            with self.assertRaises(ValueError): evidence.prepare_attempt(root,'a'*40,10,32,True)

    def test_only_explicit_unsampled_legacy_prefix_can_be_adopted(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            old={'opaque_payload_gib':100,'samples_per_operation':32,'status':'running','samples':[]}
            evidence.atomic_json(root/'report.json',old)
            with self.assertRaises(ValueError): evidence.prepare_attempt(root,'a'*40,100,32,True)
            self.assertIsNotNone(evidence.prepare_attempt(root,'a'*40,100,32,True,True))
            (root/'report.json').unlink();(root/'archive').mkdir()
            with self.assertRaises(ValueError): evidence.prepare_attempt(root,'a'*40,100,32,True,True)

    def test_unmeasured_append_accounting_and_completed_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            report={'version':3,'source_revision':'a'*40,'status':'complete',
                    'opaque_payload_gib':100,'samples_per_operation':8,'chunk_bytes':1024**2,
                    'fixture_file_bytes':100*evidence.GIB,'seeded_records':102400,
                    'baseline_records':102403,'unmeasured_append_records':3,'expected_records':102411,
                    'samples':[{'operation':op,'process_peak_rss_kib':1024}
                               for op in ('open','append','page','source') for _ in range(8)]}
            evidence.atomic_json(root/'report.json',report)
            self.assertIsNone(evidence.prepare_attempt(root,'a'*40,100,8,True))
            report['expected_records']=102408
            with self.assertRaises(ValueError): evidence.validate_report(report,100,8)


if __name__ == '__main__': unittest.main()
