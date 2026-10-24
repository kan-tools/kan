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


if __name__ == '__main__': unittest.main()
