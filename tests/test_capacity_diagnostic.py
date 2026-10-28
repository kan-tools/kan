import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('diagnostic', Path(__file__).resolve().parents[1]/'scripts/capacity_diagnostic.py')
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class DiagnosticTests(unittest.TestCase):
    def test_orphan_and_missing_reference_reported_without_changing_archive(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'archive.sqlite'
            with sqlite3.connect(path) as db:
                db.executescript('CREATE TABLE objects(cid TEXT PRIMARY KEY, bytes BLOB); CREATE TABLE commits(sequence INTEGER PRIMARY KEY,cid TEXT UNIQUE); CREATE TABLE bindings(ciphertext TEXT,length INTEGER,first_manifest TEXT);')
                db.executemany('INSERT INTO objects VALUES (?,?)', [('retained',b'abc'),('orphan',b'xyz')])
                db.execute("INSERT INTO commits VALUES(1,'commit')")
                db.executemany('INSERT INTO bindings VALUES(?,?,?)',[('retained',3,'commit'),('missing',7,'absent')])
            before = path.read_bytes()
            checkpoints = []
            result = diagnostic.inspect(path, lambda s: checkpoints.append(s['last_completed_step'] if 'last_completed_step' in s else 'start'), 1)
            self.assertEqual(path.read_bytes(),before)
            self.assertEqual(result['steps']['objects_count'],2)
            self.assertLess(checkpoints.index('commits_count'),checkpoints.index('bindings'))
            self.assertEqual(result['steps']['bindings']['missing_objects'],['missing'])
            self.assertEqual(result['steps']['bindings']['missing_commits'],['absent'])
            self.assertEqual(result['steps']['bindings']['unreferenced_objects'],['orphan'])
            self.assertEqual(result['steps']['unreferenced_orphan']['bytes'],3)
            self.assertTrue(all('COVERING INDEX' in str(result['steps'][table+'_query_plan']) for table in ('objects','commits')))
            states=[]
            with self.assertRaisesRegex(ValueError,'bound exceeded'):
                diagnostic.inspect(path,lambda s:states.append(dict(s)),1,max_records=1)
            self.assertEqual(states[-1]['status'],'failed')
            self.assertEqual(states[-1]['steps']['commits_count'],1)

if __name__ == '__main__': unittest.main()
