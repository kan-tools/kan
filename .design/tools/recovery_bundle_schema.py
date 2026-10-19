#!/usr/bin/env python3
"""Exercise the proposed KNB1 DDL in memory only; no production bundle writer.

This checks local SQL constraints, not canonical CIDs, signatures, whole-chain
coverage, profile membership, immutability, publication or durable storage.
"""
from pathlib import Path
import sqlite3
import unittest

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / '.design/fixtures/recovery-bundle-v1-schema.sql').read_text()


class DraftSchema(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.executescript(SQL)

    def tearDown(self):
        self.db.close()

    def reject(self, sql, parameters):
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(sql, parameters)

    def test_runtime_schema_matches_proposed_fixture(self):
        self.assertEqual((ROOT / "src/evidence_store/bundle.sql").read_text(), SQL)

    def test_outer_tables_are_exact_and_unpublished(self):
        actual = self.db.execute("SELECT type,name FROM sqlite_schema ORDER BY type,name").fetchall()
        self.assertEqual(actual, [('table', name) for name in sorted([
            'bundle_identity', 'member_records', 'member_objects', 'member_plan',
            'member_membership', 'observations', 'restored_objects'])])
        self.assertEqual(self.db.execute('PRAGMA application_id').fetchone()[0], 0)
        self.assertEqual(self.db.execute('PRAGMA user_version').fetchone()[0], 0)
        for absent in ('commits', 'attestations', 'objects', 'upgrade_plan'):
            with self.assertRaises(sqlite3.OperationalError):
                self.db.execute('SELECT * FROM '+absent)

    def test_original_empty_corruption_is_preserved_but_restoration_cannot_be_empty(self):
        self.db.execute('INSERT INTO member_objects VALUES(?,?)', ('fixture-key', b''))
        self.assertEqual(self.db.execute('SELECT bytes FROM member_objects').fetchone()[0], b'')
        self.reject('INSERT INTO restored_objects VALUES(?,?)', ('fixture-key', b''))
        self.db.execute('INSERT INTO restored_objects VALUES(?,?)', ('fixture-key', b'candidate'))
        self.assertEqual(self.db.execute('SELECT bytes FROM member_objects').fetchone()[0], b'')
        self.reject('INSERT INTO restored_objects VALUES(?,?)', ('fixture-key', b'other'))

    def test_blob_storage_classes_and_bounds(self):
        for table in ('member_objects', 'restored_objects'):
            for value in ('same-length-text', 123, 1.25, None, bytes(4194305)):
                self.reject('INSERT INTO '+table+' VALUES(?,?)', ('fixture-key', value))
            self.db.execute('INSERT INTO '+table+' VALUES(?,?)', ('fixture-key', bytes(4194304)))
        for table, limit in [('member_plan', 4096), ('observations', 16384)]:
            for value in ('text', 123, None, b'', bytes(limit+1)):
                self.reject('INSERT INTO '+table+' VALUES(?,?)', (1, value))
            self.db.execute('INSERT INTO '+table+' VALUES(?,?)', (1, bytes(limit)))

    def test_record_coordinates_and_each_blob_field(self):
        for sequence in (0, -1, 9007199254740992):
            self.reject('INSERT INTO member_records VALUES(?,?,?,?)', (sequence,b'm',b'r',b'p'))
        for index, limit in [(1,65536),(2,65536),(3,16384)]:
            for value in ('text',123,None,b'',bytes(limit+1)):
                row=[1,b'm',b'r',b'p']; row[index]=value
                self.reject('INSERT INTO member_records VALUES(?,?,?,?)', row)
        self.db.execute('INSERT INTO member_records VALUES(?,?,?,?)', (1,bytes(65536),bytes(65536),bytes(16384)))
        self.reject('INSERT INTO member_records VALUES(?,?,?,?)', (1,b'm',b'r',b'p'))

    def test_identifier_byte_bounds_ascii_and_embedded_nul(self):
        for value in ['é'*56, 'é'+'a'*55, 'a'*55+'\0', 'a'*55+'\n']:
            for field in (2,6):
                row=[1,bytes(32),'d'*56,2,bytes(32),bytes(32),'i'*56]
                row[field]=value
                self.reject('INSERT INTO bundle_identity VALUES(?,?,?,?,?,?,?)',row)
        for table in ('member_objects','restored_objects'):
            for key in ['é'*64, 'é'+'a'*127, 'x\0hidden','line\nbreak','has space']:
                self.reject('INSERT INTO '+table+' VALUES(?,?)',(key,b'x'))
            with self.assertRaises(sqlite3.IntegrityError):
                self.db.execute("INSERT INTO "+table+" VALUES(CAST(X'FF' AS TEXT),X'01')")
        for key in ['é'*64,'x\0hidden','line\nbreak']:
            self.reject('INSERT INTO member_membership VALUES(?,?)',(key,1))

    def test_identity_and_membership_local_shapes(self):
        identity=[1,bytes(32),'d'*56,2,bytes(32),bytes(32),'i'*56]
        for index, values in [(0,[0,2]),(1,[b'',bytes(33),'x'*32]),(2,['x'*55,'x'*81]),(3,[1,4]),(4,[bytes(31),'x'*32]),(5,[bytes(33),'x'*32]),(6,['x'*55,'x'*81])]:
            for value in values:
                row=identity.copy(); row[index]=value
                self.reject('INSERT INTO bundle_identity VALUES(?,?,?,?,?,?,?)',row)
        self.db.execute('INSERT INTO bundle_identity VALUES(?,?,?,?,?,?,?)',identity)
        self.reject('INSERT INTO bundle_identity VALUES(?,?,?,?,?,?,?)',identity)
        for value in (0,-1,4194305,None,b'12',1.25):
            self.reject('INSERT INTO member_membership VALUES(?,?)',('fixture-key',value))
        self.db.execute('INSERT INTO member_membership VALUES(?,?)',('fixture-key',4194304))


if __name__ == '__main__':
    unittest.main(verbosity=2)
