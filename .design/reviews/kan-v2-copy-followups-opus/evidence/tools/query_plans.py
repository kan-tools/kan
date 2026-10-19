"""EXPLAIN QUERY PLAN for the copy_batch read paths on an in-memory schema copy."""
import sqlite3
c = sqlite3.connect(":memory:")
c.executescript("""
CREATE TABLE objects(cid TEXT PRIMARY KEY, bytes BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE commits(sequence INTEGER PRIMARY KEY, cid TEXT NOT NULL UNIQUE, manifest BLOB, receipt BLOB);
""")
print("sqlite", sqlite3.sqlite_version)
for label, q in [
    ("Ledger::read_object (copy_batch src/dst, copy_upgrade:62)", "SELECT bytes FROM objects WHERE cid=?"),
    ("RecoveryReader::read_object (NOT used by copy_batch)", "SELECT length(bytes),substr(bytes,1,4194304) FROM objects NOT INDEXED WHERE +cid=?"),
    ("RecoveryReader::record (copy_batch record prefix)", "SELECT sequence,length(manifest),substr(manifest,1,65536),length(receipt),substr(receipt,1,65536) FROM commits NOT INDEXED WHERE sequence=?"),
    ("copy_batch source object walk", "SELECT cid,length(bytes) FROM objects ORDER BY cid"),
]:
    plan = c.execute("EXPLAIN QUERY PLAN " + q, ("x",) if "?" in q else ()).fetchall()
    print(label, "->", [r[-1] for r in plan])
