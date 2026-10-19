#!/usr/bin/env python3
"""Independent digest oracle for tiny synthetic legacy SQLite fixtures.

This checks byte/CID commitments, not writer authorization, signatures, archive
completeness, or suitability for migration. Production code never invokes it.
"""
import hashlib, importlib.util, sqlite3, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('source_digest_reference',ROOT/'scripts/evidence_reference.py')
codec=importlib.util.module_from_spec(spec);sys.modules[spec.name]=codec;spec.loader.exec_module(codec)

def digest(path):
    conn=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True)
    conn.execute('BEGIN')
    records=conn.execute('SELECT sequence,manifest,receipt FROM commits ORDER BY sequence').fetchall()
    # Deliberately read in a different order so removing Python's lexical sort
    # is observable even though SQLite's WITHOUT ROWID table scans by CID.
    objects=sorted(conn.execute('SELECT cid,bytes FROM objects ORDER BY length(bytes) DESC,cid DESC').fetchall(),key=lambda row:row[0])
    value=hashlib.sha256(b'tools.kan.archive.copy-source.v1\0')
    def number(n):value.update(n.to_bytes(8,'big'))
    def frame(b):number(len(b));value.update(b)
    frame(b'commits');number(len(records))
    for expected,(sequence,manifest,receipt) in enumerate(records,1):
        assert sequence==expected
        m=codec.decode(manifest);codec.decode(receipt)
        object_id=m['body']['entries'][0]['ciphertext']
        assert isinstance(object_id,codec.Link)
        number(sequence);frame(manifest);frame(receipt);frame(object_id.raw)
    frame(b'objects');number(len(objects))
    for cid,body in objects:
        assert codec.cid(body,0x55)==cid
        frame(codec.cid_bytes(cid));number(len(body))
    conn.close();return value.hexdigest()
if __name__=='__main__':
    if not __debug__:raise RuntimeError('assertions required')
    if len(sys.argv)!=2:raise SystemExit('one synthetic SQLite source required')
    print(digest(sys.argv[1]))
