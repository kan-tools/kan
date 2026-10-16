#!/usr/bin/env python3
"""Independent SQLite/CBOR/CID verification of an isolated kan v2 backup.

No Rust invocation, trust-filtered CLI inventory, or database writes. Operate on
an online-backup snapshot, not a live WAL file copied without its WAL.
"""
import json
import sqlite3
import sys
from pathlib import Path
from evidence_reference import cid, decode


def verify(path):
    if not __debug__:
        raise RuntimeError('verification requires Python assertions enabled')
    db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro')
    assert db.execute('pragma application_id').fetchone()[0] == 0x4b563201
    assert db.execute('pragma user_version').fetchone()[0] == 1
    assert db.execute('pragma integrity_check').fetchone() == ('ok',)
    assert not db.execute('pragma foreign_key_check').fetchall()
    objects = total = commits = 0
    for identity, raw in db.execute('select cid,bytes from objects'):
        assert 0 < len(raw) <= 4*1024*1024
        assert cid(raw, 0x55) == identity
        objects += 1
        total += len(raw)
    for sequence, identity, scope, writer, operation, position, previous, raw, receipt in db.execute('select * from commits order by sequence'):
        assert sequence == commits+1
        assert cid(raw) == identity
        m, r = decode(raw), decode(receipt)
        assert (m['v'], m['kind'], r['v'], r['kind']) == (1, 'manifest', 1, 'receipt')
        m, r = m['body'], r['body']
        assert r['manifest'] == {'$link': identity}
        assert all(r[k] == m[k] for k in ('scopeToken', 'operation', 'position'))
        assert r['durability'] == 'remote-durable'
        assert bytes.fromhex(m['scopeToken']['$bytes']) == scope
        assert m['writer']['principal'] == writer
        assert bytes.fromhex(m['operation']['$bytes']) == operation
        assert m['position'] == position
        assert m['previous'] == (None if previous is None else {'$link': previous})
        prior = db.execute('select cid from commits where scope=? and writer=? and position=? and sequence<?', (scope, writer, position-1, sequence)).fetchone()
        assert prior == (None if position == 0 else (previous,))
        for e in m['entries']:
            binding = db.execute('select b.ciphertext,b.length,c.sequence from bindings b join commits c on c.cid=b.first_manifest where b.scope=? and b.writer=? and b.slot=?', (scope, writer, bytes.fromhex(e['slot']['$bytes']))).fetchone()
            assert binding is not None and binding[:2] == (e['ciphertext']['$link'], e['length'])
            assert binding[2] <= sequence
            obj = db.execute('select bytes from objects where cid=?', (binding[0],)).fetchone()
            assert obj is not None and len(obj[0]) == e['length'] and cid(obj[0],0x55) == binding[0]
        commits += 1
    for scope, writer, slot, obj, length, first in db.execute('select * from bindings'):
        raw, = db.execute('select manifest from commits where cid=?', (first,)).fetchone()
        m = decode(raw)['body']
        assert bytes.fromhex(m['scopeToken']['$bytes']) == scope and m['writer']['principal'] == writer
        assert any(bytes.fromhex(e['slot']['$bytes']) == slot and e['ciphertext']['$link'] == obj and e['length'] == length for e in m['entries'])
    db.close()
    return {'objects': objects, 'commits': commits, 'bytes': total}


if __name__ == '__main__':
    print(json.dumps(verify(sys.argv[1]), sort_keys=True))
