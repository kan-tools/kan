#!/usr/bin/env python3
"""Python SQLite physical fixtures carrying independently signed replay vectors.

The existing proposed DDL fixture pins the schema; it is not an independently
designed schema specification. Byte/signature/state authority comes from the independent
replay vectors. No Rust invocation, production keys or network.
"""
import argparse,json,os,sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def create(path,case,encoding='UTF-8'):
    schema=(ROOT/'.design/fixtures/recovery-bundle-v1-schema.sql').read_text()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    db=sqlite3.connect(path)
    db.execute("PRAGMA encoding='"+encoding+"'")
    db.executescript(schema)
    db.execute('PRAGMA application_id=1263419953')
    assert 1263419953==0x4b4e4231
    db.execute('PRAGMA user_version=1')
    # Hostile vectors can contain states that storage constraints alone refuse.
    # Disable CHECK constraints for fixture insertion to exercise reader checks.
    db.execute('PRAGMA ignore_check_constraints=ON')
    m=case['member'];c=m['context'];unhex=bytes.fromhex
    db.execute('INSERT INTO bundle_identity VALUES(1,?,?,?,?,?,?)',(unhex(c['bundle']),c['observer'],c['profile'],unhex(c['archive']),unhex(c['scope']),c['issuer']))
    if m['plan'] is not None:db.execute('INSERT INTO member_plan VALUES(1,?)',(unhex(m['plan']),))
    db.executemany('INSERT INTO member_membership VALUES(?,?)',m['membership'])
    db.executemany('INSERT INTO member_records VALUES(?,?,?,?)',[(n,unhex(a),unhex(b),unhex(c)) for n,a,b,c in m['records']])
    db.executemany('INSERT INTO member_objects VALUES(?,?)',[(c,unhex(b)) for c,b in m['objects']])
    db.executemany('INSERT INTO restored_objects VALUES(?,?)',[(c,unhex(b)) for c,b in case['candidates']])
    db.executemany('INSERT INTO observations VALUES(?,?)',[(i+1,unhex(b)) for i,b in enumerate(case['observations'])])
    db.commit();db.close()

def main():
    p=argparse.ArgumentParser();p.add_argument('out',type=Path);p.add_argument('--case');p.add_argument('--encoding',default='UTF-8',choices=['UTF-8','UTF-16le']);a=p.parse_args()
    cases=json.loads((ROOT/'.design/fixtures/recovery-replay-v1.json').read_text())['cases']
    a.out.mkdir(parents=True,exist_ok=True)
    for case in cases:
        if a.case and case['name']!=a.case:continue
        create(a.out/(case['name']+'.sqlite'),case,a.encoding)
    print('constructed physical fixtures from independent signed histories')
if __name__=='__main__':main()
