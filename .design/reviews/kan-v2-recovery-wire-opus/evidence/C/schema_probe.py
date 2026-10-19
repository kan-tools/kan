"""Reviewer probes of the draft KNB1 DDL, in memory only. Records acceptance of
values the design intends to refuse or that only survive via SQLite affinity."""
import sqlite3, sys
sql = open(sys.argv[1] + '/.design/fixtures/recovery-bundle-v1-schema.sql').read()
print('python sqlite3 library', sqlite3.sqlite_version)
def fresh():
    db = sqlite3.connect(':memory:'); db.executescript(sql); return db
def attempt(name, q, params, note):
    db = fresh()
    try:
        db.execute(q, params)
        stored = db.execute('SELECT * FROM ' + q.split()[2]).fetchone()
        print(f'ACCEPTED\t{name}\tstored={[(type(v).__name__, v if not isinstance(v,(bytes,str)) or len(v)<20 else (type(v).__name__+str(len(v)))) for v in stored]}\t{note}')
    except sqlite3.Error as e:
        print(f'REFUSED\t{name}\t{type(e).__name__}: {e}\t{note}')
ident = [1, bytes(32), 'd'*56, 2, bytes(32), bytes(32), 'i'*56]
def idrow(i, v): r = ident.copy(); r[i] = v; return r
Q = 'INSERT INTO bundle_identity VALUES(?,?,?,?,?,?,?)'
attempt('identity-profile-text-2', Q, idrow(3, '2'), 'INTEGER affinity coerces text before CHECK')
attempt('identity-profile-real-2.0', Q, idrow(3, 2.0), 'INTEGER affinity coerces exact real')
# removed after run1: Python int 10**55 overflows SQLite binding (reviewer probe bug)
attempt('identity-observer-56-nonascii-chars', Q, idrow(2, 'é'*56), 'length() counts characters: 112 UTF-8 bytes accepted')
attempt('identity-observer-80-nonascii-chars', Q, idrow(2, 'é'*80), '160 bytes accepted though DID column bound is 80')
attempt('identity-singleton-text-1', Q, idrow(0, '1'), 'rowid alias coerces text')
attempt('membership-length-text', 'INSERT INTO member_membership VALUES(?,?)', ('k', '5'), 'INTEGER affinity coerces text')
attempt('membership-length-real-5.0', 'INSERT INTO member_membership VALUES(?,?)', ('k', 5.0), 'INTEGER affinity coerces exact real')
attempt('membership-cid-integer', 'INSERT INTO member_membership VALUES(?,?)', (12345, 5), 'TEXT affinity converts number to text')
attempt('objects-cid-blob', 'INSERT INTO member_objects VALUES(?,?)', (b'abc', b''), 'typeof check refuses blob key')
attempt('objects-cid-128-nonascii', 'INSERT INTO member_objects VALUES(?,?)', ('é'*128, b''), 'characters not bytes')
attempt('observations-seq-text', 'INSERT INTO observations VALUES(?,?)', ('1', b'x'), 'rowid alias coerces text')
attempt('observations-seq-real', 'INSERT INTO observations VALUES(?,?)', (1.0, b'x'), 'rowid alias coerces exact real')
attempt('observations-gap-allowed', 'INSERT INTO observations VALUES(?,?)', (7, b'x'), 'contiguity is verifier-only (expected)')
attempt('plan-row-for-profile2', 'INSERT INTO member_plan VALUES(?,?)', (1, b'x'), 'cross-table profile rule is verifier-only (expected)')
# STRICT alternative (reviewer suggestion only; not the fixture)
strict = sql.replace(') WITHOUT ROWID;', ') STRICT, WITHOUT ROWID;')
import re
strict = re.sub(r'\n\);', '\n) STRICT;', strict)
db = sqlite3.connect(':memory:')
try:
    db.executescript(strict)
    for name, q, p in [('strict-profile-text', Q, idrow(3, '2')), ('strict-membership-real', 'INSERT INTO member_membership VALUES(?,?)', ('k', 5.0)), ('strict-cid-int', 'INSERT INTO member_membership VALUES(?,?)', (12345, 5))]:
        try:
            db.execute(q, p); print('STRICT-ACCEPTED', name)
        except sqlite3.Error as e:
            print('STRICT-REFUSED', name, type(e).__name__, e)
except sqlite3.Error as e:
    print('STRICT variant unsupported by this sqlite:', e)
