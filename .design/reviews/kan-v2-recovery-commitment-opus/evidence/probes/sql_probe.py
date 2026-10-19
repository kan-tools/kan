#!/usr/bin/env python3
"""Reviewer probes of the draft DDL identifier constraints (in-memory only).
Usage: sql_probe.py <schema.sql>
"""
import sqlite3, sys
SQL = open(sys.argv[1]).read()
print('sqlite', sqlite3.sqlite_version)
DID = 'did:key:zDnae' + 'A' * 44  # 57 ASCII bytes; shape only
def db(encoding=None, ddl=SQL):
    c = sqlite3.connect(':memory:')
    if encoding: c.execute(f"PRAGMA encoding='{encoding}'")
    c.executescript(ddl)
    return c
def ins_identity(c, observer=DID, issuer=DID, raw_sql=None):
    try:
        if raw_sql: c.execute(raw_sql)
        else: c.execute('INSERT INTO bundle_identity VALUES(1,?,?,2,?,?,?)', (bytes(32), observer, bytes(32), bytes(32), issuer))
        c.execute('DELETE FROM bundle_identity'); return True
    except sqlite3.IntegrityError: return False
def ins_obj(c, key, table='member_objects', raw_sql=None):
    try:
        if raw_sql: c.execute(raw_sql)
        else: c.execute(f'INSERT INTO {table} VALUES(?,?)', (key, b'x'))
        c.execute(f'DELETE FROM {table}'); return True
    except sqlite3.IntegrityError: return False

rows = []
def rec(name, got, want):
    rows.append((name, got, want)); print(f"{'OK  ' if got == want else 'DIFF'} {name}: accepted={got} expected={want}")

c = db()
for n, want in [(55, False), (56, True), (80, True), (81, False)]:
    rec(f'observer-{n}-ascii-bytes', ins_identity(c, observer='d' * n), want)
    rec(f'issuer-{n}-ascii-bytes', ins_identity(c, issuer='i' * n), want)
rec('did-with-tilde-and-bang', ins_identity(c, observer='!' + 'a' * 54 + '~'), True)
for ch, name in [(' ', 'space'), ('\t', 'tab'), ('\x7f', 'DEL'), ('\x01', 'SOH')]:
    rec(f'observer-contains-{name}', ins_identity(c, observer='a' * 55 + ch), False)
rec('observer-leading-NUL', ins_identity(c, observer='\0' + 'a' * 55), False)
rec('observer-invalid-utf8-lone-0x80', ins_identity(c, raw_sql="INSERT INTO bundle_identity VALUES(1,zeroblob(32),CAST(X'" + '61' * 55 + "80' AS TEXT),2,zeroblob(32),zeroblob(32),'" + DID + "')"), False)
rec('observer-bound-as-blob', ins_identity(c, observer=DID.encode()), False)
for n, want in [(0, False), (1, True), (128, True), (129, False)]:
    for t in ('member_objects', 'member_membership', 'restored_objects'):
        if t == 'member_membership':
            try:
                c.execute('INSERT INTO member_membership VALUES(?,1)', ('b' * n,)); c.execute('DELETE FROM member_membership'); ok = True
            except sqlite3.IntegrityError: ok = False
        else: ok = ins_obj(c, 'b' * n, t)
        rec(f'{t}-cid-{n}-bytes', ok, want)
rec('cid-invalid-utf8-C3-alone', ins_obj(c, None, raw_sql="INSERT INTO member_objects VALUES(CAST(X'62C3' AS TEXT),X'01')"), False)
rec('cid-trailing-DEL', ins_obj(c, 'bafk\x7f'), False)
rec('cid-bound-as-blob', ins_obj(c, b'bafkrei'), False)

# Encoding dependence: CAST(text AS BLOB) yields the database text encoding.
for enc in ('UTF-16le', 'UTF-16be'):
    c16 = db(enc)
    got_enc = c16.execute('PRAGMA encoding').fetchone()[0]
    rec(f'{got_enc}-db-valid-ascii-did', ins_identity(c16), True)
    rec(f'{got_enc}-db-valid-ascii-cid', ins_obj(c16, 'bafkreiexample'), True)

# Clause-level mutants for member_objects.cid: which clause is load-bearing?
col = "length(CAST(cid AS BLOB)) BETWEEN 1 AND 128 AND length(cid)=length(CAST(cid AS BLOB)) AND cid NOT GLOB '*[^!-~]*'"
assert SQL.count(col) == 3
probes = [('ascii-ok', 'bafkrei', True), ('non-ascii-2byte', 'é' * 64, False), ('embedded-NUL', 'x\0hidden', False),
          ('newline', 'line\nbreak', False), ('space', 'has space', False), ('129-ascii', 'b' * 129, False),
          ('64-x-2byte=128B', 'é' * 64, False), ('65-x-2byte=130B-65ch', 'é' * 65, False), ('trailing-NUL', 'abc\0', False)]
mutants = {
    'no-byte-bound(char-bound)': col.replace('length(CAST(cid AS BLOB)) BETWEEN 1 AND 128', 'length(cid) BETWEEN 1 AND 128'),
    'no-equality': col.replace(' AND length(cid)=length(CAST(cid AS BLOB))', ''),
    'no-glob': col.replace(" AND cid NOT GLOB '*[^!-~]*'", ''),
}
print('\nclause mutants (member_objects only):')
for name, m in mutants.items():
    ddl = SQL.replace(col, m, 1)
    cm = db(ddl=ddl)
    escaped = [p for p, k, want in probes if ins_obj(cm, k) != want]
    print(f'  {name}: probes that now get the wrong verdict = {escaped or "NONE (clause redundant for this probe set)"}')
bad = [r for r in rows if r[1] != r[2]]
print(f'\n{len(rows)} probes, {len(bad)} differ from expectation: {[r[0] for r in bad]}')
