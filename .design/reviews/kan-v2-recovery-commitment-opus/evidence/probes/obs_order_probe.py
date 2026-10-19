#!/usr/bin/env python3
"""Stdlib-only: confirm the observation order fixtures discriminate text vs binary
CID order, by locating each CID's binary form inside the exact signed envelope bytes."""
import base64, hashlib, json, sys
f = json.load(open(sys.argv[1]))
def raw(data): return bytes([1, 0x55, 0x12, 0x20]) + hashlib.sha256(data).digest()
def text(r): return 'b' + base64.b32encode(r).decode().lower().rstrip('=')
a, b = raw(b'probe-19'), raw(b'probe-20')
ta, tb = text(a), text(b)
print('probe-19', ta, '\nprobe-20', tb)
print('text order a<b:', ta < tb, ' binary order a<b:', a < b, ' -> discriminating:', (ta < tb) != (a < b))
pos = [r for r in f['shapePositive'] if r.get('name') == 'canonical-cid-text-order']
neg = [r for r in f['negative'] if r.get('name') == 'binary-cid-order']
print('shapePositive names:', [r.get('name') for r in f['shapePositive']])
for label, rows in (('positive canonical-cid-text-order', pos), ('negative binary-cid-order', neg)):
    assert len(rows) == 1, (label, len(rows))
    env = bytes.fromhex(rows[0]['envelopeHex'])
    ia, ib = env.find(a), env.find(b)
    assert ia > 0 and ib > 0 and env.count(a) == 1 and env.count(b) == 1
    first = 'probe-19' if ia < ib else 'probe-20'
    order = 'text' if (ia < ib) == (ta < tb) else 'binary'
    print(f'{label}: first entry={first} -> {order} order; expected reason={rows[0].get("reason")}')
same = f['sameKeyRoles']
print('sameKeyRoles observer==issuer:', same['context']['observer'] == same['context']['issuer'],
      ' equals main observer:', same['context']['observer'] == f['context']['observer'])
