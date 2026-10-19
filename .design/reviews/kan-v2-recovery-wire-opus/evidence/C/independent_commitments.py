"""Reviewer re-implementation of M1/O1/R1 written from the codec design prose
(kan-v2-recovery-bundle-codec.md, 'Initial member commitment M1' and R1 paragraph),
not from .design/tools/recovery_commitments.py. Compares to the draft fixture."""
import base64, hashlib, json, sys
fx = json.load(open(sys.argv[1] + '/.design/fixtures/recovery-commitments-v1.json'))
def dn(v):
    if isinstance(v, dict) and set(v) == {'$bytes'}: return bytes.fromhex(v['$bytes'])
    if isinstance(v, dict): return {k: dn(x) for k, x in v.items()}
    if isinstance(v, list): return [dn(x) for x in v]
    return v
N = lambda n: n.to_bytes(8, 'big')
F = lambda b: N(len(b)) + b
def binary(text):
    raw = base64.b32decode(text[1:].upper() + '=' * (-len(text[1:]) % 8)); assert text[0] == 'b'; return raw
def m1(m, domain):
    out = domain.encode() + b'\0' + N(m['profile']) + F(m['archive']) + F(m['scope']) + F(m['issuer'].encode())
    out += F(b'plan') + (N(0) if m['plan'] is None else N(1) + F(m['plan']))
    mem = sorted(m['membership'], key=lambda x: x[0])
    out += F(b'original-membership') + N(len(mem)) + b''.join(F(binary(c)) + N(l) for c, l in mem)
    out += F(b'records') + N(len(m['records'])) + b''.join(N(s) + F(a) + F(b) + F(c) for s, a, b, c in m['records'])
    obj = sorted(m['objects'], key=lambda x: x[0])
    out += F(b'original-objects') + N(len(obj)) + b''.join(F(binary(c)) + N(len(v)) + F(v) for c, v in obj)
    return hashlib.sha256(out).hexdigest()
ok = True
for row in fx['member']:
    m = dn(row['member'])
    a, b = m1(m, 'tools.kan.recovery.member.v1'), m1(m, 'tools.kan.recovery.output.v1')
    r = (a == row['M1'], b == row['O1']); ok &= all(r); print(row['name'], 'M1', r[0], 'O1', r[1])
for i, row in enumerate(fx['restorations']):
    c = sorted(dn(row['candidates']), key=lambda x: x[0])
    d = hashlib.sha256(b'tools.kan.recovery.restorations.v1\0' + N(len(c)) + b''.join(F(binary(k)) + N(len(v)) + F(v) for k, v in c)).hexdigest()
    ok &= d == row['R1']; print('R1', i, d == row['R1'])
print('ALL-MATCH' if ok else 'MISMATCH')
