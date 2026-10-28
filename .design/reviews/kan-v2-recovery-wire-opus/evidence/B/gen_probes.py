#!/usr/bin/env python3
"""Reviewer-authored hostile recovery-observation probes (public test keys only).

Builds raw envelopes, many deliberately non-canonical at the byte level and signed
over their exact raw statement bytes, so a refusal is attributable to the named
check rather than to an incidental signature failure. Records the independent
Python oracle's verdict alongside the reviewer's own expectation.
usage: gen_probes.py <export-root> <out.json>
"""
import importlib.util, json, struct, sys, copy, base64, hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = Path(sys.argv[1]); OUT = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('rov', ROOT / '.design/tools/recovery_observation_vectors.py')
rov = importlib.util.module_from_spec(spec); spec.loader.exec_module(rov)
codec, crypto = rov.codec, rov.crypto
ORDER = crypto.ORDER; HALF = (ORDER - 1) // 2
fx = json.loads((ROOT / '.design/fixtures/recovery-observation-v1.json').read_text())
gen = rov.vectors()
assert json.loads(json.dumps(gen)) == fx, 'stored fixture differs from regenerated oracle output'
rows = fx['positive']
ctx_native = codec.from_fixture(fx['context'])
key3 = crypto.identity(3)[0]; key2 = crypto.identity(2)[0]; key4 = crypto.identity(4)[0]
E = codec.encode_value; H = codec.head

def native(i): return codec.from_fixture(copy.deepcopy(rows[i]['statement']))
def cid_link(raw, kind=0x71): return codec.Link(codec.cid_bytes(codec.cid(raw, kind)))
def sig_over(msg, key=key3):
    r, s = utils.decode_dss_signature(key.sign(msg, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    return r.to_bytes(32, 'big') + min(s, ORDER - s).to_bytes(32, 'big')
def preimage(raw, domain=rov.DOMAIN, kind=0x71):
    return E({'domain': domain, 'statement': cid_link(raw, kind)})
def envelope(raw, sig=None, key=key3): return E({'statement': raw, 'signature': sig if sig is not None else sig_over(preimage(raw), key)})
def pairs(st, override=None):
    override = override or {}
    return sorted((E(k), override[k] if k in override else E(v)) for k, v in st.items())
def raw_map(ps, count=None): return H(5, len(ps) if count is None else count) + b''.join(k + v for k, v in ps)

probes = []
def py_verdict(env, base, ctx):
    previous = None
    try:
        prev = None
        for i in range(base):
            prev = rov.verify(bytes.fromhex(rows[i]['envelopeHex']), ctx_native, prev)
        rov.verify(env, ctx, prev)
        return 'OK'
    except rov.Rejected as e:
        return str(e)
    except Exception as e:  # oracle crash is itself a finding
        return 'PYTHON-CRASH:' + type(e).__name__ + ':' + str(e)[:80]
def add(name, env, expect, base=0, ctx_override=None, cls='refuse'):
    ctx = dict(ctx_native); ctx.update(ctx_override or {})
    probes.append({'name': name, 'class': cls, 'base': base, 'envelopeHex': env.hex(), 'expect': expect,
                   'python': py_verdict(env, base, ctx), 'contextOverride': {k: (v.hex() if isinstance(v, bytes) else v) for k, v in (ctx_override or {}).items()}})
def resign(st, base, expect, name, cls='refuse', **kw): add(name, envelope(E(st)), expect, base, cls=cls, **kw)

# ---------------- canonical encoding (statement signed over its exact raw bytes) ----
st0 = native(0)
ps = pairs(st0)
add('C01-statement-duplicate-key', envelope(raw_map(ps[:1] + ps[:1] + ps[1:])), 'statement-canonical')
add('C02-statement-unsorted-keys', envelope(raw_map([ps[1], ps[0]] + ps[2:])), 'statement-canonical')
add('C03-nonminimal-sequence', envelope(raw_map(pairs(st0, {'sequence': b'\x18\x01'}))), 'statement-canonical')
add('C04-indefinite-statement-map', envelope(b'\xbf' + b''.join(k + v for k, v in ps) + b'\xff'), 'statement-canonical')
add('C05-float-sampledAt', envelope(raw_map(pairs(st0, {'sampledAt': b'\xfb' + struct.pack('>d', 1.0)}))), 'statement-canonical')
add('C06-tag1-sampledAt', envelope(raw_map(pairs(st0, {'sampledAt': b'\xc1' + E(5)}))), 'statement-canonical')
st1 = native(1)
add('C07-cid-without-identity-prefix', envelope(raw_map(pairs(st1, {'previous': b'\xd8\x2a' + H(2, 36) + st1['previous'].raw}))), 'statement-canonical', base=1)
add('C08-invalid-utf8-event', envelope(raw_map(pairs(st0, {'event': H(3, 2) + b'\xff\xfe'}))), 'statement-canonical')
add('C09-uint64-max-sequence', envelope(raw_map(pairs(st0, {'sequence': b'\x1b' + b'\xff' * 8}))), 'statement-canonical')
st2 = native(2)
add('C10-negative-restored-length', envelope(E({**st2, 'body': {**st2['body'], 'length': -1}})), 'statement-canonical', base=2)
add('C11-statement-trailing-byte', envelope(E(st0) + b'\x00'), 'statement-canonical')
def nest(d):
    v = 0
    for _ in range(d): v = [v]
    return v
add('C12-depth-40-in-extra-field', envelope(E({**st0, 'extra': nest(40)})), 'statement-canonical')
add('C13-depth-30-in-extra-field', envelope(E({**st0, 'extra': nest(30)})), 'statement-fields')
add('C14-bundle-as-text', envelope(E({**st0, 'bundle': 'x' * 32})), 'byte-width')
add('C15-statement-not-map', envelope(E([1, 2])), 'statement-fields')
add('C16-sha512-restored-cid', envelope(E({**st2, 'body': {**st2['body'], 'cid': codec.Link(bytes([1, 0x55, 0x13, 0x40]) + hashlib.sha512(b'x').digest())}})), 'link-profile', base=2)
add('C17-cidv0-intent', None or envelope(E({**native(4), 'body': {**native(4)['body'], 'intent': codec.Link(b'\x12\x20' + hashlib.sha256(b'x').digest())}})), 'link-profile', base=4)
add('C18-boolean-frontier-through', envelope(E({**st0, 'body': {**st0['body'], 'frontier': {'through': True, 'manifest': None, 'attestation': None}}})), 'integer')
add('C19-empty-event', envelope(E({**st0, 'event': ''})), 'event')
add('C20-long-event', envelope(E({**st0, 'event': 'c' * 33})), 'event')
add('C21-integer-event', envelope(E({**st0, 'event': 1})), 'event')
env_ok = bytes.fromhex(rows[0]['envelopeHex']); dec = codec.decode(env_ok)
add('C22-envelope-statement-as-text', E({'statement': 'abc', 'signature': dec['signature']}), 'statement-bytes')
add('C23-envelope-extra-key', E({**dec, 'x': 1}), 'envelope-fields')
add('C24-envelope-missing-signature', E({'statement': dec['statement']}), 'envelope-fields')
eps = sorted((E(k), E(v)) for k, v in dec.items())
add('C25-envelope-duplicate-key', raw_map(eps[:1] + eps), 'envelope-canonical')
add('C26-envelope-not-map', E(b'abc'), 'envelope-fields')
add('C27-empty-input', b'', 'envelope-canonical')
add('C28-signature-63', E({**dec, 'signature': dec['signature'][:63]}), 'byte-width')
add('C29-signature-65', E({**dec, 'signature': dec['signature'] + b'\x01'}), 'byte-width')
add('C30-signature-text', E({**dec, 'signature': 'x' * 64}), 'byte-width')
# exact envelope bound: pad an extra common field until the envelope is 16384 / 16385 bytes
for target, expect in [(16384, 'statement-fields'), (16385, 'envelope-bound')]:
    for n in range(15000, 16400):
        raw = E({**st0, 'pad': b'\0' * n}); env = envelope(raw)
        if len(env) == target:
            add(f'C31-envelope-exactly-{target}', env, expect); break
    else:
        raise SystemExit('no padding for ' + str(target))

# ---------------- DID / key / signature --------------------------------------------
def did(prefix, pub): return 'did:key:z' + crypto.b58(prefix + pub)
k1 = ec.derive_private_key(5, ec.SECP256K1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
add('D01-context-observer-secp256k1', env_ok, 'did-key', ctx_override={'observer': did(b'\xe7\x01', k1)})
add('D02-context-issuer-ed25519', env_ok, 'did-key', ctx_override={'issuer': did(b'\xed\x01', bytes(range(32)))})
unc = key3.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
udid = did(b'\x80\x24', unc)
add('D03-uncompressed-p256-observer-consistent', envelope(E({**st0, 'observer': udid})), 'did-key', ctx_override={'observer': udid})
add('D04-observer-trailing-space', envelope(E({**st0, 'observer': ctx_native['observer'] + ' '})), 'did-key', ctx_override={'observer': ctx_native['observer'] + ' '})
add('D05-observer-uppercase-did-prefix', envelope(E({**st0, 'observer': 'DID' + ctx_native['observer'][3:]})), 'did-key', ctx_override={'observer': 'DID' + ctx_native['observer'][3:]})
raw0 = E(st0); good = sig_over(preimage(raw0)); r, s = int.from_bytes(good[:32], 'big'), int.from_bytes(good[32:], 'big')
def with_rs(rv, sv): return envelope(raw0, rv.to_bytes(32, 'big') + sv.to_bytes(32, 'big'))
add('D06-r-zero', with_rs(0, s), 'signature-range')
add('D07-r-equals-order', with_rs(ORDER, s), 'signature-range')
add('D08-r-plus-order-overflow-impossible-use-order-minus-1', with_rs(ORDER - 1, s), 'signature-invalid')
add('D09-s-zero', with_rs(r, 0), 'signature-range')
add('D10-s-half-plus-1', with_rs(r, HALF + 1), 'signature-range')
add('D11-s-half-exact-not-valid', with_rs(r, HALF), 'signature-invalid')
add('D12-signature-from-other-statement', envelope(raw0, sig_over(preimage(E(native(1))))), 'signature-invalid')
add('D13-raw-codec-statement-cid-preimage', envelope(raw0, sig_over(preimage(raw0, kind=0x55))), 'signature-invalid')
add('D14-signature-over-statement-bytes', envelope(raw0, sig_over(raw0)), 'signature-invalid')
add('D15-issuer-key-signature', envelope(raw0, key=key2), 'signature-invalid')
add('D16-cross-domain-copy-plan', envelope(raw0, sig_over(preimage(raw0, domain='tools.kan.copy.plan.v1'))), 'signature-invalid')
issuer = ctx_native['issuer']
add('D17-observer-equals-issuer', envelope(E({**st0, 'observer': issuer}), key=key2), 'OK', ctx_override={'observer': issuer}, cls='semantic-acceptance')

# ---------------- predecessor (wire-level; Rust adds foreign-context probes) -------
add('P01-genesis-with-previous-given', env_ok, 'sequence', base=1)
add('P02-seq3-links-seq1-given-seq2', envelope(E({**native(2), 'previous': cid_link(E(native(0)))})), 'predecessor', base=2)
add('P03-previous-raw-codec', envelope(E({**native(1), 'previous': cid_link(E(native(0)), 0x55)})), 'link-profile', base=1)
add('P04-seq2-without-predecessor', bytes.fromhex(rows[1]['envelopeHex']), 'genesis', base=0)
add('P05-fork-alternative-seq2', envelope(E({**native(1), 'sampledAt': 1})), 'OK', base=1, cls='semantic-acceptance')

# ---------------- event shapes ---------------------------------------------------
created_cid = cid_link(E(native(0)))
def at(i, **body): st = native(i); st['body'] = {**st['body'], **body}; return st
resign(at(5, intent=created_cid), 5, 'OK', 'S01-observed-intent-cites-created', cls='semantic-acceptance')
resign(at(5, output=b'\x09' * 32), 5, 'OK', 'S02-observed-output-differs-from-intent', cls='semantic-acceptance')
resign(at(5, attempt=b'\x01' * 16), 5, 'OK', 'S03-observed-attempt-differs-from-intent', cls='semantic-acceptance')
resign(at(2, member=b'\x0a' * 32), 2, 'OK', 'S04-restored-member-differs-from-created', cls='semantic-acceptance')
resign(at(2, length=15), 2, 'OK', 'S05-restored-length-not-candidate-length', cls='semantic-acceptance')
st = native(5); st['event'] = 'unavailable'; st['body'] = native(1)['body']
resign(st, 5, 'OK', 'S06-unavailable-after-publication', cls='semantic-acceptance')
st = native(5); st['event'] = 'publication-intent'; st['body'] = native(3)['body']
resign(st, 5, 'OK', 'S07-second-intent-same-attempt', cls='semantic-acceptance')
resign(at(0, frontier={'through': 5, 'manifest': cid_link(b'm'), 'attestation': cid_link(b'p')}), 0, 'OK', 'S08-created-arbitrary-frontier', cls='semantic-acceptance')
resign(at(0, frontier={'through': 5, 'manifest': cid_link(b'm'), 'attestation': None}), 0, 'link-profile', 'S09-frontier-half-null')
# text-vs-binary canonical CID order
a = b'probe-19'; b = b'probe-20'
la, lb = cid_link(a, 0x55), cid_link(b, 0x55)
ta, tb = codec.cid(a, 0x55), codec.cid(b, 0x55)
assert (ta < tb) != (la.raw < lb.raw)
first, second = (la, lb) if ta < tb else (lb, la)
ent = lambda o, l, n=1, st='missing': {'occurrence': o, 'cid': l, 'expectedLength': n, 'state': st}
resign(at(1, entries=[ent(1, first), ent(1, second)]), 1, 'OK', 'S10-entries-text-order', cls='positive')
resign(at(1, entries=[ent(1, second), ent(1, first)]), 1, 'entry-order-unique', 'S11-entries-binary-order')
resign(at(1, entries=[ent(None, first), ent(1, second)]), 1, 'entry-order-unique', 'S12-null-occurrence-first')
resign(at(1, entries=[ent(1, first), ent(2, first)]), 1, 'OK', 'S13-shared-cid-two-occurrences', cls='positive')
resign(at(1, entries=[ent(1, first, st='missing'), ent(1, first, st='corrupt')]), 1, 'entry-order-unique', 'S14-same-coordinate-two-states')
resign(at(1, entries=[ent(None, first, 7)]), 1, 'OK', 'S15-null-occurrence-with-length', cls='positive')
resign(at(1, entries=[ent(9007199254740991, first, 4194304)]), 1, 'OK', 'S16-max-occurrence-and-length', cls='positive')
resign(at(1, entries=[ent(1, cid_link(b'x'))]), 1, 'link-profile', 'S17-entry-dagcbor-cid')
resign(at(1, entries=[ent(2, first), ent(10, first)]), 1, 'OK', 'S18-numeric-not-text-occurrence-order', cls='positive')
st = native(5); st['event'] = 'publication-failed'; st['body'] = {'attempt': st['body']['attempt'], 'intent': st['body']['intent'], 'reason': 'io'}
resign(st, 5, 'OK', 'S19-failed-after-observed', cls='semantic-acceptance')

json.dump({'context': fx['context'], 'probes': probes}, open(OUT, 'w'), indent=1)
mism = [p for p in probes if p['python'] != p['expect']]
print(f'{len(probes)} probes; python disagrees with reviewer expectation on {len(mism)}:')
for p in mism: print('  ', p['name'], 'expect', p['expect'], 'python', p['python'])
