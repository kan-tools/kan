#!/usr/bin/env python3
"""Reviewer probe: hostile re-signed attestation cases labelled by the Python oracle.

argv: repo_root output_json. Reads the committed oracle module and fixture; never
writes them. Each case records the oracle's own verdict (label or ACCEPT) so the
Rust probe can compare implementations on identical bytes.
"""
import copy, importlib.util, json, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location('oracle', ROOT / '.design/tools/attestation_vectors.py')
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)
c = o.codec
data = json.loads((ROOT / '.design/fixtures/service-attestation-v1.json').read_text())
rows = data['positive']
_, current = o.identity(); _, historical = o.identity(2)
states = []
prev = None
for r in rows:
    prev = o.verify(bytes.fromhex(r['envelopeHex']), data['pinnedIssuer'], bytes.fromhex(data['archiveHex']),
                    bytes.fromhex(data['scopeHex']), prev, bytes.fromhex(r['manifestHex']), bytes.fromhex(r['receiptHex']))
    states.append(prev)
cases = []


def label(case):
    i = case['base']; row = rows[i]
    try:
        o.verify(bytes.fromhex(case['envelopeHex']), case.get('pinnedIssuer', data['pinnedIssuer']),
                 bytes.fromhex(case.get('archiveHex', data['archiveHex'])), bytes.fromhex(case.get('scopeHex', data['scopeHex'])),
                 states[i - 1] if i else None, bytes.fromhex(case.get('manifestHex', row['manifestHex'])),
                 bytes.fromhex(case.get('receiptHex', row['receiptHex'])))
    except o.Rejected as e:
        return str(e)
    except Exception as e:  # oracle crash is itself a finding
        return 'PYTHON-CRASH:' + type(e).__name__
    return 'ACCEPT'


def add(name, base=0, st=None, env=None, **kw):
    if env is None:
        env = o.sign(st if st is not None else rows[base]['statement'])
    case = dict(name=name, base=base, envelopeHex=env.hex(), **kw)
    case['python'] = label(case)
    cases.append(case)


def stmt(i=0):
    return copy.deepcopy(rows[i]['statement'])


def with_records(name, base, manifest=None, receipt=None):
    """Re-sign a statement binding exactly these (possibly hostile) records."""
    manifest = manifest if manifest is not None else copy.deepcopy(rows[base]['manifest'])
    mb = c.encode(manifest)
    if receipt is None:
        receipt = copy.deepcopy(rows[base]['receipt'])
        receipt['body']['manifest'] = c.link(c.cid(mb))
    rb = c.encode(receipt)
    st = stmt(base); st['body'].update(manifest=c.link(c.cid(mb)), receipt=c.link(c.cid(rb)))
    add(name, base, st=st, manifestHex=mb.hex(), receiptHex=rb.hex())


def did_case(name, did):
    st = stmt(); st['body']['issuer'] = o.author(did)
    add(name, st=st, pinnedIssuer=did)


# --- canonical type / shape cases ---------------------------------------
st = stmt(); st['v'] = True; add('v-true', st=st)
st = stmt(); st['body']['archiveId'] = 'a' * 32; add('archive-text', st=st)
st = stmt(); st['body']['scopeToken'] = 's' * 32; add('scope-text', st=st)
st = stmt(); st['body']['manifest'] = c.link(c.cid(b'x', 0x55)); add('manifest-raw-codec-link', st=st)
st = stmt(); st['body']['receipt'] = c.link(c.cid(b'x', 0x55)); add('receipt-raw-codec-link', st=st)
st = stmt(1); st['body']['previousManifest'] = c.link(c.cid(b'x', 0x55)); add('prev-manifest-raw-codec', 1, st=st)
st = stmt(1); st['body']['previousAttestation'] = c.link(c.cid(b'x', 0x55)); add('prev-attestation-raw-codec', 1, st=st)
st = stmt(); st['body']['purpose'] = 'Admitted'; add('purpose-case', st=st)
st = stmt(); st['body']['issuedAt'] = o.SAFE; add('issuedAt-max-safe-accept', st=st)
st = stmt(); st['body']['issuedAt'] = 0; add('issuedAt-zero-accept', st=st)
add('kind-swap', manifestHex=rows[0]['receiptHex'], receiptHex=rows[0]['manifestHex'])
src = json.loads((ROOT / 'tests/fixtures/evidence-v1/vectors.json').read_text())
values = {v['name']: v['value'] for v in src['positive']}
add('capture-as-receipt', receiptHex=c.encode(values['capture']).hex())
add('capture-as-manifest', manifestHex=c.encode(values['capture']).hex())
add('noncanonical-manifest-bytes', manifestHex=rows[0]['manifestHex'] + '00')

# --- envelope framing ------------------------------------------------------
env = bytes.fromhex(rows[0]['envelopeHex']); dec = c.decode(env)
def envelope(name, **fields):
    e = copy.deepcopy(dec); e.update(fields); add(name, env=c.encode_value(e))
envelope('signature-text', signature='a' * 64)
envelope('signature-65', signature=dec['signature'] + b'\0')
envelope('signature-link', signature=c.Link(c.cid_bytes(c.cid(b'x'))))
envelope('statement-link', statement=c.Link(c.cid_bytes(c.cid(b'x'))))
for length, name in [(16294, 'envelope-exactly-16384'), (16295, 'envelope-16385')]:
    e = copy.deepcopy(dec); e['statement'] = b'\0' * length; raw = c.encode_value(e)
    add(name, env=raw); cases[-1]['envelopeLength'] = len(raw)
add('precedence-outer-trailing-and-bad-manifest', env=env + b'\0', manifestHex=rows[0]['manifestHex'] + '00')

# --- issuer did:key shape --------------------------------------------------
did = current['principal']
did_case('did-short-55', did[:55])
did_case('did-z2', 'did:key:z2')
did_case('did-long-81', did + '1' * (81 - len(did)))
did_case('did-invalid-base58-char', did[:-1] + '0')
did_case('did-leading-1', 'did:key:z1' + did[9:])
ed = ec.derive_private_key(1, ec.SECP256R1())  # placeholder object for typing only
did_case('did-ed25519', 'did:key:z' + o.b58(b'\xed\x01' + b'\x11' * 32))
for x in range(1, 200):  # first x with no curve point: invalid compressed point
    raw = b'\x02' + x.to_bytes(32, 'big')
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        did_case('did-invalid-point', 'did:key:z' + o.b58(b'\x80\x24' + raw)); break
unc = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
did_case('did-uncompressed', 'did:key:z' + o.b58(b'\x80\x24' + unc))

# --- source receipt/manifest schemas ---------------------------------------
def receipt_issuer(name, issuer):
    m = copy.deepcopy(rows[1]['manifest']); r = copy.deepcopy(rows[1]['receipt'])
    r['body']['issuer'] = issuer
    with_records(name, 1, manifest=m, receipt=r)
receipt_issuer('rv-receipt-didkey-versionId', dict(historical, identityVersion={'kind': 'versionId', 'value': 'v1'}))
receipt_issuer('rv-receipt-web-bogus-version', {'principal': 'did:web:example.com', 'verificationMethod': 'did:web:example.com#k',
                                                 'identityVersion': {'kind': 'bogus', 'value': 5}})
receipt_issuer('rv-receipt-web-versionId-accept', {'principal': 'did:web:example.com', 'verificationMethod': 'did:web:example.com#k',
                                                    'identityVersion': {'kind': 'versionId', 'value': 'v1'}})
receipt_issuer('rv-receipt-web-empty-fragment', {'principal': 'did:web:example.com', 'verificationMethod': 'did:web:example.com#',
                                                  'identityVersion': {'kind': 'versionId', 'value': 'v1'}})
m = copy.deepcopy(rows[0]['manifest']); m['body']['entries'] = []
with_records('manifest-empty-entries', 0, manifest=m)
m = copy.deepcopy(rows[0]['manifest']); m['body']['writer'] = 'not-an-author'
with_records('manifest-bad-writer', 0, manifest=m)
m = copy.deepcopy(rows[0]['manifest']); m['body']['operation'] = c.blob(b'\x05' * 15)
r = copy.deepcopy(rows[0]['receipt']); r['body']['operation'] = m['body']['operation']
r['body']['manifest'] = c.link(c.cid(c.encode(m)))
with_records('manifest-and-receipt-15-byte-operation', 0, manifest=m, receipt=r)

Path(sys.argv[2]).write_text(json.dumps(cases, indent=1) + '\n')
for case in cases:
    print(f"{case['name']:48} python={case['python']}")
