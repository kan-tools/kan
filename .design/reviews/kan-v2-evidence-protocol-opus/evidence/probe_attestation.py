#!/usr/bin/env python3
"""Synthetic reviewer probes against the proposed attestation oracle.

Reads .design/fixtures/service-attestation-v1.json and imports
.design/tools/attestation_vectors.py from the reviewed tree. Never writes
fixtures. Uses only public test scalars 1 and 2. No archive, key or network.
Usage: python probe_attestation.py <tree-root>
"""
import copy
import importlib.util
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

ROOT = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location('oracle', ROOT / '.design/tools/attestation_vectors.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
codec = oracle.codec
DATA = json.loads((ROOT / '.design/fixtures/service-attestation-v1.json').read_text())
PIN = DATA['pinnedIssuer']
results = []


def sign_with(scalar, statement):
    key = ec.derive_private_key(scalar, ec.SECP256R1())
    raw = codec.encode(statement)
    r, s = utils.decode_dss_signature(key.sign(oracle.preimage(raw), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    sig = r.to_bytes(32, 'big') + min(s, oracle.ORDER - s).to_bytes(32, 'big')
    return codec.encode({'statement': codec.blob(raw), 'signature': codec.blob(sig)})


def attempt(label, expect, raw, previous):
    try:
        oracle.verify(raw, PIN, previous)
        got = 'accept'
    except Exception as e:  # report which check fired
        got = 'reject(%s: %s)' % (type(e).__name__, e)
    ok = got.startswith(expect)
    results.append((label, expect, got, ok))
    return got


rows = DATA['positive']
s1 = codec.from_fixture(rows[0]['statement']) if hasattr(codec, 'from_fixture') else None
st1 = oracle.vectors()['positive'][0]['statement']
st2 = oracle.vectors()['positive'][1]['statement']
env1 = bytes.fromhex(rows[0]['envelopeHex'])
env2 = bytes.fromhex(rows[1]['envelopeHex'])
state1 = oracle.verify(env1, PIN, None)

# P1 chain negatives absent from the fixture set: re-signed by the PINNED key,
# so only the chain checks can reject them.
for field, value in [('previousAttestation', codec.link(codec.cid(codec.encode(st2)))),
                     ('previousManifest', st2['body']['manifest']),
                     ('sequence', 3), ('previousSequence', 0)]:
    bad = copy.deepcopy(st2); bad['body'][field] = value
    attempt('P1 re-signed seq2 with wrong ' + field, 'reject', sign_with(1, bad), state1)
bad = copy.deepcopy(st1); bad['body']['previousManifest'] = st2['body']['manifest']
attempt('P1 re-signed genesis with non-null previousManifest', 'reject', sign_with(1, bad), None)

# P2 fork: a second, different, validly signed statement at sequence 2 with the
# same predecessor (e.g. post-restore re-admission, or a second upgrade copy).
fork = copy.deepcopy(st2); fork['body']['issuedAt'] += 1; fork['body']['purpose'] = 'admitted'
attempt('P2 equal-height fork statement verifies per-statement', 'accept', sign_with(1, fork), state1)

# P3 receipt binding: statement names a receipt CID whose receipt binds a
# DIFFERENT manifest. The oracle never decodes the receipt.
foreign = copy.deepcopy(rows[1]['receipt'])
foreign_receipt = codec.from_fixture(foreign) if hasattr(codec, 'from_fixture') else None
alt = copy.deepcopy(st2)
alt['body']['receipt'] = codec.link(codec.cid(codec.encode(oracle.vectors()['positive'][0]['receipt'])))
attempt('P3 statement binds receipt of a different manifest', 'accept', sign_with(1, alt), state1)

# P4 purpose 'admitted' with a receipt issued by another service identity:
# no rule in oracle ties admitted purpose to receipt issuer.
other_receipt = copy.deepcopy(oracle.vectors()['positive'][1]['receipt'])
other_receipt['body']['issuer'] = {'principal': 'did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc',
    'verificationMethod': 'did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc#zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc',
    'identityVersion': {'kind': 'static', 'value': None}}
adm = copy.deepcopy(st2); adm['body']['purpose'] = 'admitted'
adm['body']['receipt'] = codec.link(codec.cid(codec.encode(other_receipt)))
attempt('P4 admitted purpose over foreign-issuer receipt', 'accept', sign_with(1, adm), state1)

# P5 issuer transition (upgrade signer != later service key): scalar 2 signs seq2.
key2 = ec.derive_private_key(2, ec.SECP256R1())
from cryptography.hazmat.primitives import serialization
pub2 = key2.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
did2 = 'did:key:z' + oracle.b58(b'\x80\x24' + pub2)
tr = copy.deepcopy(st2); tr['body']['issuer'] = {'principal': did2, 'verificationMethod': did2 + '#' + did2[8:], 'identityVersion': {'kind': 'static', 'value': None}}
attempt('P5 issuer transition within one chain', 'reject', sign_with(2, tr), state1)

# P6 mid-chain page: verify seq2 without the verified predecessor state.
attempt('P6 verify mid-chain row without predecessor', 'reject', env2, None)

# P7 encodings the RFC names but the fixture set does not exercise.
dec = codec.decode(env2)
r, s = int.from_bytes(dec['signature'][:32], 'big'), int.from_bytes(dec['signature'][32:], 'big')
der = copy.deepcopy(dec); der['signature'] = utils.encode_dss_signature(r, s)
attempt('P7 DER signature', 'reject', codec.encode_value(der), state1)
unk = copy.deepcopy(st2); unk['body']['extra'] = None
attempt('P7 re-signed unknown statement body field', 'reject', sign_with(1, unk), state1)
v2 = copy.deepcopy(st2); v2['v'] = 2
attempt('P7 re-signed statement v=2', 'reject', sign_with(1, v2), state1)
pur = copy.deepcopy(st2); pur['body']['purpose'] = 'historical-admission'
attempt('P7 re-signed unknown purpose', 'reject', sign_with(1, pur), state1)
# noncanonical outer map: signature/statement keys swapped (statement first)
raw_stmt = dec['statement']; raw_sig = dec['signature']
swapped = (b'\xa2' + codec.encode_value('statement')[0:0] + b'' )
swapped = b'\xa2' + b'\x69statement' + codec.encode_value(codec.blob(raw_stmt)) if False else None
try:
    head = oracle.codec.head
    enc_s = head(3, 9) + b'statement' + head(2, len(raw_stmt)) + raw_stmt
    enc_g = head(3, 9) + b'signature' + head(2, 64) + raw_sig
    attempt('P7 noncanonical envelope key order', 'reject', b'\xa2' + enc_s + enc_g, state1)
except Exception as e:
    results.append(('P7 noncanonical envelope key order', 'reject', 'probe error %s' % e, False))

for label, expect, got, ok in results:
    print('%s | %s | expected %s | got %s' % ('OK ' if ok else 'UNEXPECTED', label, expect, got))
print('%d probes, %d unexpected' % (len(results), sum(not r[3] for r in results)))
