#!/usr/bin/env python3
"""Proposed attestation profile oracle. Independent of Rust; no archive access.

Uses the existing independent Python DAG-CBOR oracle and cryptography/OpenSSL
for P-256. --write regenerates public synthetic fixtures using private scalar 1;
--check never rewrites them. These vectors do not prove service admission.
"""
import argparse
import copy
import importlib.util
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature

if not __debug__:
    raise RuntimeError('protocol oracle requires assertions enabled')
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('evidence_oracle', ROOT/'scripts/evidence_reference.py')
codec = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = codec
spec.loader.exec_module(codec)
PATH = ROOT/'.design/fixtures/service-attestation-v1.json'
ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
DOMAIN = 'tools.kan.service.attestation.v1'
SAFE = 2**53 - 1


def b58(raw):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n, result = int.from_bytes(raw, 'big'), ''
    while n:
        n, r = divmod(n, 58)
        result = alphabet[r] + result
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + result


def identity():
    # Public test scalar, never a production identity.
    key = ec.derive_private_key(1, ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    did = 'did:key:z' + b58(b'\x80\x24' + public)
    author = {'principal': did, 'verificationMethod': did+'#'+did[8:], 'identityVersion': {'kind': 'static', 'value': None}}
    return key, author


def preimage(statement):
    return codec.encode({'domain': DOMAIN, 'statement': codec.link(codec.cid(statement))})


def vectors():
    source = json.loads((ROOT/'tests/fixtures/evidence-v1/vectors.json').read_text())
    values = {v['name']: v['value'] for v in source['positive']}
    key, author = identity()
    previous_manifest = previous_statement = None
    rows = []
    for sequence, (name, purpose) in enumerate([('manifest', 'admitted'), ('second-batch', 'retained-verified')], 1):
        manifest = values[name]
        manifest_cid = codec.cid(codec.encode(manifest))
        receipt = copy.deepcopy(values['receipt'])
        receipt['body'].update(issuer=author, manifest=codec.link(manifest_cid), position=manifest['body']['position'], operation=manifest['body']['operation'])
        statement = {'v': 1, 'kind': 'service-attestation', 'body': {
            'issuer': author, 'scopeToken': manifest['body']['scopeToken'], 'sequence': sequence,
            'manifest': codec.link(manifest_cid), 'receipt': codec.link(codec.cid(codec.encode(receipt))),
            'previousSequence': sequence-1, 'previousManifest': previous_manifest,
            'previousAttestation': previous_statement, 'purpose': purpose, 'issuedAt': 1792108800100 + sequence}}
        raw = codec.encode(statement)
        signing = preimage(raw)
        r, s = utils.decode_dss_signature(key.sign(signing, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
        signature = r.to_bytes(32, 'big') + min(s, ORDER-s).to_bytes(32, 'big')
        envelope = codec.encode({'statement': codec.blob(raw), 'signature': codec.blob(signature)})
        rows.append({'name': purpose, 'manifest': manifest, 'receipt': receipt, 'statement': statement,
                     'statementHex': raw.hex(), 'statementCid': codec.cid(raw), 'signingHex': signing.hex(),
                     'signatureHex': signature.hex(), 'envelopeHex': envelope.hex(), 'envelopeCid': codec.cid(envelope)})
        previous_manifest, previous_statement = codec.link(manifest_cid), codec.link(codec.cid(raw))
    return {'status': 'proposal-only; no Rust implementation or admission proof', 'testPrivateScalar': 1,
            'pinnedIssuer': author['principal'], 'positive': rows}


def closed(value, names):
    assert isinstance(value, dict) and set(value) == set(names), 'closed fields'


def uint(value):
    assert type(value) is int and 0 <= value <= SAFE, 'unsigned safe integer'


def record_link(value):
    assert isinstance(value, codec.Link) and len(value.raw) == 36 and value.raw[:4] == b'\x01\x71\x12\x20', 'record CID'


def verify(raw, pinned, previous):
    assert len(raw) <= 16384, 'envelope bound'
    env = codec.decode(raw)
    closed(env, ['statement', 'signature'])
    assert isinstance(env['statement'], bytes), 'statement bytes'
    statement = codec.decode(env['statement'])
    closed(statement, ['v', 'kind', 'body'])
    assert type(statement['v']) is int and statement['v'] == 1 and statement['kind'] == 'service-attestation', 'profile'
    b = statement['body']
    closed(b, ['issuer', 'scopeToken', 'sequence', 'manifest', 'receipt', 'previousSequence', 'previousManifest', 'previousAttestation', 'purpose', 'issuedAt'])
    _, expected_author = identity()
    assert b['issuer'] == expected_author and b['issuer']['principal'] == pinned, 'pinned issuer'
    assert isinstance(b['scopeToken'], bytes) and len(b['scopeToken']) == 32, 'scope'
    for field in ['sequence', 'previousSequence', 'issuedAt']:
        uint(b[field])
    assert b['sequence'] > 0 and b['previousSequence'] == b['sequence']-1, 'sequence'
    for field in ['manifest', 'receipt']:
        record_link(b[field])
    assert b['purpose'] in ['admitted', 'retained-verified'], 'purpose'
    if previous is None:
        assert b['sequence'] == 1 and b['previousManifest'] is None and b['previousAttestation'] is None, 'genesis'
    else:
        record_link(b['previousManifest']); record_link(b['previousAttestation'])
        assert b['previousSequence'] == previous['sequence'] and b['scopeToken'] == previous['scopeToken'], 'chain position/scope'
        assert b['previousManifest'] == previous['manifest'] and b['previousAttestation'] == previous['statementCid'], 'chain commitments'
    sig = env['signature']
    assert isinstance(sig, bytes) and len(sig) == 64, 'signature encoding'
    r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    assert 0 < r < ORDER and 0 < s <= ORDER//2, 'canonical low-S'
    identity()[0].public_key().verify(utils.encode_dss_signature(r,s), preimage(env['statement']), ec.ECDSA(hashes.SHA256()))
    return {**b, 'statementCid': codec.Link(codec.cid_bytes(codec.cid(env['statement'])))}


def check(data):
    assert data == vectors(), 'exact fixtures changed; no automatic rewrite'
    previous = None
    for row in data['positive']:
        raw = bytes.fromhex(row['statementHex'])
        assert codec.encode(row['statement']) == raw
        assert codec.cid(raw) == row['statementCid']
        assert preimage(raw).hex() == row['signingHex']
        env = bytes.fromhex(row['envelopeHex'])
        assert codec.cid(env) == row['envelopeCid']
        state = verify(env, data['pinnedIssuer'], previous)
        assert state['manifest'].raw == codec.cid_bytes(codec.cid(codec.encode(row['manifest'])))
        assert state['receipt'].raw == codec.cid_bytes(codec.cid(codec.encode(row['receipt'])))
        # Invalid transport encoding, cryptographic corruption, profile and
        # metadata substitution. Kept distinct from absent payload semantics.
        invalid = [('trailing', env+b'\0'), ('oversize', env+b'\0'*16384)]
        decoded = codec.decode(env)
        changed = copy.deepcopy(decoded); changed['signature'] = bytes(64)
        invalid.append(('zero-signature', codec.encode_value(changed)))
        sig = decoded['signature']; high = sig[:32]+(ORDER-int.from_bytes(sig[32:],'big')).to_bytes(32,'big')
        changed = copy.deepcopy(decoded); changed['signature'] = high
        invalid.append(('high-S', codec.encode_value(changed)))
        changed = copy.deepcopy(decoded); changed['extra'] = None
        invalid.append(('unknown-envelope-field', codec.encode_value(changed)))
        for field, value in [('purpose','admitted' if row['name']=='retained-verified' else 'retained-verified'), ('sequence',True), ('issuedAt',SAFE+1), ('scopeToken',codec.blob(b'\x07'*32))]:
            changed_statement = copy.deepcopy(row['statement']); changed_statement['body'][field] = value
            changed = copy.deepcopy(decoded); changed['statement'] = codec.encode(changed_statement)
            invalid.append((field, codec.encode_value(changed)))
        for label, value in invalid:
            try:
                verify(value, data['pinnedIssuer'], previous)
            except (AssertionError, ValueError, InvalidSignature):
                pass
            else:
                raise AssertionError('accepted invalid '+label)
        try:
            verify(env, data['pinnedIssuer']+'wrong', previous)
        except AssertionError:
            pass
        else:
            raise AssertionError('accepted unpinned signer')
        previous = state
    print('2 exact P-256 low-S signed proposal vectors; byte/CID/preimage/signature and 20 negative checks passed. No Rust/admission/availability claim.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--write', action='store_true'); mode.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.write:
        PATH.write_text(json.dumps(vectors(), indent=2)+'\n')
    check(json.loads(PATH.read_text()))
