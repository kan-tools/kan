#!/usr/bin/env python3
"""Independent, stdlib-only RFC 4 byte oracle. Never imports or invokes Rust.

--check compares pinned vectors without writing; --write is explicit regeneration.
The decoder is independent of the encoder and rejects noncanonical CBOR itself.
This is a restricted DAG-CBOR oracle, not an RFC 1 identity/signature verifier.
"""
import argparse
import base64
import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

if not __debug__:
    raise RuntimeError('evidence verification requires Python assertions enabled')

FIXTURE = Path(__file__).resolve().parents[1] / 'tests/fixtures/evidence-v1/vectors.json'


def cid(raw, codec=0x71):
    return 'b' + base64.b32encode(bytes([1, codec, 0x12, 0x20]) + hashlib.sha256(raw).digest()).decode().lower().rstrip('=')


def cid_bytes(value):
    return base64.b32decode(value[1:].upper() + '=' * ((-len(value[1:])) % 8))


def blob(value):
    return {'$bytes': value.hex()}


def link(value):
    return {'$link': value}


def head(major, n):
    for limit, width, suffix in [(24, 0, n), (256, 1, 24), (65536, 2, 25), (2**32, 4, 26), (2**64, 8, 27)]:
        if n < limit:
            return bytes([(major << 5) | suffix]) + (n.to_bytes(width, 'big') if width else b'')
    raise ValueError('integer too large')


@dataclass(frozen=True)
class Link:
    raw: bytes


def from_fixture(value):
    if isinstance(value, list):
        return [from_fixture(v) for v in value]
    if isinstance(value, dict):
        if set(value) == {'$bytes'}:
            return bytes.fromhex(value['$bytes'])
        if set(value) == {'$link'}:
            return Link(cid_bytes(value['$link']))
        if set(value) == {'$map'}:
            return {k: from_fixture(v) for k, v in value['$map'].items()}
        return {k: from_fixture(v) for k, v in value.items()}
    return value


def encode(value):
    """Encode explicit JSON fixture notation, not decoded values."""
    return encode_value(from_fixture(value))


def encode_value(value):
    if value is None:
        return b'\xf6'
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, int):
        return head(0 if value >= 0 else 1, value if value >= 0 else -1-value)
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, Link):
        raw = b'\x00' + value.raw
        return b'\xd8\x2a' + head(2, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(map(encode_value, value))
    if isinstance(value, dict):
        pairs = sorted((encode_value(k), encode_value(v)) for k, v in value.items())
        return head(5, len(pairs)) + b''.join(k + v for k, v in pairs)
    raise ValueError('unsupported value')


def validate_cid(raw):
    """Canonical CIDv0 or CIDv1, u64 varints, multihash digest <= 64 bytes."""
    if len(raw) == 34 and raw[:2] == b'\x12\x20':
        return
    pos = 0

    def varint():
        nonlocal pos
        value = 0
        for i in range(10):
            if pos == len(raw):
                raise ValueError('truncated CID varint')
            b = raw[pos]
            pos += 1
            value |= (b & 127) << (7*i)
            if b < 128:
                if (i and b == 0) or value >= 2**64:
                    raise ValueError('nonminimal/overflow CID varint')
                return value
        raise ValueError('CID varint overflow')

    if varint() != 1:
        raise ValueError('CID version')
    varint()  # codec
    varint()  # multihash code
    size = varint()
    if size > 64 or len(raw)-pos != size:
        raise ValueError('CID digest length/trailing bytes')


def decode(raw):
    if len(raw) > 65536:
        raise ValueError("record too large")
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(raw):
            raise ValueError('truncated')
        result = raw[pos:pos+n]
        pos += n
        return result

    def item(depth=0):
        nonlocal pos
        if depth > 32:
            raise ValueError('depth')
        byte = take(1)[0]
        major, ai = byte >> 5, byte & 31
        if major == 7:
            if byte in (0xf4, 0xf5, 0xf6):
                return {0xf4: False, 0xf5: True, 0xf6: None}[byte]
            raise ValueError('unsupported simple or float')
        if ai < 24:
            n = ai
        elif ai in (24, 25, 26, 27):
            width = 1 << (ai-24)
            n = int.from_bytes(take(width), 'big')
            if n < {1: 24, 2: 256, 4: 65536, 8: 2**32}[width]:
                raise ValueError('nonminimal')
        else:
            raise ValueError('indefinite/reserved')
        if major == 0 and n <= 2**53-1:
            return n
        if major == 2:
            return take(n)
        if major == 3:
            return take(n).decode('utf8')
        if major == 4:
            if depth >= 32:
                raise ValueError('container depth')
            return [item(depth+1) for _ in range(n)]
        if major == 5:
            if depth >= 32:
                raise ValueError('container depth')
            result, previous = {}, None
            for _ in range(n):
                start = pos
                k = item(depth+1)
                encoded_key = raw[start:pos]
                if not isinstance(k, str) or (previous is not None and encoded_key <= previous):
                    raise ValueError('unordered/duplicate/nontext key')
                previous = encoded_key
                result[k] = item(depth+1)
            return result
        if major == 6 and n == 42:
            if pos == len(raw) or raw[pos] >> 5 != 2:
                raise ValueError("CID tag requires immediate byte string")
            b = item(depth)
            if not isinstance(b, bytes) or not b or b[0] != 0:
                raise ValueError('invalid CID tag payload')
            validate_cid(b[1:])
            return Link(b[1:])
        raise ValueError('unsupported tag/type')

    value = item()
    if pos != len(raw):
        raise ValueError('trailing bytes')
    return value


def fixtures():
    # RFC 1 author syntax; deliberately no claim that this fixture signs anything.
    did = 'did:key:zDnaebVRiiKts4HkYSXknYdTZgmWgwRhGuD8LFXimVqaeJZFc'
    author = {'principal': did, 'verificationMethod': did + '#' + did[8:], 'identityVersion': {'kind': 'static', 'value': None}}
    capture = {'v': 1, 'kind': 'capture', 'body': {
        'observer': author, 'scope': blob(b'\x12\x20' + b'\x01'*32), 'stream': blob(b'\x02'*16),
        'sequence': 0, 'previous': None, 'occurredAt': 1792108800000, 'eventType': 'provider.request',
        'payloads': [{'sha256': blob(hashlib.sha256(b'raw\x00input').digest()), 'length': 9, 'mediaType': 'application/octet-stream'}],
        'parents': [], 'coverage': {'complete': True, 'missing': []}}}
    ciphertext = b'synthetic opaque ciphertext\x00'  # no production encryption claim
    manifest = {'v': 1, 'kind': 'manifest', 'body': {
        'writer': author, 'scopeToken': blob(b'\x03'*32), 'operation': blob(b'\x04'*16), 'position': 0,
        'previous': None, 'entries': [{'slot': blob(b'\x05'*32), 'ciphertext': link(cid(ciphertext, 0x55)), 'length': len(ciphertext)}]}}
    receipt = {'v': 1, 'kind': 'receipt', 'body': {
        'issuer': author, 'manifest': link(cid(encode(manifest))), 'scopeToken': blob(b'\x03'*32), 'operation': blob(b'\x04'*16),
        'position': 0, 'durability': 'remote-durable', 'issuedAt': 1792108800020}}
    positive = []

    def add(name, value, supported=True):
        raw = encode(value)
        assert same_value(decode(raw), from_fixture(value))
        c = cid(raw)
        row = {'name': name, 'value': value, 'hex': raw.hex(), 'cid': c, 'supported': supported}
        if supported:
            row['signingHex'] = encode({'domain': 'tools.kan.evidence.v1', 'kind': value['kind'], 'record': link(c)}).hex()
        positive.append(row)

    add('capture', capture)
    add('manifest', manifest)
    add('receipt', receipt)
    followup = copy.deepcopy(capture)
    followup['body'].update(sequence=1, previous=link(cid(encode(capture))), parents=[link(cid(encode(capture)))], coverage={'complete': False, 'missing': ['harness.unobserved', 'tool.unobserved']})
    followup['body']['payloads'][0]['length'] = 11*1024*1024
    add('partial-large-payload', followup)
    second = copy.deepcopy(manifest)
    second['body'].update(position=1, previous=link(cid(encode(manifest))), operation=blob(b'\x06'*16))
    second['body']['entries'].append({'slot': blob(b'\x07'*32), 'ciphertext': link(cid(b'other ciphertext', 0x55)), 'length': 16})
    add('second-batch', second)
    add('unknown-version', {'v': 2, 'kind': 'capture', 'body': {'future': True}}, False)
    add('unknown-kind', {'v': 1, 'kind': 'future', 'body': {}}, False)
    nested = None
    for _ in range(30):
        nested = [nested]
    add('unknown-at-depth-boundary', {'v': 1, 'kind': 'future', 'body': {'nested': nested, 'maximum': 2**53-1}}, False)
    prefix = b'\x00\x01\x55\x12\x00'
    for name, source, field, size in [
        ('cid-shaped-stream', capture, 'stream', 16),
        ('cid-shaped-operation', manifest, 'operation', 16),
        ('cid-shaped-scope-token', manifest, 'scopeToken', 32),
        ('cid-shaped-receipt-scope', receipt, 'scopeToken', 32),
        ('cid-shaped-receipt-operation', receipt, 'operation', 16),
    ]:
        v = copy.deepcopy(source)
        v['body'][field] = blob(prefix + b'\x04'*(size-len(prefix)))
        add(name, v)
    v = copy.deepcopy(manifest)
    v['body']['entries'][0]['slot'] = blob(prefix + b'\x05'*27)
    add('cid-shaped-slot', v)
    v = copy.deepcopy(capture)
    v['body']['payloads'][0]['sha256'] = blob(prefix + b'\x09'*27)
    add('cid-shaped-payload-hash', v)
    for name, raw_cid in [
        ('cidv0', b'\x12\x20' + b'\x01'*32),
        ('dag-pb', b'\x01\x70\x12\x20' + b'\x02'*32),
        ('sha512', b'\x01\x71\x13\x40' + b'\x03'*64),
        ('blake3', b'\x01\x55\x1e\x20' + b'\x04'*32),
    ]:
        spelling = 'b' + base64.b32encode(raw_cid).decode().lower().rstrip('=')
        add('unknown-' + name, {'v': 2, 'kind': 'future', 'body': {'link': link(spelling)}}, False)
    add('literal-sentinel-maps', {'v': 2, 'kind': 'future', 'body': {
        'bytes-map': {'$map': {'$bytes': '0001'}},
        'link-map': {'$map': {'$link': cid(b'example')}}}}, False)
    add('unknown-nested-cid-shaped-bytes', {'v': 2, 'kind': 'future', 'body': {'nested': [blob(prefix+b'\x01'*32)]}}, False)
    dynamic_authors = []
    for method, kind, state in [('web', 'documentCid', cid(b'document', 0x55)), ('kan', 'event', cid(b'identity-event'))]:
        principal = 'did:web:example.com' if method == 'web' else 'did:kan:zExample'
        dynamic = {'principal': principal, 'verificationMethod': principal+'#k', 'identityVersion': {'kind': kind, 'value': link(state)}}
        dynamic_authors.append((method, dynamic, state))
        for role, source in [('observer', capture), ('writer', manifest), ('issuer', receipt)]:
            v = copy.deepcopy(source)
            v['body'][role] = dynamic
            add(method+'-'+role+'-linked-state', v)
    negatives = []

    def bad(name, value):
        negatives.append({'name': name, 'hex': encode(value).hex(), 'class': 'canonical' if name in ('negative-sequence', 'unsafe-integer', 'unknown-negative', 'unknown-unsafe') else 'schema'})

    def changed(name, source, field, value):
        v = copy.deepcopy(source)
        v['body'][field] = value
        bad(name, v)

    for method, dynamic, state in dynamic_authors:
        for role, source in [('observer', capture), ('writer', manifest), ('issuer', receipt)]:
            for suffix, tail in [('exact', b''), ('trailing', b'\x00')]:
                bad_author = copy.deepcopy(dynamic)
                bad_author['identityVersion']['value'] = blob(b'\x00'+cid_bytes(state)+tail)
                changed(method+'-'+role+'-bytes-state-'+suffix, source, role, bad_author)
    bad('unknown-negative' , {'v': 2, 'kind': 'future', 'body': {'n': -1}})
    bad('unknown-unsafe', {'v': 2, 'kind': 'future', 'body': {'n': 2**53}})
    changed('bad-writer', manifest, 'writer', dict(author, verificationMethod='did:key:other#other'))
    changed('bad-issuer', receipt, 'issuer', dict(author, verificationMethod='did:key:other#other'))
    bad('version-zero', {'v': 0, 'kind': 'capture', 'body': {}})
    bad('unknown-envelope-field', dict(capture, extra=True))
    bad('invalid-kind-token', {'v': 2, 'kind': 'Future', 'body': {}})
    bad('unknown-body-not-map', {'v': 2, 'kind': 'future', 'body': []})
    changed('negative-sequence', capture, 'sequence', -1)
    changed('unsafe-integer', capture, 'occurredAt', 2**53)
    changed('genesis-predecessor', capture, 'previous', link(cid(encode(capture))))
    changed('missing-predecessor', capture, 'sequence', 1)
    changed('bad-scope', capture, 'scope', blob(b'\x00'*34))
    changed('bad-stream', capture, 'stream', blob(b'\x02'*15))
    changed('duplicate-parents', capture, 'parents', [link(cid(encode(capture)))]*2)
    changed('too-many-payloads', capture, 'payloads', capture['body']['payloads']*129)
    changed('coverage-inconsistent', capture, 'coverage', {'complete': True, 'missing': ['gap']})
    changed('coverage-unsorted', capture, 'coverage', {'complete': False, 'missing': ['z', 'a']})
    changed('coverage-duplicate', capture, 'coverage', {'complete': False, 'missing': ['gap', 'gap']})
    changed('empty-media-type', capture, 'payloads', [dict(capture['body']['payloads'][0], mediaType='')])
    changed('bad-author', capture, 'observer', dict(author, verificationMethod='did:key:other#other'))
    changed('unknown-author-field', capture, 'observer', dict(author, extra=True))
    changed('private-field-in-manifest', manifest, 'payloads', capture['body']['payloads'])
    changed('empty-manifest', manifest, 'entries', [])
    changed('duplicate-slots', manifest, 'entries', manifest['body']['entries']*2)
    changed('unsorted-slots', second, 'entries', list(reversed(second['body']['entries'])))
    changed('wrong-ciphertext-codec', manifest, 'entries', [dict(manifest['body']['entries'][0], ciphertext=link(cid(ciphertext)))])
    changed('zero-ciphertext-length', manifest, 'entries', [dict(manifest['body']['entries'][0], length=0)])
    changed('unknown-durability', receipt, 'durability', 'backed-up')
    changed('short-operation', receipt, 'operation', blob(b'\x04'*15))
    missing = copy.deepcopy(capture)
    del missing['body']['previous']
    bad('missing-null-field', missing)
    # Explicit malformed bytes, including an otherwise valid envelope with a
    # widened version integer. These exercise more than schema validation.
    raw = encode(capture)
    malformed = {
        'nonminimal-version': raw.replace(b'\x61v\x01', b'\x61v\x18\x01', 1),
        'trailing-byte': raw + b'\x00', 'truncated': raw[:-1],
        'duplicate-key': bytes.fromhex('a2617601617601'),
        'unordered-keys': bytes.fromhex('a2616201616101'),
        'indefinite-map': bytes.fromhex('bf616101ff'),
        'float': bytes.fromhex('fb3ff0000000000000'),
        'unknown-tag': bytes.fromhex('c100'),
        'oversized-declared-bytes': bytes.fromhex('5bffffffffffffffff'),
        'invalid-utf8': bytes.fromhex('61ff'),
        'too-many-containers': encode({'v': 2, 'kind': 'future', 'body': {'nested': [nested]}}),
    }
    cid_payload = b'\x00' + cid_bytes(cid(b'tag probe'))
    literal = encode_value({'$bytes': cid_payload.hex()})
    malformed['tagged-literal-bytes-map'] = b'\xd8\x2a' + literal
    for name, payload in [
        ('trailing-cid', cid_payload+b'\x00'),
        ('nonminimal-cid', b'\x00\x81\x00'+cid_payload[2:]),
        ('missing-cid-prefix', cid_payload[1:]),
    ]:
        malformed[name] = b'\xd8\x2a' + head(2, len(payload)) + payload
    for name, raw in malformed.items():
        negatives.append({'name': name, 'hex': raw.hex(), 'class': 'canonical'})
    # Independently pinned examples from the RFC decision table. Trust exclusions
    # describe a downstream display; they do not change source inventory.
    inventory = [
        [False, 'same', True, 0, True, 0, 'access-limited'],
        [False, None, False, 2, False, 2, 'access-limited'],
        [True, None, True, 0, True, 0, 'incomplete'],
        [True, 'other', True, 0, True, 0, 'incomplete'],
        [True, 'same', False, 0, False, 0, 'incomplete'],
        [True, 'same', True, 2, False, 0, 'incomplete'],
        [True, 'same', False, 0, True, 0, 'present-incomplete'],
        [True, 'same', True, 2, True, 0, 'present-incomplete'],
        [True, 'same', True, 0, True, 0, 'present-complete'],
        [True, 'same', True, 0, True, 2, 'present-complete'],
        [True, 'same', True, 0, False, 0, 'absent-at-snapshot'],
        [True, 'same', True, 0, False, 2, 'absent-at-snapshot'],
    ]
    operations = [[False, None, 'unauthorized'], [False, 'same', 'unauthorized'],
                  [False, 'other', 'unauthorized'], [True, None, 'new'],
                  [True, 'same', 'duplicate'], [True, 'other', 'conflict']]
    return {'profile': 'experimental-rfc4-v1', 'positive': positive, 'negative': negatives,
            'inventoryColumns': ['authorized', 'covered', 'fullyIndexed', 'unsupported', 'hasMatch', 'displayExcluded', 'result'],
            'inventory': inventory, 'operationColumns': ['admitted', 'existing', 'result'], 'operations': operations}


def same_value(left, right):
    """IPLD/fixture equality must not equate Python bool, int and float."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_value(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same_value(a, b) for a, b in zip(left, right))
    return left == right


def check(data):
    expected = fixtures()
    if not same_value(data, expected):
        raise ValueError('pinned vectors differ from independent oracle')
    for vector in data['positive']:
        raw = bytes.fromhex(vector['hex'])
        if not same_value(decode(raw), from_fixture(vector['value'])) or cid(raw) != vector['cid']:
            raise ValueError('byte/CID mismatch')
    for vector in data['negative']:
        if vector['class'] == 'canonical':
            try:
                decode(bytes.fromhex(vector['hex']))
            except (ValueError, UnicodeError):
                continue
            raise ValueError('decoder accepted ' + vector['name'])
        else:
            decode(bytes.fromhex(vector['hex']))  # schema-invalid must still be canonical


def self_test():
    assert not same_value(True, 1) and not same_value(1.0, 1)
    assert not same_value({'x': [True]}, {'x': [1]})
    altered = fixtures()
    altered['positive'][0]['value']['body']['coverage']['complete'] = 1
    try:
        check(altered)
    except ValueError:
        pass
    else:
        raise AssertionError('oracle missed bool/integer fixture substitution')
    probe = {'v': 2, 'kind': 'future', 'body': {'bytes': b'x'*65000}}
    overhead = len(encode_value(probe))-65000
    for size in (65536, 65537):
        probe['body']['bytes'] = b'x'*(size-overhead)
        raw = encode_value(probe)
        assert len(raw) == size
        try:
            decode(raw)
        except ValueError:
            assert size == 65537
        else:
            assert size == 65536
    actual_link = Link(cid_bytes(cid(b'type control')))
    for value in (b'\x00\x01\x55\x12\x00', actual_link,
                  {'$bytes': '0001551200'}, {'$link': cid(b'type control')}):
        assert decode(encode_value(value)) == value
    assert decode(encode_value(actual_link)) != decode(encode_value({'$link': cid(b'type control')}))
    data = fixtures()
    data['positive'][0]['cid'] = cid(b'wrong')
    try:
        check(data)
    except ValueError:
        return
    raise AssertionError('oracle missed corrupted golden CID')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check', action='store_true')
    group.add_argument('--write', action='store_true')
    args = parser.parse_args()
    self_test()
    if args.write:
        FIXTURE.write_text(json.dumps(fixtures(), indent=2) + '\n')
    data = json.loads(FIXTURE.read_text())
    check(data)
    print(f"Evidence oracle: {len(data['positive'])} positive, {len(data['negative'])} negative vectors; corruption self-test passed")


if __name__ == '__main__':
    main()
