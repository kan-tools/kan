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
from pathlib import Path

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


def encode(value):
    if value is None:
        return b'\xf6'
    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, int):
        return head(0 if value >= 0 else 1, value if value >= 0 else -1-value)
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(map(encode, value))
    if isinstance(value, dict):
        if set(value) == {'$bytes'}:
            raw = bytes.fromhex(value['$bytes'])
            return head(2, len(raw)) + raw
        if set(value) == {'$link'}:
            raw = b'\x00' + cid_bytes(value['$link'])
            return b'\xd8\x2a' + head(2, len(raw)) + raw
        pairs = sorted((encode(k), encode(v)) for k, v in value.items())
        return head(5, len(pairs)) + b''.join(k + v for k, v in pairs)
    raise ValueError('unsupported value')


def decode(raw):
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
        if major == 0:
            return n
        if major == 1:
            return -1-n
        if major == 2:
            return blob(take(n))
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
            b = item(depth)
            if not isinstance(b, dict) or set(b) != {'$bytes'}:
                raise ValueError('invalid CID tag payload')
            b = bytes.fromhex(b['$bytes'])
            if len(b) != 37 or b[0] != 0 or b[1] != 1 or b[2] not in (0x55, 0x71) or b[3:5] != b'\x12\x20':
                raise ValueError('CID outside vector profile')
            return link('b' + base64.b32encode(b[1:]).decode().lower().rstrip('='))
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
        assert decode(raw) == value
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
    negatives = []

    def bad(name, value):
        negatives.append({'name': name, 'hex': encode(value).hex(), 'class': 'schema'})

    def changed(name, source, field, value):
        v = copy.deepcopy(source)
        v['body'][field] = value
        bad(name, v)

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
    for name, raw in malformed.items():
        negatives.append({'name': name, 'hex': raw.hex(), 'class': 'canonical'})
    return {'profile': 'experimental-rfc4-v1', 'positive': positive, 'negative': negatives}


def check(data):
    expected = fixtures()
    if data != expected:
        raise ValueError('pinned vectors differ from independent oracle')
    for vector in data['positive']:
        raw = bytes.fromhex(vector['hex'])
        if decode(raw) != vector['value'] or cid(raw) != vector['cid']:
            raise ValueError('byte/CID mismatch')
    for vector in data['negative']:
        if vector['class'] == 'canonical':
            try:
                decode(bytes.fromhex(vector['hex']))
            except (ValueError, UnicodeError):
                continue
            raise ValueError('decoder accepted ' + vector['name'])


def self_test():
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
