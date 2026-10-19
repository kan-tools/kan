#!/usr/bin/env python3
"""Reviewer-only: hand-rolled CBOR encoder producing noncanonical/hostile copy plans.

Independent of scripts/evidence_reference.py. Input: copy-plan-v1.json; output JSON list
of {name, hex, expect} where expect is "accept" or "refuse".
"""
import base64, hashlib, json, struct, sys

def head(major, n, width=None):
    if width is None:
        width = 0 if n < 24 else 1 if n < 256 else 2 if n < 65536 else 4 if n < 2**32 else 8
    if width == 0:
        return bytes([major << 5 | n])
    code = {1: 24, 2: 25, 4: 26, 8: 27}[width]
    return bytes([major << 5 | code]) + n.to_bytes(width, 'big')

def cid_bytes(s):
    assert s[0] == 'b'
    t = s[1:].upper()
    t += '=' * (-len(t) % 8)
    return base64.b32decode(t)

def enc(v, opt):
    if v is None:
        return b'\xf6'
    if v is True:
        return b'\xf5'
    if v is False:
        return b'\xf4'
    if isinstance(v, float):
        return b'\xfb' + struct.pack('>d', v)
    if isinstance(v, int):
        if v >= 0:
            return head(0, v, opt.get('intwidth') if opt.get('intkey') == opt.get('_key') else None)
        return head(1, -1 - v)
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, dict) and set(v) == {'$link'}:
        raw = b'\x00' + cid_bytes(v['$link'])
        return b'\xd8\x2a' + head(2, len(raw)) + raw
    if isinstance(v, dict) and set(v) == {'$bytes'}:
        return enc(bytes.fromhex(v['$bytes']), opt)
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(enc(x, opt) for x in v)
    if isinstance(v, dict):
        items = list(v.items())
        order = opt.get('order', 'canonical')
        if order == 'canonical':
            items.sort(key=lambda kv: (len(kv[0].encode()), kv[0].encode()))
        elif order == 'lexical':
            items.sort(key=lambda kv: kv[0].encode())
        out = b''
        for k, x in items:
            out += enc(k, opt)
            o = dict(opt); o['_key'] = k
            out += enc(x, o)
        for k, x in opt.get('dup', []):
            out += enc(k, opt) + enc(x, opt)
        n = len(items) + len(opt.get('dup', []))
        if opt.get('indefinite'):
            return b'\xbf' + out + b'\xff'
        return head(5, n) + out
    raise TypeError(type(v))

def main():
    fx = json.load(open(sys.argv[1]))
    base = fx['positive'][0]['plan']
    canon = enc(base, {})
    assert canon.hex() == fx['positive'][0]['hex'], 'reviewer encoder disagrees with fixture'
    domain = bytes.fromhex(fx['domainHex'])
    assert domain == b'tools.kan.archive.copy-plan.v1\x00'
    assert hashlib.sha256(domain + canon).hexdigest() == fx['positive'][0]['archiveHex']
    out = [{'name': 'reviewer-canonical-roundtrip', 'hex': canon.hex(), 'expect': 'accept'}]
    def add(name, value, opt=None, expect='refuse'):
        out.append({'name': name, 'hex': enc(value, opt or {}).hex(), 'expect': expect})
    add('keys-lexical-order', base, {'order': 'lexical'})
    add('keys-json-insertion-order', base, {'order': 'none'})
    rev = dict(reversed(list(base.items())))
    add('keys-insertion-reversed', rev, {'order': 'none'})
    add('nonminimal-through-1byte', base, {'intkey': 'sourceThrough', 'intwidth': 1})
    add('nonminimal-through-8byte', base, {'intkey': 'sourceThrough', 'intwidth': 8})
    add('nonminimal-recipe', base, {'intkey': 'recipe', 'intwidth': 2})
    add('indefinite-map', base, {'indefinite': True})
    add('duplicate-nonce', base, {'dup': [('nonce', bytes(32))]})
    v = dict(base); v['sourceThrough'] = 1.0; add('float-through', v)
    v = dict(base); v['historicalIssuer'] = base['historicalIssuer'] + '#frag'; add('historical-with-fragment', v)
    v = dict(base); v['issuer'] = 'did:key:Z' + base['issuer'][9:]; add('issuer-uppercase-multibase', v)
    v = dict(base); v['issuer'] = base['issuer'] + ' '; add('issuer-trailing-space', v)
    v = dict(base); v['historicalIssuer'] = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'; add('historical-ed25519', v, expect='observe')
    # CID with sha2-512 multihash but dag-cbor codec, and CIDv0-shaped bytes inside tag 42.
    tip = cid_bytes(base['sourceTip']['$link'])
    sha512 = bytes([1, 0x71, 0x13, 0x40]) + hashlib.sha512(b'x').digest()
    v = dict(base); v['sourceTip'] = {'$link': 'b' + base64.b32encode(sha512).decode().lower().rstrip('=')}; add('tip-sha512', v)
    v = dict(base); v['sourceTip'] = {'$link': base['sourceTip']['$link']}
    raw_bad_prefix = enc(v, {}).replace(b'\xd8\x2a\x58\x25\x00' + tip, b'\xd8\x2a\x58\x25\x01' + tip)
    out.append({'name': 'tag42-missing-identity-prefix', 'hex': raw_bad_prefix.hex(), 'expect': 'refuse'})
    v = dict(base); v['sourceDigest'] = {'$bytes': '00' * 33}; add('long-digest', v)
    v = dict(base); v['nonce'] = {'$bytes': ''}; add('empty-nonce', v)
    v = dict(base); v['sourceThrough'] = 0; v['sourceTip'] = None; add('empty-source', v, expect='accept')
    v = dict(base); v['recipe'] = -1; add('negative-recipe', v)
    json.dump(out, sys.stdout, indent=1)

if __name__ == '__main__':
    main()
