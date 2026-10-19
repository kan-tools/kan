#!/usr/bin/env python3
"""Reviewer scope-B probes: issuer-referenced candidate writer binding.
Expectations from codec.md 'Replay review follow-through' (A-F1(a)), not Rust."""
import json, sys
from pathlib import Path
EXPORT = Path(sys.argv[2]); sys.path.insert(0, str(EXPORT / '.design/tools'))
import recovery_replay_vectors as rv, recovery_bundle_files as rbf
members, frame, codec = rv.members, rv.frame, rv.codec; att = members.att
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True); cases = []
def add(name, h, expect):
    env = h.encoded()
    c = {'name': name, 'member': members.pack(name, h.m, h.observer, complete=rv.complete(h.m)),
         'candidates': [[cid, b.hex()] for cid, b in h.candidates], 'observations': [b.hex() for b in env],
         'checkpoint': h.checkpoint, 'designExpect': expect}
    try: rv.replay(h, env); c['pythonOracle'] = 'accept'
    except Exception as e: c['pythonOracle'] = 'refuse:' + str(e)
    cases.append(c); rbf.create(out / (name + '.sqlite'), c)
def rebind(edit, key):
    m, o = members.build(2, 1); value = json.loads(m['objects'][0][1]); req = value['request']; edit(req)
    raw = members.canonical({'request': req, 'signature': members.sign_json(req, key)}); cid = frame.raw_cid(raw)
    man = codec.decode(m['records'][0][1]); e = man['body']['entries'][0]
    e['ciphertext'] = codec.Link(codec.cid_bytes(cid)); e['length'] = len(raw); mb = codec.encode(man)
    rec = codec.decode(m['records'][0][2]); rec['body']['manifest'] = codec.Link(codec.cid_bytes(codec.cid(mb)))
    m['records'][0][1] = mb; m['records'][0][2] = codec.encode(rec); m['objects'] = []; members.resign(m)
    h = rv.History(m, o); h.initial(); h.restore(cid, raw); return h
wk, writer = att.identity(5); fk, foreign = att.identity(7)
def other_ciphertext(r): r['command']['ciphertext'] = b'reviewer ciphertext'.hex()
add('B1-correct-writer-resigned-new-ciphertext-control', rebind(other_ciphertext, wk), 'accept')
def foreign_principal(r): r['principal'] = foreign['principal']
add('B2-foreign-principal-valid-signature', rebind(foreign_principal, fk), 'refuse:candidate writer request')
def foreign_audience(r): r['audience'] = foreign['principal']
add('B3-wrong-audience-valid-writer-signature', rebind(foreign_audience, wk), 'refuse:candidate writer request')
def signed_by_foreign_key(r): pass
add('B4-writer-principal-signed-by-foreign-key', rebind(signed_by_foreign_key, fk), 'refuse:candidate writer request')
(out / 'cases.json').write_text(json.dumps({'cases': cases}, indent=1))
for c in cases: print(c['name'], 'designExpect=' + c['designExpect'], 'pythonOracle=' + c['pythonOracle'])
