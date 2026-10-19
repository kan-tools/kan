#!/usr/bin/env python3
"""Reviewer probe generator (independent of the author's corpus selection).
Builds signed histories with the repo's public test-key primitives and writes
physical KNB1 files with the author's fixture constructor. Expectations come
from the design text, not Rust. Usage: gen_physical_probes.py OUT_DIR
"""
import json, os, subprocess, sys, sqlite3, shutil
from pathlib import Path
EXPORT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.cwd()
TOOLS = EXPORT / '.design/tools'
sys.path.insert(0, str(TOOLS))
import recovery_replay_vectors as rv
import recovery_bundle_files as rbf
members, frame, codec = rv.members, rv.frame, rv.codec
out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
cases = []
def add(name, h, design_expect):
    env = h.encoded()
    c = {'name': name, 'member': members.pack(name, h.m, h.observer, complete=rv.complete(h.m)),
         'candidates': [[cid, b.hex()] for cid, b in h.candidates],
         'observations': [b.hex() for b in env], 'checkpoint': h.checkpoint,
         'designExpect': design_expect}
    try:
        rv.replay(h, env); c['pythonOracle'] = 'accept'
    except Exception as e:
        c['pythonOracle'] = 'refuse:' + str(e)
    cases.append(c)
    rbf.create(out / (name + '.sqlite'), c)
# E1: original-only key whose retained original BLOB is empty (design: preserve
# empty original bytes as retained corrupt evidence; it is a loss, not absent).
m, o = members.build(2, 0); tcid = frame.raw_cid(b'correct'); m['objects'] = [[tcid, b'']]
h = rv.History(m, o); h.initial()
add('E1-empty-original-initial-loss', h, 'accept')
# E2: same, then a valid restoration of the correct bytes.
m, o = members.build(2, 0); tcid = frame.raw_cid(b'correct'); m['objects'] = [[tcid, b'']]
h = rv.History(m, o); h.initial(); h.restore(tcid, b'correct')
add('E2-empty-original-restored', h, 'accept')
# E3 control: identical shape with a one-byte corrupt original.
m, o = members.build(2, 0); tcid = frame.raw_cid(b'correct'); m['objects'] = [[tcid, b'x']]
h = rv.History(m, o); h.initial(); h.restore(tcid, b'correct')
add('E3-nonempty-corrupt-original-restored-control', h, 'accept')
(out / 'cases.json').write_text(json.dumps({'cases': cases}, indent=1))
for c in cases: print(c['name'], 'designExpect=' + c['designExpect'], 'pythonOracle=' + c['pythonOracle'])
