#!/usr/bin/env python3
"""Reviewer scope-A probe generator (not the author's selection).
Signed histories use the repo's public test-key primitives (recovery_replay_vectors);
physical files use the author's fixture constructor, then reviewer SQL mutations.
Expectations are written from the design text before running Rust:
  - empty original BLOB = retained corrupt evidence (a loss), must be accepted
  - source TEXT / empty candidate must still refuse.
Usage: gen_A_probes.py OUT_DIR EXPORT_DIR
"""
import json, sys, sqlite3
from pathlib import Path
out = Path(sys.argv[1]); EXPORT = Path(sys.argv[2])
sys.path.insert(0, str(EXPORT / '.design/tools'))
import recovery_replay_vectors as rv
import recovery_bundle_files as rbf
members, frame = rv.members, rv.frame
out.mkdir(parents=True, exist_ok=True)
cases = []

def add(name, m, observer, restores, expect, sql=None, expect_err=None):
    h = rv.History(m, observer); h.initial()
    for cid, data in restores:
        h.restore(cid, data)
    env = h.encoded()
    c = {'name': name, 'member': members.pack(name, m, observer, complete=rv.complete(m)),
         'candidates': [[cid, b.hex()] for cid, b in h.candidates],
         'observations': [b.hex() for b in env], 'checkpoint': h.checkpoint,
         'designExpect': expect, 'expectErr': expect_err, 'sql': sql,
         'emptyOriginals': [cid for cid, b in m['objects'] if b == b'']}
    try:
        rv.replay(h, env); c['pythonOracle'] = 'accept'
    except Exception as e:
        c['pythonOracle'] = 'refuse:' + str(e)
    path = out / (name + '.sqlite')
    rbf.create(path, c)
    if sql:
        db = sqlite3.connect(path)
        db.execute('PRAGMA ignore_check_constraints=ON')
        cur = db.execute(sql)
        c['sqlChanged'] = cur.rowcount
        db.commit(); db.close()
    cases.append(c)

# PA1/PA2: COMPLETE profile 3 (not covered by author's E4/E5 partial cases).
def p3_complete():
    m, o = members.build(3, 3)
    cid, correct = m['objects'][0]
    m['objects'][0] = [cid, b'']
    return m, o, cid, correct
m, o, cid, correct = p3_complete()
add('PA1-p3-complete-empty-original-initial-loss', m, o, [], 'accept')
m, o, cid, correct = p3_complete()
add('PA2-p3-complete-empty-original-restored', m, o, [(cid, correct)], 'accept')
# PA3: partial profile 3, TWO empty originals, only one restored.
m, o = members.build(3, 3); m['records'] = m['records'][:1]
(c0, k0), (c1, k1) = m['objects'][0], m['objects'][1]
m['objects'][0] = [c0, b'']; m['objects'][1] = [c1, b'']
add('PA3-p3-partial-two-empty-one-restored', m, o, [(c0, k0)], 'accept')
# PA4: profile 2, two original-only keys, both empty, both restored.
m, o = members.build(2, 0)
ca, cb = frame.raw_cid(b'alpha'), frame.raw_cid(b'beta')
m['objects'] = sorted([[ca, b''], [cb, b'']])
add('PA4-p2-two-empty-both-restored', m, o, sorted([(ca, b'alpha'), (cb, b'beta')]), 'accept')
# Hostile physical mutations of otherwise-accepted histories.
m, o, cid, correct = p3_complete()
add('PH1-empty-original-stored-as-TEXT', m, o, [], 'refuse',
    "UPDATE member_objects SET bytes=CAST(x'' AS TEXT) WHERE length(bytes)=0", 'cell storage class')
m, o, cid, correct = p3_complete()
add('PH2-empty-candidate-blob', m, o, [(cid, correct)], 'refuse',
    "UPDATE restored_objects SET bytes=x''", 'integer storage class or bounds')
m, o, cid, correct = p3_complete()
add('PH3-empty-candidate-TEXT', m, o, [(cid, correct)], 'refuse',
    "UPDATE restored_objects SET bytes=CAST(x'' AS TEXT)", 'cell storage class')
m, o, cid, correct = p3_complete()
add('PH4-empty-original-rewritten-as-zeroblob0', m, o, [], 'accept',
    "UPDATE member_objects SET bytes=zeroblob(0) WHERE length(bytes)=0")
m, o, cid, correct = p3_complete()
# A nonempty original made empty AFTER signing: the history committed to the
# nonempty object, so the physical file no longer matches -> must refuse (not
# be smoothed over by the empty-projection admission).
add('PH5-nonempty-original-truncated-to-empty-after-signing', m, o, [], 'refuse',
    "UPDATE member_objects SET bytes=x'' WHERE length(bytes)>0 AND cid=(SELECT min(cid) FROM member_objects WHERE length(bytes)>0)", None)
m, o, cid, correct = p3_complete()
# Retained empty original replaced by a NUL byte (1 byte) after signing -> refuse.
add('PH6-empty-original-replaced-by-one-byte', m, o, [], 'refuse',
    "UPDATE member_objects SET bytes=x'00' WHERE length(bytes)=0", None)
(out / 'cases.json').write_text(json.dumps({'cases': cases}, indent=1))
for c in cases:
    print(c['name'], 'designExpect=' + c['designExpect'], 'pythonOracle(pre-mutation history)=' + c['pythonOracle'],
          'sqlChanged=' + str(c.get('sqlChanged')), 'emptyOriginals=%d' % len(c['emptyOriginals']))
