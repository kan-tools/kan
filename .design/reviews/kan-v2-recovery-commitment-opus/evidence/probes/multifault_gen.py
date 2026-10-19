#!/usr/bin/env python3
"""Generate signed multi-fault observation envelopes with the author's independent
oracle (public scalar 3 only), record Python's refusal label. Rust labels are
measured separately by zz_review_multifault.rs.  Usage: multifault_gen.py <out.json>"""
import copy, importlib.util, json, sys
from pathlib import Path
E = Path('/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state/.local-state/reviews/recovery-commitment')
spec = importlib.util.spec_from_file_location('oracle', E / '.design/tools/recovery_observation_vectors.py')
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)
f = o.decode_notation(json.load(open(E / '.design/fixtures/recovery-observation-v1.json'))) if hasattr(o, 'decode_notation') else None
gen = o.vectors()
assert json.loads(json.dumps(gen, default=str)) is not None
rows = gen['positive']
# run1 bug: gen['context'] is notation-typed; the oracle's own checks() converts the stored context.
ctx = o.codec.from_fixture(json.load(open(E / '.design/fixtures/recovery-observation-v1.json'))['context'])
cases = []
def add(name, base, st, note):
    env = o.sign(st)
    prev = None
    if base > 0:
        prev = o.verify(bytes.fromhex(rows[0]['envelopeHex']), ctx, None)
        for i in range(1, base):
            prev = o.verify(bytes.fromhex(rows[i]['envelopeHex']), ctx, prev)
    try:
        o.verify(env, ctx, prev); label = 'ACCEPTED'
    except o.Rejected as e:
        label = str(e)
    cases.append({'name': name, 'base': base, 'envelopeHex': env.hex(), 'python': label, 'note': note})
# 1: created at sequence 2 (position fault) AND 31-byte member (body fault)
st = copy.deepcopy(rows[1]['statement']); st['event'] = 'created'
st['body'] = copy.deepcopy(rows[0]['statement']['body']); st['body']['member'] = o.codec.blob(bytes(31))
add('created-later+short-member', 1, st, 'position + body width')
# 2: unavailable at sequence 1 (position fault) AND zero entries (body fault)
st = copy.deepcopy(rows[0]['statement']); st['event'] = 'unavailable'
st['body'] = copy.deepcopy(rows[1]['statement']['body']); st['body']['entries'] = []
add('unavailable-first+empty-entries', 0, st, 'position + entries bound')
# 3: control - both orders agree (single body fault at correct position)
st = copy.deepcopy(rows[0]['statement']); st['body']['member'] = o.codec.blob(bytes(31))
add('single-fault-short-member', 0, st, 'single fault, agreement expected')
json.dump({'context_from': 'fixture context (identical generator)', 'cases': cases}, open(sys.argv[1], 'w'), indent=1)
for c in cases: print(c['name'], 'python=', c['python'])
