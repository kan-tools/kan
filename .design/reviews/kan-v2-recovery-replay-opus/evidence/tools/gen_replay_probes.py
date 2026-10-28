#!/usr/bin/env python3
"""Reviewer probe corpus for pure recovery replay (outside the author's 45 cases).

Uses the author's *member/wire/framing primitives* only to construct signed
histories (public test keys). Expected acceptance/refusal comes from the design
text (.design/kan-v2-recovery-bundle-codec.md); expected R1/O1 for positive
cases are computed here directly from frame.restoration_digest/member_digest
over a union this script builds itself. No Rust-derived value is used.
Writes only to the path given as argv[1].
"""
import copy, hashlib, json, sys
from pathlib import Path

TOOLS = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(TOOLS))
import recovery_replay_vectors as rv   # noqa: E402  (History/base helpers)
members, frame, codec, wire = rv.members, rv.frame, rv.codec, rv.wire

OUT = Path(sys.argv[1])
cases = []


def text(link):
    return rv.text(link)


def union_objects(m, selected):
    """Design: union of original object keys, record refs, membership keys."""
    keys = set(c for c, _ in m['membership']) | set(c for c, _ in m['objects'])
    for _, mb, _, _ in m['records']:
        for e in codec.decode(mb)['body']['entries']:
            keys.add(text(e['ciphertext']))
    original = dict(m['objects'])
    sel = dict(selected)
    return [[c, sel.get(c, original.get(c))] for c in sorted(keys)]


def my_r1_o1(m, selected):
    return (frame.restoration_digest(sorted(selected)),
            frame.member_digest({**m, 'objects': union_objects(m, selected)}, True))


def add(name, h, expect, env_edit=None, note=''):
    env = h.encoded()
    if env_edit:
        env_edit(env)
    c = {'name': name, 'note': note,
         'member': members.pack(name, h.m, h.observer, complete=rv.complete(h.m)),
         'candidates': [[cid, b.hex()] for cid, b in h.candidates],
         'observations': [b.hex() for b in env],
         'checkpoint': h.checkpoint, 'expect': expect}
    # Author oracle verdict recorded separately (not used as expectation).
    try:
        rv.replay(h, env)
        c['authorOracle'] = 'accept'
    except Exception as e:  # noqa: BLE001
        c['authorOracle'] = 'refuse:' + str(e)
    if expect.get('accept'):
        c['expect']['latestCid'] = codec.cid(codec.decode(env[-1])['statement'])
        c['expect']['latestSequence'] = len(env)
    cases.append(c)


def att(h, idx, selected, observed_at, failures):
    r1, o1 = my_r1_o1(h.m, selected)
    env = h.encoded()
    intent = codec.cid(codec.decode(env[idx])['statement'])
    return {'id': h.events[idx][1]['attempt'].hex(), 'intent': intent, 'output': o1.hex(),
            'restorations': r1.hex(), 'failureCount': failures, 'observedAt': observed_at}


# P01 writer-invalid request restored with no intent: design says restoration is a
# content-address check only (writer re-audit happens at intent). Expect ACCEPT.
m, o = members.build(2, 1)
request = json.loads(m['objects'][0][1]); sig = bytearray.fromhex(request['signature']); sig[7] ^= 1
request['signature'] = sig.hex(); bad = members.canonical(request); badcid = frame.raw_cid(bad)
man = codec.decode(m['records'][0][1]); e = man['body']['entries'][0]
e['ciphertext'] = codec.Link(codec.cid_bytes(badcid)); e['length'] = len(bad); mb = codec.encode(man)
rec = codec.decode(m['records'][0][2]); rec['body']['manifest'] = codec.Link(codec.cid_bytes(codec.cid(mb)))
m['records'][0][1] = mb; m['records'][0][2] = codec.encode(rec); m['objects'] = []; members.resign(m)
bad_member = copy.deepcopy(m)
h = rv.History(m, o); h.initial(); h.restore(badcid, bad)
add('P01-writer-invalid-restoration-without-intent', h,
    {'accept': True, 'restoredObjects': [{'cid': badcid, 'length': len(bad), 'basis': 'IssuerMetadata'}], 'attempts': []},
    note='asymmetry probe: same bytes as an original refuse the member (P02)')
# P02 same bytes present as the original object: member refuses (hash-valid, bad writer).
m2 = copy.deepcopy(bad_member); m2['objects'] = [[badcid, bad]]
h = rv.History(m2, o); h.initial()
add('P02-writer-invalid-bytes-as-original-refuse-member', h, {'accept': False, 'error': 'member:retained writer request'})

# P03 issuer-signed false length; true bytes as candidate. Expect 'candidate expected length'.
m, o = members.build(2, 1); raw = m['objects'][0][1]; rcid = m['objects'][0][0]
man = codec.decode(m['records'][0][1]); man['body']['entries'][0]['length'] = len(raw) + 1; mb = codec.encode(man)
rec = codec.decode(m['records'][0][2]); rec['body']['manifest'] = codec.Link(codec.cid_bytes(codec.cid(mb)))
m['records'][0][1] = mb; m['records'][0][2] = codec.encode(rec); m['objects'] = []; members.resign(m)
h = rv.History(m, o); h.initial(); h.restore(rcid, raw)
add('P03-false-signed-length-candidate', h, {'accept': False, 'error': 'candidate expected length'})

# P04 corrupt orphan, intent with the O1 a buggy verifier would compute over the corrupt bytes.
h, _ = rv.base(2, False); orphan = frame.raw_cid(b'orphan'); h.m['objects'].append([orphan, b'corrupt']); h.m['objects'].sort()
h.events = []; h.initial()
r1, o1 = my_r1_o1(h.m, [])
h.add('publication-intent', {'attempt': b'\x09' * 16, 'member': frame.member_digest(h.m), 'restorations': r1,
                             'output': o1, 'frontier': rv.frontier(h.m)})
add('P04-corrupt-orphan-with-self-consistent-o1', h, {'accept': False, 'error': 'publication-blocked-unavailable-object'})

# P05 restored event with wrong candidate bytes and no intent. Expect 'candidate hash'.
h, saved = rv.base(2, True); cid0, b0 = saved[0]; wrong = b'x' * len(b0)
h.restore(cid0, wrong)
add('P05-restored-wrong-bytes-without-intent', h, {'accept': False, 'error': 'candidate hash'})

# P06 two intents over the same selection (cache reuse), failure, interleaved outcomes.
h, _ = rv.base(2, False); a = h.intent(9); h.outcome(a, 'publication-failed'); b = h.intent(10); h.outcome(b); h.outcome(a)
add('P06-same-selection-two-attempts-interleaved', h,
    {'accept': True, 'restoredObjects': [], 'attempts': [att(h, a, [], 6, 1), att(h, b, [], 5, 0)]})

# P07 restoration of an already-available key after the intent, before observed.
h, saved = rv.base(2, False); a = h.intent(); h.restore(*saved[0]); h.outcome(a)
add('P07-restore-after-intent-before-observed', h,
    {'accept': True, 'restoredObjects': [{'cid': saved[0][0], 'length': len(saved[0][1]), 'basis': 'IssuerMetadata'}],
     'attempts': [att(h, a, [], 4, 0)]})

# P08 observed for attempt A citing attempt B's intent.
h, _ = rv.base(2, False); a = h.intent(9); b = h.intent(10); h.outcome(a); h.events[-1][1]['intentIndex'] = b
add('P08-observed-cites-other-attempts-intent', h, {'accept': False, 'error': 'intent citation'})

# P09 failure citing the created statement.
h, _ = rv.base(2, False); a = h.intent(9); h.outcome(a, 'publication-failed'); h.events[-1][1]['intentIndex'] = 0
add('P09-failed-cites-created', h, {'accept': False, 'error': 'intent citation'})

# P10/P11 wrong frontier in intent / observed.
h, _ = rv.base(2, False); a = h.intent(); h.events[a][1]['frontier'] = {'through': 0, 'manifest': None, 'attestation': None}
add('P10-intent-wrong-frontier', h, {'accept': False, 'error': 'metadata frontier'})
h, _ = rv.base(2, False); a = h.intent(); h.outcome(a); h.events[-1][1]['frontier'] = {'through': 0, 'manifest': None, 'attestation': None}
add('P11-observed-wrong-frontier', h, {'accept': False, 'error': 'metadata frontier'})

# P12 unavailable carrying a wrong member digest.
h, _ = rv.base(2, True); h.events[1][1]['member'] = b'\xee' * 32
add('P12-unavailable-wrong-member', h, {'accept': False, 'error': 'member commitment'})

# P13..P15 partition edges: exactly 32, exactly 64, and 32 split 16+16.
h, _ = rv.base(2, True, 32); add('P13-exactly-32-losses-one-event', h, {'accept': True, 'restoredObjects': [], 'attempts': []})
h, _ = rv.base(2, True, 64); add('P14-exactly-64-losses-two-events', h, {'accept': True, 'restoredObjects': [], 'attempts': []})
h, _ = rv.base(2, True, 32); ent = h.events[1][1]['entries']; h.events[1][1]['entries'] = ent[:16]
h.events.insert(2, ['unavailable', {'member': frame.member_digest(h.m), 'entries': ent[16:]}])
add('P15-32-losses-split-16-16', h, {'accept': False, 'error': 'initial loss partition'})

# P16 external checkpoint inside the loss-coverage prefix (seq 2 of 3).
h, _ = rv.base(2, True, 34); env = h.encoded(); h.checkpoint = [2, codec.cid(codec.decode(env[1])['statement'])]
add('P16-checkpoint-inside-loss-coverage', h, {'accept': True, 'restoredObjects': [], 'attempts': []})

# P17 complete profile 3 with a valid non-member orphan object: publication union includes it.
h, _ = rv.base(3, False, 1); od = b'valid orphan bytes'; h.m['objects'].append([frame.raw_cid(od), od]); h.m['objects'].sort()
h.events = []; h.initial(); a = h.intent(); h.outcome(a)
add('P17-complete-p3-valid-orphan-in-output', h, {'accept': True, 'restoredObjects': [], 'attempts': [att(h, a, [], 3, 0)]})

# P18 restored orphan (OriginalObject basis) with *different length* than the corrupt original.
h, _ = rv.base(2, False, 1); good = b'orphan good bytes'; ocid = frame.raw_cid(good); h.m['objects'].append([ocid, b'z']); h.m['objects'].sort()
h.events = []; h.initial(); h.restore(ocid, good); a = h.intent(); h.outcome(a)
add('P18-orphan-restored-length-from-candidate', h,
    {'accept': True, 'restoredObjects': [{'cid': ocid, 'length': len(good), 'basis': 'OriginalObject'}],
     'attempts': [att(h, a, [[ocid, good]], 5, 0)]})

# P19 intent made before restorations, failure, then new attempt after; first attempt observed
# afterwards must still match its own historical (empty-selection) output -> refuse since
# originals missing: an intent over an unpublishable selection is a false signed claim.
h, saved = rv.base(2, True, 1); h.add('publication-intent', {'attempt': b'\x09' * 16, 'member': frame.member_digest(h.m),
                                                             'restorations': frame.restoration_digest([]), 'output': b'\x00' * 32,
                                                             'frontier': rv.frontier(h.m)})
add('P19-intent-before-required-restoration', h, {'accept': False, 'error': 'publication-blocked-unavailable-object'})

# P20 partial profile-3 copy: referenced (IssuerMetadata) key with an issuer-signed
# length that disagrees with the true bytes; membership row agrees with the reference.
# Candidate = true bytes. Design: authenticated reference length still constrains.
h, _ = rv.base(3, False, 3); m = h.m; m['records'] = m['records'][:1]
man = codec.decode(m['records'][0][1]); e = man['body']['entries'][0]; tcid = text(e['ciphertext'])
true_bytes = dict(m['objects'])[tcid]; e['length'] = len(true_bytes) + 1; mb = codec.encode(man)
rec = codec.decode(m['records'][0][2]); rec['body']['manifest'] = codec.Link(codec.cid_bytes(codec.cid(mb)))
m['records'][0][1] = mb; m['records'][0][2] = codec.encode(rec)
m['membership'] = [[c, (n + 1 if c == tcid else n)] for c, n in m['membership']]
m['objects'] = [o for o in m['objects'] if o[0] != tcid]; members.resign(m)
h.events = []; h.initial(); h.restore(tcid, true_bytes)
add('P20-partial-copy-issuer-length-constrains-candidate', h, {'accept': False, 'error': 'candidate expected length'})

# Envelope-size arithmetic for the greedy partition rule: largest possible
# 32-entry unavailable statement (max safe integers, longest state string).
m, o = members.build(2, 0); ctx = rv.ctx(m, o)
entry = {'occurrence': 2**53 - 1, 'cid': codec.Link(codec.cid_bytes(frame.raw_cid(b'a'))), 'expectedLength': 4 * 1024 * 1024, 'state': 'corrupt'}
st = {'version': 1, 'domain': wire.DOMAIN, **ctx, 'sequence': 2**53 - 1,
      'previous': codec.Link(codec.cid_bytes(codec.cid(b'x'))), 'sampledAt': 2**53 - 1,
      'event': 'unavailable', 'body': {'member': b'\xff' * 32, 'entries': [entry] * 32}}
raw = codec.encode(st)
envelope = codec.encode({'statement': codec.blob(raw), 'signature': codec.blob(b'\x00' * 64)})
size = {'maxEntryBytes': len(codec.encode(entry)), 'max32EntryStatementBytes': len(raw),
        'max32EntryEnvelopeBytes': len(envelope), 'MAX_ENVELOPE': 16384,
        'greedyShrinkReachable': len(envelope) > 16384}

OUT.write_text(json.dumps({'cases': cases, 'envelopeArithmetic': size}, indent=1) + '\n')
print(json.dumps(size))
for c in cases:
    print(c['name'], 'expect', 'accept' if c['expect'].get('accept') else 'refuse:' + c['expect']['error'],
          '| author-oracle', c['authorOracle'])
