#!/usr/bin/env python3
"""Reviewer probes for the corrected service-attestation proposal.

Synthetic public scalars 1, 2, 3 only. In-memory; writes nothing. Usage:
  python -I probe_correction.py <export-root>
Each probe states EXPECT (what the corrected design text requires) and
OBSERVED (what the oracle/fixtures actually do). A probe "documents a gap"
when the fixture/oracle accepts something the design says must be refused,
or when the design leaves the outcome unspecified.
"""
import copy, importlib.util, json, sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location('oracle', ROOT/'.design/tools/attestation_vectors.py')
O = importlib.util.module_from_spec(spec); sys.modules['oracle'] = O; spec.loader.exec_module(O)
C = O.codec
DATA = json.loads((ROOT/'.design/fixtures/service-attestation-v1.json').read_text())
PIN = DATA['pinnedIssuer']; ARCH = bytes.fromhex(DATA['archiveHex']); SCOPE = bytes.fromhex(DATA['scopeHex'])
K1, CUR = O.identity(1); K2, HIST = O.identity(2); K3, THIRD = O.identity(3)
ROWS = DATA['positive']
results = []

def outcome(fn):
    try:
        v = fn(); return ('accept', v)
    except O.Rejected as e:
        return ('reject:'+str(e), None)
    except Exception as e:
        return ('unexpected:'+type(e).__name__+':'+str(e)[:60], None)

def report(pid, title, expect, observed, gap):
    results.append((pid, gap))
    print(f"{pid} [{'GAP' if gap else 'ok '}] {title}\n    EXPECT:   {expect}\n    OBSERVED: {observed}")

def verify(env, prev, m, r, pinned=PIN, arch=ARCH, scope=SCOPE):
    return O.verify(env, pinned, arch, scope, prev, m, r)

def mhex(i): return bytes.fromhex(ROWS[i]['manifestHex'])
def rhex(i): return bytes.fromhex(ROWS[i]['receiptHex'])
def env(i): return bytes.fromhex(ROWS[i]['envelopeHex'])
s1 = verify(env(0), None, mhex(0), rhex(0))
s2 = verify(env(1), s1, mhex(1), rhex(1))

# ---- Independent descending verifier, written from design lines 266-273 ----
def descend(anchor, rows):
    """anchor = (archiveId, sequence, manifestCid, statementCid) from a signed snapshot.
    rows = newest-first [(envelope, manifestRaw, receiptRaw)]. Returns verified bodies.
    Signature/field checks reuse O.verify with previous=None semantics replaced by
    an explicit predecessor-equality step (the design's descending rule)."""
    expect = anchor; out = []
    for envb, mr, rr in rows:
        if expect[1] == 0:
            raise O.Rejected('page-past-genesis')
        st = C.decode(C.decode(envb)['statement'])['body']
        # verify fields/signature without a forward predecessor: emulate by
        # supplying a synthetic 'previous' derived from the row's own claims,
        # then check those claims against the NEXT row (descending).
        prev = None if st['sequence'] == 1 else {
            'sequence': st['previousSequence'], 'scopeToken': st['scopeToken'], 'archiveId': st['archiveId'],
            'manifest': st['previousManifest'], 'statementCid': st['previousAttestation'], 'issuer': st['issuer']}
        b = O.verify(envb, PIN, ARCH, SCOPE, prev, mr, rr)
        got = (b['archiveId'], b['sequence'], b['manifest'], b['statementCid'])
        if got != expect:
            raise O.Rejected('anchor-mismatch')
        out.append(b)
        expect = (b['archiveId'], b['previousSequence'], b['previousManifest'], b['previousAttestation'])
    return out

def anchor_of(b): return (b['archiveId'], b['sequence'], b['manifest'], b['statementCid'])

# P1: same-height alternate statements (design :326 "Test semantically valid
# alternate statements with changed purpose/time/receipt against a pinned successor").
for field, value in [('issuedAt', ROWS[0]['statement']['body']['issuedAt']+1), ('purpose', 'retained-verified')]:
    st = copy.deepcopy(ROWS[0]['statement']); st['body'][field] = value
    alt = O.sign(st, K1)
    o, b = outcome(lambda: verify(alt, None, mhex(0), rhex(0)))
    o2, _ = outcome(lambda: verify(env(1), b, mhex(1), rhex(1))) if b else ('n/a', None)
    o3, _ = outcome(lambda: descend(anchor_of(s2), [(env(1), mhex(1), rhex(1)), (alt, mhex(0), rhex(0))]))
    in_fixture = any(n['base'] == 0 and n['expected'] in ('anchor-mismatch', 'chain-commitments') for n in DATA['negative'])
    report('P1-'+field, f'alternate seq-1 statement ({field} changed, re-signed by pinned key)',
           'refused against pinned successor; fixture carries a labelled vector',
           f'standalone={o}; successor-forward={o2}; reviewer-descending={o3}; fixture vector present={in_fixture}',
           gap=not in_fixture)

# P2: the oracle has no snapshot/anchor/page/cursor function or vector at all.
names = [n for n in dir(O) if any(k in n.lower() for k in ('page', 'anchor', 'snapshot', 'cursor', 'descend'))]
keys = set(DATA)
report('P2', 'descending page / snapshot anchor / cursor in oracle+fixture',
       'design :266-284 + RFC :166-174 algorithm has independent vectors before freezing',
       f'oracle names={names}; fixture keys={sorted(keys)}', gap=True)

# P3: fork splice under a pinned tip (backup-restore fork, same archiveId+key).
st = copy.deepcopy(ROWS[1]['statement']); st['body']['issuedAt'] += 999
forkB = O.sign(st, K1)
o, bB = outcome(lambda: verify(forkB, s1, mhex(1), rhex(1)))
o2, _ = outcome(lambda: descend(anchor_of(s2), [(forkB, mhex(1), rhex(1))]))
report('P3', 'same-height fork statement under pinned tip of branch A',
       'forward verify accepts (declared: no equivocation guarantee); descending anchor rejects',
       f'forward={o}; descending-from-A-tip={o2}', gap=not (o == 'accept' and o2.startswith('reject')))

# P4: descending genesis termination and over-run.
o, _ = outcome(lambda: descend(anchor_of(s2), [(env(1), mhex(1), rhex(1)), (env(0), mhex(0), rhex(0)), (env(0), mhex(0), rhex(0))]))
report('P4', 'page that continues past genesis', 'integrity error', o, gap=not o.startswith('reject'))

# P5: purpose ordering in a mixed chain. Upgrade produces retained-verified 1..N
# then admitted N+1..; the positive fixture itself is admitted(1) -> retained-verified(2).
def chain(specs):
    prev = None; prevm = prevs = None; states = []
    for seq, (purpose, rissuer) in enumerate(specs, 1):
        man = copy.deepcopy(ROWS[0]['manifest']); man['body']['position'] = seq-1
        man['body']['previous'] = prevm if seq > 1 else None
        mraw = C.encode(man); mc = C.cid(mraw)
        rec = copy.deepcopy(ROWS[0]['receipt']); rec['body'].update(issuer=rissuer, manifest=C.link(mc), position=seq-1)
        rraw = C.encode(rec)
        stt = {'v': 1, 'kind': 'service-attestation', 'body': {'issuer': CUR, 'archiveId': C.blob(ARCH),
               'scopeToken': man['body']['scopeToken'], 'sequence': seq, 'manifest': C.link(mc),
               'receipt': C.link(C.cid(rraw)), 'previousSequence': seq-1, 'previousManifest': prevm,
               'previousAttestation': prevs, 'purpose': purpose, 'issuedAt': 1792108800000 + (100-seq)}}
        e = O.sign(stt, K1)
        prev = verify(e, prev, mraw, rraw); states.append(prev)
        prevm, prevs = C.link(mc), prev['statementCid']
    return states
o, _ = outcome(lambda: chain([('admitted', CUR), ('retained-verified', HIST), ('admitted', CUR), ('retained-verified', THIRD)]))
report('P5', 'interleaved admitted/retained-verified chain, three receipt issuers, decreasing issuedAt',
       'design specifies upgrade = complete legacy prefix of retained-verified with one pinned legacy issuer (:255,:312); '
       'a verifier rule or explicit statement that order/issuer-consistency is unchecked',
       f'{o} (no purpose-order, single-historical-issuer or issuedAt monotonicity rule in RFC/oracle)', gap=(o == 'accept'))

# P6: retained-verified receipt with receipt.issuer == current issuer, and with
# a receipt issuer that is not a valid Author at all.
o_same, _ = outcome(lambda: chain([('retained-verified', CUR)]))
junk = {'principal': 'not-a-did', 'verificationMethod': 'x', 'identityVersion': {'kind': 'static', 'value': None}}
o_junk, _ = outcome(lambda: chain([('retained-verified', junk)]))
o_junk_adm, _ = outcome(lambda: chain([('admitted', junk)]))
report('P6', 'retained-verified over receipt with malformed historical issuer Author',
       'historical issuer is displayed by UI (:253); must at least be a valid static Author; fixture negative',
       f'issuer==current: {o_same}; junk issuer retained-verified: {o_junk}; junk admitted: {o_junk_adm}',
       gap=(o_junk == 'accept'))

# P7: receipt schema not validated by oracle: wrong durability, extra field, missing field.
def with_receipt(mod):
    rec = copy.deepcopy(ROWS[0]['receipt']); mod(rec); rraw = C.encode(rec)
    st = copy.deepcopy(ROWS[0]['statement']); st['body']['receipt'] = C.link(C.cid(rraw))
    return outcome(lambda: verify(O.sign(st, K1), None, mhex(0), rraw))[0]
r_dur = with_receipt(lambda r: r['body'].update(durability='best-effort'))
r_extra = with_receipt(lambda r: r['body'].update(extra=1))
r_missing = with_receipt(lambda r: r['body'].pop('issuer'))
r_kind = with_receipt(lambda r: r.update(kind='manifest'))
report('P7', 'receipt schema (durability literal, closed fields, required issuer) in proof binding',
       'RFC :71 closed receipt body; labelled negatives for Rust parity (Python oracle declares schema Rust-only :246)',
       f'durability=best-effort: {r_dur}; extra field: {r_extra}; missing issuer: {r_missing}; kind=manifest: {r_kind}',
       gap=(r_dur == 'accept' or r_extra == 'accept' or r_missing.startswith('unexpected')))

# P8: manifest-profile / receipt-profile / issuer-point / r>=n have no vectors.
labels = {n['expected'] for n in DATA['negative']}
missing = [l for l in ['manifest-profile', 'receipt-profile', 'issuer-point', 'manifest-canonical', 'receipt-canonical', 'statement-bound'] if l not in labels]
pt = 'did:key:z' + O.b58(b'\x80\x24' + b'\x02' + b'\x00'*31 + b'\x01')
a = O.author(pt); st = copy.deepcopy(ROWS[0]['statement']); st['body']['issuer'] = a
raw = C.encode(st); e = C.encode({'statement': C.blob(raw), 'signature': C.blob(b'\x01'*64)})
o_pt, _ = outcome(lambda: verify(e, None, mhex(0), rhex(0), pinned=pt))
d = C.decode(env(0)); sig = d['signature']
d['signature'] = O.ORDER.to_bytes(32, 'big') + sig[32:]
o_rn, _ = outcome(lambda: verify(C.encode_value(d), None, mhex(0), rhex(0)))
report('P8', 'labels without any fixture vector', 'every verifier label has a labelled vector (design :323-329)',
       f'labels with no vector={missing}; off-curve x=1 did → {o_pt}; r=n → {o_rn}', gap=bool(missing))

# P9: boundary s == n//2 must be ACCEPTED (positive) — not pinned.
pos_s = [int.from_bytes(bytes.fromhex(r['signatureHex'])[32:], 'big') for r in ROWS]
report('P9', 'acceptance boundary s = floor(n/2)', 'a positive vector pins inclusive bound (RFC :121 "0 < s <= n/2")',
       f'positive s values == n//2: {[s == O.ORDER//2 for s in pos_s]}', gap=True)

# P10: cross-archive replay: a statement valid in archive X presented as archive Y row.
o, _ = outcome(lambda: verify(env(0), None, mhex(0), rhex(0), arch=b'\x0a'*32))
report('P10', 'cross-archive replay to a reader configured for another archiveId', 'configured-archive', o,
       gap=(o != 'reject:configured-archive'))

# P11: retained-verified proof plus existing audience rule. The current service
# (src/evidence_service.rs:549) and reader (src/evidence_reader.rs:182,287) require
# request.audience == configured issuer; verify_retained_request (:338-341) requires
# receipt.issuer == request.audience. For a historical issuer H != current C:
H, Cc = HIST['principal'], CUR['principal']
service_retry_ok = (H == Cc)      # execute(): audience != self.issuer() -> AccessLimited before dedupe
reader_source_ok = (H == Cc)      # read source: signed.request.audience != access.issuer -> Corrupt
retained_ok = True                # receipt.issuer(H) == audience(H): consistent
report('P11', 'H != C: exact retry of copied legacy op / source read of retained-verified row under existing audience rules',
       'design :299-301 says exact retry returns retained-verified; :288-290 source read verifies writer request',
       f'service retry admitted={service_retry_ok}; reader source accepted={reader_source_ok}; retained binding={retained_ok}; '
       'design specifies no audience rule change', gap=True)

print('\nSUMMARY:', sum(1 for _, g in results if g), 'gaps of', len(results), 'probes')
