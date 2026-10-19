#!/usr/bin/env python3
"""Reviewer semantic controls. Each control mutates one guard, runs the named test
binaries with --no-fail-fast, records the full log, restores the exact file and
checks its sha256 against the frozen identity manifest before continuing.
Classification: COMPILE-FAIL (not a kill), KILLED-BY:<binaries> (behavioural
panic/assertion in a named test), SURVIVED (all tests pass).
Usage: controls.py MANIFEST [control-id ...]"""
import hashlib, json, re, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'review-evidence' / 'controls'
OUT.mkdir(exist_ok=True)
manifest = json.load(open(sys.argv[1]))['files']
I = 'src/evidence_interpretation.rs'
AS = 'src/evidence_assembly.rs'
BU = 'src/evidence_store/bundle.rs'
IT = ['evidence_interpretation', 'zz_review_interp_probes']
AT = ['evidence_assembly', 'evidence_assembly_review_regressions']
BT = ['evidence_recovery_bundle']
# (id, file, old, new, occurrence(None=must be unique), tests, concern)
C = [
 ('R-C1-dup-full-frame-equality', I, 'if expected != original {', 'if false && expected != original {', None, IT,
  'map_region accepts a forged duplicate whose body matches but whose full frame differs'),
 ('R-C2-direction-dropped', I, 'Event::RequestChunk { offset } => (0, offset)', 'Event::RequestChunk { offset } => (1, offset)', None, IT,
  'map_region group identity ignores request/response direction'),
 ('R-C3-frame-offset', I, 'if offset != s.offset {', 'if false && offset != s.offset {', None, IT,
  'map_region trusts segment offset over the frame-claimed offset'),
 ('R-C4-body-span', I, 'if frame.body_span != source.bytes {', 'if false && frame.body_span != source.bytes {', None, IT,
  'map_region cites equal bytes outside the frame body (header)'),
 ('R-C5-final-extent', I, '    if next != bytes.len() {\n        return Err(Error::Mapping);', '    if false && next != bytes.len() {\n        return Err(Error::Mapping);', None, IT,
  'map_region accepts contiguous bytes beyond the segment layout'),
 ('R-C6-block-start-after-message-delta', I, 'if !state.started || state.delta {', 'if !state.started {', 0, IT,
  'content_block_start after message_delta is not a sequence issue'),
 ('R-C7-delta-after-block-stop', I, 'if b.stopped {\n                    i.issues.push(Issue::Sequence);\n                }\n                if b.kind != want', 'if b.kind != want', None, IT,
  'content_block_delta after content_block_stop accepted'),
 ('R-C8-stop-without-message-delta', I, 'if !state.started || !state.delta || state.open_blocks != 0 {', 'if !state.started || state.open_blocks != 0 {', None, IT,
  'message_stop without message_delta coheres'),
 ('R-C9-message-start-content', I, '.is_some_and(Vec::is_empty)', '.is_some()', None, IT,
  'message_start with prefilled content not flagged'),
 ('R-C10-strict-output-uncharged', I, '    w.scan(bytes.len())?;\n    w.output(bytes.len())?;', '    w.scan(bytes.len())?;', None, IT,
  'retained JSON Value is not charged to output budget (absolute output accounting)'),
 ('R-C11-double-block-stop', I, 'if b.stopped {\n                    i.issues.push(Issue::Sequence);\n                } else {', 'if false {\n                    i.issues.push(Issue::Sequence);\n                } else if !b.stopped {', None, IT,
  'second content_block_stop for the same index silently accepted'),
 ('R-C12-empty-region-boundary', I, '(region.is_empty() && next <= a && a <= end && a == region.start)', '(region.is_empty() && next <= a && a < end && a == region.start)', None, IT,
  'empty region at a segment end boundary loses the left citation (behaviour change, not safety)'),
 ('B-X1-dup-compare-partial-charge', AS, '        work.scan(a.len())?;\n        if a != b {', '        work.scan(a.len().min(1))?;\n        if a != b {', None, AT,
  'duplicate comparison charged one byte per chunk instead of its length'),
 ('B-X2-sort-by-input-only', AS, 'out.segments.sort_by_key(|s| (s.offset, s.sources[0].input));', 'out.segments.sort_by_key(|s| s.sources[0].input);', None, AT,
  'segments ordered by input index instead of offset'),
 ('B-X3-extent-dedup-by-value', AS, '    if let Some(&(_, n)) = out.extents.first() {', '    out.extents.dedup_by_key(|e| e.1);\n    if let Some(&(_, n)) = out.extents.first() {', None, AT,
  'duplicate RequestEnd sources collapsed when their claimed extents agree'),
 ('A-X1-empty-text-as-blob', BU, '        row.get_ref(col)? == ValueRef::Text(if text { b"text" } else { b"blob" }),', '        row.get_ref(col)? == ValueRef::Text(if text { b"text" } else { b"blob" }) || (!text && row.get_ref(col + 1)? == ValueRef::Integer(0)),', None, BT,
  'empty cell of any storage class accepted where BLOB required (only class guard at :144 relaxed; :149/:153 projection guard still active)'),
 ('A-X2-empty-text-as-blob-both-guards', BU, '        (false, ValueRef::Null) if len == 0 => &[],', '        (false, ValueRef::Null | ValueRef::Text(_)) if len == 0 => &[],', None, BT,
  'with A-X1 also applied: empty TEXT projected as empty BLOB (storage-class confusion end-to-end)'),
]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def run(cid, tests):
    cmd = ['cargo', 'test', '--offline', '--locked', '--features', 'v2-crypto', '--no-fail-fast']
    for t in tests: cmd += ['--test', t]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=900)
    return cmd, r.returncode, r.stdout + r.stderr
def classify(log, rc):
    if 'could not compile' in log or re.search(r'^error(\[E\d+\])?:', log, re.M) and 'test failed' not in log:
        return 'COMPILE-FAIL'
    if rc == 0: return 'SURVIVED'
    failed = re.findall(r'^test (\S+) \.\.\. FAILED', log, re.M)
    panics = re.findall(r"panicked at (tests/[^\s:]+:\d+)", log)
    return 'KILLED-BY ' + ', '.join(sorted(set(failed))) + ' @ ' + ', '.join(sorted(set(panics)))
want = set(sys.argv[2:])
results = []
applied_stack = {}  # for A-X2 which composes with A-X1
for cid, f, old, new, occ, tests, why in C:
    if want and cid not in want: continue
    path = ROOT / f
    orig = path.read_text()
    assert sha(path) == manifest[f], ('pre-control hash mismatch', f)
    src = orig
    if cid == 'A-X2-empty-text-as-blob-both-guards':
        a1 = [c for c in C if c[0] == 'A-X1-empty-text-as-blob'][0]
        assert src.count(a1[2]) == 1; src = src.replace(a1[2], a1[3])
    n = src.count(old)
    if occ is None:
        assert n == 1, (cid, n)
        mutated = src.replace(old, new)
    else:
        idx = -1
        for _ in range(occ + 1): idx = src.index(old, idx + 1)
        mutated = src[:idx] + new + src[idx + len(old):]
    try:
        path.write_text(mutated)
        cmd, rc, log = run(cid, tests)
    finally:
        path.write_text(orig)
    assert sha(path) == manifest[f], ('restore failed', f)
    verdict = classify(log, rc)
    (OUT / f'{cid}.txt').write_text(f'# control {cid}\n# concern: {why}\n# file: {f}\n# old: {old!r}\n# new: {new!r} occ={occ}\n$ {" ".join(cmd)}\n{log}\n# exit={rc}\n# classification: {verdict}\n# restored sha256 {sha(path)} == manifest\n')
    results.append((cid, verdict))
    print(f'{cid}: {verdict}', flush=True)
(OUT / ('summary-' + ('-'.join(sorted(want)) if want else 'all') + '.txt')).write_text('\n'.join(f'{a}: {b}' for a, b in results) + '\n')
