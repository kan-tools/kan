#!/usr/bin/env python3
"""Reviewer compiled-mutant runner. argv: repo_root out_dir [mutant ids...].

Each mutant replaces one exact, uniquely occurring source fragment, runs the named
test binaries with --no-fail-fast, then restores the original bytes and checks the
SHA-256 before continuing. Results distinguish compile errors from assertion kills.
"""
import hashlib, os, re, subprocess, sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve(); OUT = Path(sys.argv[2]).resolve(); OUT.mkdir(parents=True, exist_ok=True)
A, E = 'src/evidence_attestation.rs', 'src/evidence.rs'
COMMITTED, PROBE, CONTRACT = 'evidence_attestation', 'zz_review_attestation_probe', 'evidence_contract'
MUTANTS = {
    'RM1-did-length-bound': (A, 'if !(56..=80).contains(&did.len()) || !did.starts_with("did:key:z")',
                             'if !did.starts_with("did:key:z")', [COMMITTED, PROBE]),
    'RM2-did-roundtrip': (A, '    if atrium_crypto::did::format_did_key(algorithm, &key).map_err(|_| invalid("issuer-point"))?\n        != did\n    {\n        return Err(invalid("issuer-encoding"));\n    }\n',
                          '    let _ = &key;\n', [COMMITTED, PROBE]),
    'RM3-row-after-genesis': (A, '    if expected.through == 0 {\n        return Err(invalid("row-after-genesis"));\n    }\n', '', [COMMITTED, PROBE]),
    'RM4-pinned-frontier': (A, '    if verified.frontier() != expected {\n', '    if false {\n', [COMMITTED, PROBE]),
    'RM5-low-s-off-by-one': (A, '|| signature[32..] > HALF[..]', '|| signature[32..] >= HALF[..]', [COMMITTED, PROBE]),
    'RM6-chain-issuer': (A, '            || previous.issuer.as_deref() != Some(context.issuer)\n', '', [COMMITTED, PROBE]),
    'RM7-record-kind': (A, 'evidence::Decoded::Known(record) if record.kind() == kind => Ok(record),',
                        'evidence::Decoded::Known(record) => {\n                    let _ = kind;\n                    Ok(record)\n                }', [COMMITTED, PROBE]),
    'RM8-manifest-only-pin': (A, '    if verified.frontier() != expected {\n',
                              '    if verified.frontier().through != expected.through\n        || verified.frontier().manifest != expected.manifest\n    {\n', [COMMITTED, PROBE]),
    'RM9-frontier-issuer-conjunct': (A, '            || (self.through == 0) != self.issuer.is_none()\n', '', [COMMITTED, PROBE]),
    'RM10-record-bound-shared': (E, '    let value = canonical_value(bytes, MAX_RECORD_BYTES)?;',
                                 '    let value = canonical_value(bytes, MAX_RECORD_BYTES + 1)?;', [CONTRACT, COMMITTED]),
}


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(mid):
    rel, old, new, tests = MUTANTS[mid]
    path = ROOT / rel
    original = path.read_bytes(); before = sha(path)
    text = original.decode()
    assert text.count(old) == 1, (mid, text.count(old))
    log = OUT / f'{mid}.txt'
    try:
        path.write_text(text.replace(old, new))
        cmd = ['cargo', 'test', '-j4', '--no-fail-fast', '--features', 'v2-crypto']
        for t in tests:
            cmd += ['--test', t]
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              env={**os.environ, 'REVIEW_DIFFERENTIAL': str(ROOT / 'review-evidence/probes/differential.json')})
        output = proc.stdout + proc.stderr
    finally:
        path.write_bytes(original)
        assert sha(path) == before, f'{mid}: restore mismatch'
    compile_error = bool(re.search(r'^error(\[E\d+\])?: ', output, re.M)) and 'could not compile' in output
    per = {}
    current = None
    for line in output.splitlines():
        m = re.match(r'\s+Running tests/(\w+)\.rs', line)
        if m:
            current = m.group(1)
        m = re.match(r'test result: (\w+)\. (\d+) passed; (\d+) failed', line)
        if m and current:
            per[current] = f'{m.group(1)} {m.group(2)}p/{m.group(3)}f'
    failed = re.findall(r'^    (\S+) stdout ----$|^---- (\S+) stdout ----$', output, re.M)
    names = [a or b for a, b in failed]
    asserts = re.findall(r"panicked at [^\n]*\n([^\n]*)", output)
    log.write_text(f'mutant {mid}\nfile {rel}\n--- old\n{old}\n--- new\n{new}\n--- restored sha {before}\n\n' + output)
    verdict = 'COMPILE-ERROR' if compile_error else ('KILLED' if proc.returncode else 'SURVIVED')
    summary = f'{mid:30} {verdict:13} ' + ' '.join(f'{k}={v}' for k, v in per.items())
    summary += ('\n      failing: ' + ', '.join(names)) if names else ''
    summary += ''.join(f'\n      assert: {a.strip()[:150]}' for a in asserts[:4])
    return summary


ids = sys.argv[3:] or list(MUTANTS)
with open(OUT / 'SUMMARY.txt', 'a') as s:
    for mid in ids:
        line = run(mid)
        print(line, flush=True)
        s.write(line + '\n')
