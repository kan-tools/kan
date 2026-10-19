#!/usr/bin/env python3
"""Append reviewer probes, run them (and probe-killed mutants), then byte-restore."""
import hashlib, pathlib, subprocess, sys, os
ROOT = pathlib.Path(__file__).resolve().parents[2]
P = ROOT / 'review-evidence/probes'
OUT = ROOT / 'review-evidence/40-probes.txt'
tests = ROOT / 'tests/evidence_reader.rs'
lib = ROOT / 'src/evidence_library.rs'
orig = {f: f.read_bytes() for f in (tests, lib)}
env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / 'target'), CARGO_BUILD_JOBS='4')


def sh(cmd, log):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env, timeout=600)
    log.write(f'$ {" ".join(cmd)}\nexit={r.returncode}\n{r.stdout}{r.stderr}\n')
    log.flush()
    return r


try:
    tests.write_bytes(orig[tests] + (P / 'reviewer_probes.rs.txt').read_bytes())
    src = orig[lib].decode()
    assert src.endswith('}\n')
    lib.write_text(src[:-2] + (P / 'budget_probe.rs.txt').read_text() + '}\n')
    with OUT.open('w') as log:
        base = ['cargo', 'test', '-j4', '--features', 'v2-crypto']
        sh(base + ['--test', 'evidence_reader', 'probe_', '--', '--nocapture', '--test-threads=1'], log)
        sh(base + ['--lib', 'probe_whole_deadline_includes_queue_time'], log)
    m = [sys.executable, str(P / 'mutate.py')]
    L = 'src/evidence_library.rs'
    R = 'src/evidence_reader.rs'
    for args in [
        ['K03-denial-marks-partial-vs-probe', L, 'Err(Failure::AccessLimited) => {}', 'Err(Failure::AccessLimited) => partial = true,', 'evidence_reader', 'probe_p1_denial_only_catalog_is_complete'],
        ['K08-leak-failure-count-vs-probe', L, '"coverage":if partial {"partial"} else {"complete"},', '"coverage":if partial {"partial"} else {"complete"},"failed":configured.len()-scopes.len(),', 'evidence_reader', 'probe_p1_denial_only_catalog_is_complete'],
        ['K12-timeout-is-denial-vs-probe', R, '.map_err(|_| Failure::Unavailable)?\n        .map_err(|failure|', '.map_err(|_| Failure::AccessLimited)?\n        .map_err(|failure|', 'evidence_reader', 'probe_p2_sixteen_stalled_scopes_fit_budget_and_keep_order'],
        ['K24-whole-excludes-queue-vs-probe', L, '''let connection = async {
            let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
            work.await;
        };
        let _ = tokio::time::timeout(Duration::from_secs(35), connection).await;''', '''let Ok(Ok(_request)) = tokio::time::timeout(
                Duration::from_secs(6),
                self.requests.clone().acquire_owned(),
            )
            .await
            else {
                return;
            };
        let _ = tokio::time::timeout(Duration::from_secs(35), work).await;''', 'lib', 'evidence_library::budget_tests::probe_whole_deadline_includes_queue_time'],
    ]:
        subprocess.run(m + args, cwd=ROOT, env=env, check=False)
finally:
    for f, b in orig.items():
        f.write_bytes(b)
    for f, b in orig.items():
        assert hashlib.sha256(f.read_bytes()).digest() == hashlib.sha256(b).digest()
    print('restored', [str(f.relative_to(ROOT)) for f in orig])
