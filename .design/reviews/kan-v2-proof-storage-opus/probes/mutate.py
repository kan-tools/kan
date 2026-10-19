#!/usr/bin/env python3
"""Reviewer compiled mutants / negative controls for 9f1dffa. Usage: mutate.py <export-root> <out-dir>
Each case edits one source file, runs the named suites with --no-fail-fast, records the per-test
outcome, and restores the exact original bytes (checked by SHA-256) in `finally`."""
import hashlib, pathlib, re, subprocess, sys

ROOT = pathlib.Path(sys.argv[1]).resolve()
OUT = pathlib.Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
ST = 'src/evidence_store/attested.rs'
PARENT = 'src/evidence_store.rs'
PERSIST = 'src/persistence.rs'


def sub(text, old, new):
    assert text.count(old) == 1, f'pattern count {text.count(old)}: {old[:60]!r}'
    return text.replace(old, new)


CASES = [
    ('RM1-drop-retry-envelope-compare', ST, lambda s: sub(s,
        "                    || envelope(tx, row.sequence)? != old.bytes()\n", ""),
     ['evidence_attested_store', 'zz_review_storage_probe']),
    ('RM2-drop-retry-receipt-recheck', ST, lambda s: sub(s,
        "                proof::verify_at(\n                    old.bytes(),\n                    &binding.context(),\n                    &row.manifest,\n                    &row.receipt,\n                    old.frontier(),\n                )?;\n", ""),
     ['evidence_attested_store', 'zz_review_storage_probe']),
    ('RM3-drop-historical-issuer-consistency', ST, lambda s: sub(s,
        ".is_some_and(|h| h != &signed.request.audience)",
        ".is_some_and(|h| h != &signed.request.audience && false)"),
     ['evidence_attested_store', 'zz_review_storage_probe']),
    ('RM4-drop-p256-binding-check', ST, lambda s: sub(s,
        "        if algorithm != atrium_crypto::Algorithm::P256\n            || atrium",
        "        if atrium"),
     ['evidence_attested_store', 'zz_review_storage_probe']),
    ('RM5-proof-hook-after-commit', PARENT, lambda s: sub(s,
        "        if let Some(hook) = &mut proof_hook {\n            hook(&tx, &record, observe)?;\n        }\n        observe(Boundary::BeforeCommit);\n        tx.commit()?;\n",
        "        observe(Boundary::BeforeCommit);\n        tx.commit()?;\n        if let Some(hook) = &mut proof_hook {\n            let tx = self.conn.unchecked_transaction()?;\n            hook(&tx, &record, observe)?;\n            tx.commit()?;\n        }\n"),
     ['evidence_attested_store', 'zz_review_storage_probe']),
    ('RM6-drop-lock-proof-cardinality', ST, lambda s: sub(s,
        "            if u64::try_from(count).ok() != Some(previous.through) {\n                return Err(Error::Conflict(",
        "            if false && u64::try_from(count).ok() != Some(previous.through) {\n                return Err(Error::Conflict("),
     ['evidence_attested_store', 'zz_review_storage_probe']),
    ('RM7-drop-lock-binding-check', ST, lambda s: sub(s,
        "            check_binding(tx, binding)?;\n            let count",
        "            let count"),
     ['evidence_attested_store', 'zz_review_storage_probe']),
    ('RM8-drop-writable-schema-check', ST, lambda s: sub(s,
        "        archive.ledger.check_write_profile(true)?;\n", ""),
     ['evidence_attested_store', 'zz_review_storage_probe']),
    ('NC1-raw-sql-attestation-update-in-store', ST, lambda s: sub(s,
        "                observe(Boundary::AttestationInserted);\n",
        "                tx.execute(\"UPDATE attestations SET envelope=envelope WHERE sequence=?\", [i64::try_from(row.sequence).unwrap()])?;\n                observe(Boundary::AttestationInserted);\n"),
     ['surface_conformance', 'evidence_attested_store']),
    ('NC2-second-facade-call', ST, lambda s: sub(s,
        "                observe(Boundary::AttestationInserted);\n",
        "                if false {\n                    // surface-write: evidence-proof-sqlite:attestations\n                    crate::persistence::insert_evidence_proof(\n                        crate::persistence::SurfaceWrite::EvidenceAttestation,\n                        tx,\n                        0,\n                        &[],\n                    )?;\n                }\n                observe(Boundary::AttestationInserted);\n"),
     ['surface_conformance']),
    ('NC3-facade-insert-or-replace', PERSIST, lambda s: sub(s,
        '"INSERT INTO attestations VALUES(?,?)"', '"INSERT OR REPLACE INTO attestations VALUES(?,?)"'),
     ['surface_conformance', 'evidence_attested_store']),
    ('NC4-uncatalogued-profile2-table', ST, lambda s: sub(s,
        "PRAGMA user_version=2;\n", "CREATE TABLE proof_cache(k BLOB);\nPRAGMA user_version=2;\n"),
     ['surface_conformance', 'evidence_attested_store']),
    ('NC5-uncatalogued-profile2-index', ST, lambda s: sub(s,
        "PRAGMA user_version=2;\n", "CREATE INDEX attestations_by_envelope ON attestations(envelope);\nPRAGMA user_version=2;\n"),
     ['surface_conformance', 'evidence_attested_store']),
]


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    only = set(sys.argv[3:])
    summary = []
    for name, rel, mutate, suites in CASES:
        if only and name not in only:
            continue
        path = ROOT / rel
        original = path.read_bytes()
        before = digest(path)
        changed = mutate(original.decode())
        assert changed.encode() != original, name
        try:
            path.write_text(changed)
            args = ['cargo', 'test', '--features', 'v2-crypto', '--no-fail-fast']
            for s in suites:
                args += ['--test', s]
            r = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
            log = r.stdout + r.stderr
            (OUT / f'{name}.txt').write_text(log)
            if 'could not compile' in log or 'error[E' in log:
                verdict = 'COMPILE-FAILURE (not counted)'
                failed = []
            else:
                failed = re.findall(r'^test (\S+) \.\.\. FAILED', log, re.M)
                verdict = 'KILLED' if failed else 'SURVIVED'
            line = f'{name}: {verdict} exit={r.returncode} failed={failed}'
        finally:
            path.write_bytes(original)
            assert digest(path) == before, f'restore failed for {rel}'
        print(line, flush=True)
        summary.append(line)
    with open(OUT / 'SUMMARY.txt', 'a') as f:
        f.write('\n'.join(summary) + '\n')


if __name__ == '__main__':
    main()
