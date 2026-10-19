#!/usr/bin/env python3
"""Reviewer mutation driver. Usage: mutate.py <export-root> <evidence-dir> <set>
Each mutant: exact single-occurrence replacement, run named commands, restore,
verify SHA-256 of the mutated file equals the original. Verdict per command:
KILLED (named test failed), SURVIVED (passed), COMPILE-ERROR."""
import hashlib, json, subprocess, sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
SET = sys.argv[3]
CARGO = [str(ROOT / 'review-evidence/cargo.sh')]

def rust(test_target, filt=None, release=False, extra=()):
    cmd = CARGO + ['test'] + (['--release'] if release else []) + ['--features', 'v2-crypto', '--test', test_target]
    cmd += ['--'] + ([filt, '--exact'] if filt else []) + ['--test-threads=1', '--nocapture'] + list(extra)
    return cmd

def node(path):
    return ['node', '--test', path]

A_OVERVIEW = 'src/evidence_operations/projection.rs'
A_COLL = 'src/evidence_operations_collection/overview.rs'
APP = 'web/operations/app.js'
STORE = 'src/evidence_store.rs'
PROOF = 'src/evidence_store/attested.rs'
KAN_V2 = 'src/bin/kan-v2.rs'

SETS = {
 'A': [
  ('AM1-single-step-copy', A_OVERVIEW, 'let step = backup.step(64)?;', 'let step = backup.step(-1)?;',
     [rust('evidence_operations_overview', 'active_snapshot_parsing_does_not_exclude_health_writes'),
      rust('zz_review_overview_correction', 'ra1_cross_process_writer_never_fails_during_near_ceiling_refreshes')]),
  ('AM2-no-five-second-deadline', A_OVERVIEW, 'Duration::from_secs(5);', 'Duration::from_secs(500);',
     [rust('evidence_operations_overview'), rust('evidence_overview_review_regressions')]),
  ('AM3-skip-copied-schema-validation', A_OVERVIEW, 'self.schema = Self::validate_connection(&memory)?;', 'let _ = Self::validate_connection;',
     [rust('evidence_operations_overview'), rust('evidence_overview_review_regressions'), rust('evidence_operations'), rust('evidence_operations_collection')]),
  ('AM4-window-not-copy-window', A_COLL, 'snapshot.started_at = start;', 'let _ = start;',
     [rust('evidence_operations_overview'), rust('evidence_overview_review_regressions')]),
  ('AM5-sqlite-busy-labelled-invalid', A_COLL, 'if matches!(e.code,rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked))', 'if false && matches!(e.code,rusqlite::ErrorCode::DatabaseBusy|rusqlite::ErrorCode::DatabaseLocked))',
     [rust('evidence_operations_overview', 'busy_sources_are_distinguished_from_invalid_history'),
      rust('zz_review_overview_correction', 'ra4_busy_versus_invalid_classification')]),
  ('AM6-busy-classifies-everything', A_COLL, '_ if source_busy(error.as_ref()) => {', '_ if true || source_busy(error.as_ref()) => {',
     [rust('evidence_operations_overview'), rust('evidence_overview_review_regressions'), rust('zz_review_overview_correction', 'ra4_busy_versus_invalid_classification')]),
  ('UM1-error-path-without-serial-guard', APP, "catch(e){if(current===generation&&serial===overviewSerial){", "catch(e){if(current===generation){",
     [node('tests/operations_ui.test.cjs'), node('review-evidence/probes/zz_review_operations_ui.test.cjs')]),
  ('UM2-finally-without-serial-guard', APP, "finally{clearTimeout(timeout);if(current===generation&&serial===overviewSerial){", "finally{clearTimeout(timeout);if(current===generation){",
     [node('tests/operations_ui.test.cjs'), node('review-evidence/probes/zz_review_operations_ui.test.cjs')]),
  ('UM3-no-superseded-label', APP, "if(typeof active==='string'&&/^[a-f0-9]{32}$/.test(active)&&active!==s.last.active)", "if(false)",
     [node('tests/operations_ui.test.cjs')]),
 ],
}

SETS['B'] = [
  # Author's five controls, replicated with identical anchors (their script writes inside the export).
  ('BA1-author-drop-proof-copy', STORE, 'attested::copy_proof(&self.ledger.conn, &tx, raw.sequence)?;', 'let _ = &tx;',
     [rust('evidence_attested_lifecycle', 'proof_bytes_survive_backup_rebuild_and_derived_repair'), rust('zz_review_proof_lifecycle', 'rb1_exact_authoritative_rows_survive_backup_and_rebuild_with_h_ne_c')]),
  ('BA2-author-drop-extra-proof-check', PROOF, 'if u64::try_from(count).ok() != Some(through) {\n        return Err(corrupt("attestation cardinality"));\n    }\n    Ok(())\n}\npub(super) fn copy_proof', 'if false && u64::try_from(count).ok() != Some(through) {\n        return Err(corrupt("attestation cardinality"));\n    }\n    Ok(())\n}\npub(super) fn copy_proof',
     [rust('evidence_attested_lifecycle', 'recovery_refuses_missing_or_corrupt_proofs_and_payloads')]),
  ('BA3-author-resume-as-legacy', PROOF, 'Ledger::initialize_empty(root, &path, &mut |_| {}, Some(&binding))?', 'Ledger::initialize_empty(root, &path, &mut |_| {}, None)?',
     [rust('evidence_attested_lifecycle', 'interrupted_initialization_resumes_only_by_explicit_owner_action'), rust('zz_review_proof_lifecycle', 'rb4_random_sigkill_during_create_and_resume')]),
  ('BA4-author-drop-backup-proof-audit', PROOF, 'verify_contents(&reader.reader.ledger, &reader.binding, &base)?;', 'let _ = &reader.binding;',
     [rust('evidence_attested_lifecycle', 'backup_success_requires_verifying_the_copied_proof_chain'), rust('zz_review_proof_lifecycle', 'rb2_valid_foreign_proof_substitution_is_refused_everywhere')]),
  ('BA5-author-drop-pinned-read', STORE, 'PRAGMA query_only=ON; BEGIN;', 'PRAGMA query_only=ON;',
     [rust('evidence_attested_lifecycle', 'recovery_pins_source_before_later_admission'), rust('zz_review_proof_lifecycle', 'rb5_cross_process_admission_during_rebuild_and_backup')]),
  # Reviewer mutants.
  ('BM1-no-precommit-proof-audit', STORE, 'attested::verify_contents(&target, binding, &expected)?;', 'let _ = &expected;',
     [rust('evidence_attested_lifecycle'), rust('zz_review_proof_lifecycle', 'rb2_valid_foreign_proof_substitution_is_refused_everywhere')]),
  ('BM2-recovery-open-skips-binding', PROOF, 'check_binding(&reader.ledger.conn, &binding)?;', 'let _ = &binding;',
     [rust('evidence_attested_lifecycle'), rust('zz_review_proof_lifecycle', 'rb3_cli_pin_permutations_and_profile_mismatch_create_nothing')]),
  ('BM3-verify-file-skips-exact-schema', PROOF, 'reader.reader.ledger.check_write_profile(true)?;', 'let _ = &reader;',
     [rust('evidence_attested_lifecycle'), rust('evidence_attested_followups'), rust('evidence_attested_store')]),
  ('BM4-cli-verify-overclaims-admission', KAN_V2, '"writable_admission":"not-checked","cryptographic_admission":if attested {"proof-purpose-dependent"}', '"writable_admission":"not-checked","cryptographic_admission":if attested {"admitted-verified"}',
     [rust('evidence_attested_lifecycle', 'owner_cli_requires_all_pins_and_reports_exact_proof_lifecycle')]),
  ('BM5-cli-recover-overclaims-history', KAN_V2, '"cryptographic_admission":if attested {"proof-purpose-dependent"} else {"not-verified"}, "historical_completeness":"not-verified",', '"cryptographic_admission":if attested {"proof-purpose-dependent"} else {"not-verified"}, "historical_completeness":"complete",',
     [rust('evidence_attested_lifecycle', 'owner_cli_requires_all_pins_and_reports_exact_proof_lifecycle')]),
  ('BM6-cli-binding-partial-means-legacy', KAN_V2, '_ => Err("all proof owner pins are required together".into()),', '_ => Ok(None),',
     [rust('evidence_attested_lifecycle', 'owner_cli_requires_all_pins_and_reports_exact_proof_lifecycle'), rust('zz_review_proof_lifecycle', 'rb3_cli_pin_permutations_and_profile_mismatch_create_nothing')]),
]

def run_set(name):
    results = []
    d = OUT / ('mutants-' + name)
    d.mkdir(parents=True, exist_ok=True)
    for (mid, rel, old, new, cmds) in SETS[name]:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode()
        assert text.count(old) == 1, f'{mid}: anchor count {text.count(old)}'
        path.write_text(text.replace(old, new))
        verdicts = []
        try:
            for i, cmd in enumerate(cmds):
                r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
                log = r.stdout + r.stderr
                (d / f'{mid}.{i}.txt').write_text(' '.join(cmd) + '\n' + log)
                if 'could not compile' in log or 'error[E' in log:
                    v = 'COMPILE-ERROR'
                elif r.returncode == 0:
                    v = 'SURVIVED'
                else:
                    failed = [l for l in log.splitlines() if (' ... FAILED' in l) or l.startswith('✖ ')]
                    v = 'KILLED by ' + '; '.join(sorted(set(failed)))[:400] if failed else f'FAILED(rc={r.returncode}, no named test)'
                verdicts.append((' '.join(cmd[-6:]), v))
        finally:
            path.write_bytes(original)
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, f'{mid}: restore mismatch'
        results.append({'mutant': mid, 'file': rel, 'restored_sha256': digest, 'verdicts': verdicts})
        print(json.dumps(results[-1]), flush=True)
    (d / 'SUMMARY.json').write_text(json.dumps(results, indent=1))

if __name__ == '__main__':
    run_set(SET)
