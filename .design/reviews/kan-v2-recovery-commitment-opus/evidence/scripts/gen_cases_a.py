#!/usr/bin/env python3
"""Generate scope-A mutation cases (reviewer-designed + one author control reproduced)."""
import json, sys
E = '/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-state/.local-state/reviews/recovery-commitment'
F = 'src/evidence_recovery_commitment.rs'
env = {'REVIEW_VECTORS': E + '/review-evidence/probes/reviewer-vectors.json'}
tests = ['evidence_recovery_commitment', 'zz_review_commitment_probes']
S = ' ' * 4
cases = [
 ('AC00-author-binary-cid-order', 'Ok((cid.to_string(), raw))', 'Ok((format!("{:02x?}", raw), raw))', 1),
 ('AC01-put-unchunked', 'for part in bytes.chunks(64 * 1024) {\n            self.meter.spend(part.len())?;\n            self.hash.update(part)',
  'for part in bytes.chunks(usize::MAX) {\n            self.meter.spend(part.len())?;\n            self.hash.update(part)', 1),
 ('AC02-verify-unchunked', 'for part in bytes.chunks(64 * 1024) {\n            self.core.meter.spend(part.len())?;\n            hash.update(part)',
  'for part in bytes.chunks(usize::MAX) {\n            self.core.meter.spend(part.len())?;\n            hash.update(part)', 1),
 ('AC03-candidate-empty-allowed', '!bytes.is_empty() && bytes.len() <= MAX_OBJECT,', 'bytes.len() <= MAX_OBJECT,', 1),
 ('AC04-membership-zero-length', '(1..=MAX_OBJECT as u64).contains(&length)', '(0..=MAX_OBJECT as u64).contains(&length)', 1),
 ('AC05-proof-bound-16385', '(proof, 16384)', '(proof, 16385)', 1),
 ('AC06-plan-bound-4097', 'p.len() <= 4096', 'p.len() <= 4097', 1),
 ('AC07-plan-empty-allowed', '!p.is_empty() && p.len() <= 4096', 'p.len() <= 4096', 1),
 ('AC08-issuer-bound-removed', '!header.issuer.is_empty() && header.issuer.len() <= 80', 'true', 1),
 ('AC09-membership-phase-check-removed', 's.phase == Phase::Membership && s.seen < s.counts.membership', 's.seen < s.counts.membership', 1),
 ('AC10-member-finish-count-removed', 'self.phase == Phase::Objects && self.seen == self.counts.objects', 'self.phase == Phase::Objects', 1),
 ('AC11-object-order-not-reset', 's.phase = Phase::Objects;\n            s.seen = 0;\n            s.last = None;', 's.phase = Phase::Objects;\n            s.seen = 0;', 1),
 ('AC12-item-precheck-removed', 'if items > limits.items {\n            return Err(Error::Budget);\n        }', '', 1),
 ('AC13-item-runtime-check-removed', 'if self.items > self.limits.items {', 'if false && self.items > self.limits.items {', 1),
 ('AC14-deadline-removed', 'if Instant::now() >= self.deadline {', 'if false && Instant::now() >= self.deadline {', 1),
 ('AC15-finish-recheck-removed', 'self.meter.check()?;\n        Ok(self.hash.finalize().into())', 'Ok(self.hash.finalize().into())', 1),
 ('AC16-safe-count-removed', 'shape(count <= SAFE, "count")?', 'shape(true, "count")?', 2),
 ('AC17-duration-upper-removed', ' && limits.duration <= Duration::from_secs(3600)', '', 1),
 ('AC18-verify-not-charged', 'self.core.meter.spend(part.len())?;\n            hash.update(part)', 'hash.update(part)', 1),
 ('AC19-operation-poison-not-set', 'self.core.failed = true;\n        let result', 'let result', 1),
 ('AC20-candidate-poison-not-set', 'self.core.failed = true;\n        shape(self.seen < self.count', 'shape(self.seen < self.count', 1),
 ('AC21-object-max-plus1', 'shape(bytes.len() <= MAX_OBJECT, "object bytes")', 'shape(bytes.len() <= MAX_OBJECT + 1, "object bytes")', 1),
 ('AC22-raw-key-any-codec', 'raw[..4] == [1, 0x55, 0x12, 0x20]', 'raw[..4] == [1, raw[1], 0x12, 0x20]', 1),
 ('AC23-record-receipt-proof-swapped', 's.core.frame(receipt)?;\n            s.core.frame(proof)?;', 's.core.frame(proof)?;\n            s.core.frame(receipt)?;', 1),
 ('AC24-membership-length-unframed', 's.core.frame(&key)?;\n            s.core.n(length)?;', 's.core.frame(&key)?;', 1),
 ('AC25-cancel-check-only-at-new', 'fn spend(&mut self, bytes: usize) -> Result<()> {\n        self.check()?;', 'fn spend(&mut self, bytes: usize) -> Result<()> {', 1),
]
out = [{'name': n, 'file': F, 'old': o, 'new': w, 'count': c, 'cargo_tests': tests, 'env': env} for n, o, w, c in cases]
json.dump(out, open(sys.argv[1], 'w'), indent=1)
print(len(out), 'cases')
