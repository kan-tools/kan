#!/usr/bin/env python3
"""Reviewer compiled guard-removal controls for src/evidence_recovery_member.rs.
Each case: exact-count replace, run author suite + reviewer probes (--no-fail-fast),
record failing tests/panic messages, restore, verify sha256 == frozen manifest.
Outputs to review-evidence/mutations/. Never touches git."""
import hashlib, json, os, re, subprocess, sys, time
EXPORT = "/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-member/.local-state/reviews/recovery-member"
FILE = os.path.join(EXPORT, "src/evidence_recovery_member.rs")
OUT = os.path.join(EXPORT, "review-evidence/mutations" + ("/round2" if os.environ.get("PROBES2") else ""))
IDENT = json.load(open(os.path.join(os.path.dirname(EXPORT), "recovery-member-identity.json")))
FROZEN = IDENT["files"]["src/evidence_recovery_member.rs"]
AUTHOR = [  # verbatim from scripts/recovery_member_negative_controls.py
 ('A-item-budget','if u64::try_from(items).map_err(|_| Error::Budget)? > budget.items','if false && u64::try_from(items).map_err(|_| Error::Budget)? > budget.items'),
 ('A-input-budget','if self.bytes > self.budget.input_bytes','if false && self.bytes > self.budget.input_bytes'),
 ('A-cancelled','if self.budget.cancelled.load(Ordering::Relaxed)','if false && self.budget.cancelled.load(Ordering::Relaxed)'),
 ('A-source-digest','require(digest == p.source().digest, "source metadata digest")?','require(true || digest == p.source().digest, "source metadata digest")?'),
 ('A-expected-length','c.length.is_none_or(|old| old == n)','true || c.length.is_none_or(|old| old == n)'),
 ('A-duplicate-operation','operations.insert((writer.to_string(), op.to_vec()))','true || operations.insert((writer.to_string(), op.to_vec()))'),
 ('A-original-hash','&& actual == object.cid.to_bytes()[4..]','&& (true || actual == object.cid.to_bytes()[4..])'),
 ('A-orphan-loss','if !c.referenced && c.state != Availability::Available','if false && !c.referenced && c.state != Availability::Available'),
 ('A-writer-signature','.map_err(|_| Error::Invalid("retained writer request"))?;','.ok();'),
]
REVIEWER = [
 ('R01-historical-receipt-issuer','require(r.body()["issuer"] == author, "historical receipt issuer")?;','require(true || r.body()["issuer"] == author, "historical receipt issuer")?;'),
 ('R02-source-tip','require(plan.source().tip.as_ref() == Some(m.cid()), "source tip")?','require(true || plan.source().tip.as_ref() == Some(m.cid()), "source tip")?'),
 ('R03-slot-conflict','slots.get(&sk).is_none_or(|old| old == &sv)','true || slots.get(&sk).is_none_or(|old| old == &sv)'),
 ('R04-service-slot','require(slot.as_slice() == expected_slot, "service slot")?;','require(true || slot.as_slice() == expected_slot, "service slot")?;'),
 ('R05-retained-membership','require(c.member, "retained reference absent from membership")?','require(true || c.member, "retained reference absent from membership")?'),
 ('R06-partial-untracked-object','require(c.member, "untracked object in partial copy")?','require(true || c.member, "untracked object in partial copy")?'),
 ('R07-proof-purpose','p.purpose()\n                == if retained {','true || p.purpose()\n                == if retained {'),
 ('R08-null-loss-for-membership-keys','if !c.referenced && c.state != Availability::Available','if !c.referenced && !c.member && c.state != Availability::Available'),
 ('R09-writer-predecessor','require(\n            match expected {','require(\n            true || match expected {'),
 ('R10-static-writer','service::author(writer).map_err(|_| Error::Invalid("static writer"))? == b["writer"],','true || service::author(writer).map_err(|_| Error::Invalid("static writer"))? == b["writer"],'),
 ('R11-plan-scope-issuer-binding','p.archive_id() == ctx.archive\n                    && p.target().scope == ctx.scope\n                    && p.target().issuer == ctx.issuer,','p.archive_id() == ctx.archive,'),
 ('R12-hash-unchunked','for part in bytes.chunks(65536) {','for part in bytes.chunks(usize::MAX) {'),
 ('R13-hash-no-poll','for part in bytes.chunks(65536) {\n            self.check()?;','for part in bytes.chunks(65536) {'),
 ('R14-new-initial-check','s.check()?;\n        Ok(s)','Ok(s)'),
 ('R15-membership-input-charge','work.input(44)?;',''),
 ('R16-full-flag-always-false','let full = frontier.through >= p.source().through;','let full = false;'),
 ('R17-nonempty-original','let valid = !object.bytes.is_empty()\n            &&','let valid = true\n            &&'),
 ('R18-record-position','require(row.sequence == frontier.through + 1, "record position")?;','require(true || row.sequence == frontier.through + 1, "record position")?;'),
]
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
def run_tests():
    cmd = ["cargo","test","--offline","--no-fail-fast","--features","v2-crypto","--test","evidence_recovery_member","--test","zz_review_member_probes"]+(["--test","zz_review_member_probes2"] if os.environ.get("PROBES2") else [])+["--","--test-threads=1"]
    t=time.time(); p=subprocess.run(cmd,cwd=EXPORT,capture_output=True,text=True,timeout=1800)
    return p.returncode, p.stdout+p.stderr, time.time()-t, cmd
def classify(log):
    failed = re.findall(r'^test (\S+) \.\.\. FAILED', log, re.M)
    panics = re.findall(r"panicked at ([^\n]+)\n([^\n]*)\n?([^\n]*)", log)
    compile_err = 'could not compile' in log or 'error[E' in log
    return failed, panics, compile_err
def main():
    os.makedirs(OUT, exist_ok=True)
    original = open(FILE,'rb').read()
    assert hashlib.sha256(original).hexdigest()==FROZEN, "source not frozen before controls"
    text = original.decode()
    which = sys.argv[1:] or [c[0] for c in AUTHOR+REVIEWER]
    summary=[]
    try:
        for name, old, new in AUTHOR+REVIEWER:
            if name not in which: continue
            n = text.count(old)
            if n != 1:
                summary.append(f"{name}\tNOT-APPLIED count={n}"); print(summary[-1], flush=True); continue
            open(FILE,'w').write(text.replace(old,new))
            rc, log, dt, cmd = run_tests()
            open(FILE,'wb').write(original)
            assert sha(FILE)==FROZEN, "restore failed"
            failed, panics, cerr = classify(log)
            with open(os.path.join(OUT,name+'.txt'),'w') as fh:
                fh.write(f"# mutation {name}\n# old: {old!r}\n# new: {new!r}\n# cmd: {' '.join(cmd)}\n# exit={rc} elapsed={dt:.1f}s restored_sha256={sha(FILE)}\n\n"+log)
            status = "COMPILE-ERROR" if cerr else ("SURVIVED" if rc==0 else "KILLED")
            line=f"{name}\t{status}\tfailed={','.join(failed) or '-'}"
            summary.append(line); print(line, flush=True)
    finally:
        open(FILE,'wb').write(original)
        assert sha(FILE)==FROZEN
    with open(os.path.join(OUT,'SUMMARY-'+time.strftime('%H%M%S')+'.tsv'),'w') as fh: fh.write("\n".join(summary)+"\n")
if __name__=='__main__': main()
