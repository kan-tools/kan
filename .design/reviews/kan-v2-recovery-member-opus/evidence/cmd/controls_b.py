#!/usr/bin/env python3
"""Scope B: reproduce the 13 follow-up controls (cases read from the tracked
reviewer-cases.json) plus reviewer additions, against the promoted target and
polling units. Restores and hash-checks src/evidence_recovery_commitment.rs."""
import hashlib, json, os, re, subprocess, sys, time
EXPORT = "/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-member/.local-state/reviews/recovery-member"
FILE = os.path.join(EXPORT, "src/evidence_recovery_commitment.rs")
OUT = os.path.join(EXPORT, "review-evidence/mutations/scope-b")
IDENT = json.load(open(os.path.join(os.path.dirname(EXPORT), "recovery-member-identity.json")))
FROZEN = IDENT["files"]["src/evidence_recovery_commitment.rs"]
CASES = json.load(open(os.path.join(EXPORT, ".design/reviews/kan-v2-recovery-commitment-followups-author/reviewer-cases.json")))
SEL = ['AC01','AC02','AC03','AC04','AC05','AC06','AC07','AC08','AC09','AC10','AC16','AC17','AC25']
cases = [(c['name'], c['old'], c['new'], c['count']) for c in CASES if c['name'][:4] in SEL]
cases += [
 ('RB1-poll-every-128KiB','for part in bytes.chunks(64 * 1024) {\n            self.meter.spend(part.len())?;','for part in bytes.chunks(128 * 1024) {\n            self.meter.spend(part.len())?;',1),
 ('RB2-verify-poll-every-128KiB','for part in bytes.chunks(64 * 1024) {\n            self.core.meter.spend(part.len())?;','for part in bytes.chunks(128 * 1024) {\n            self.core.meter.spend(part.len())?;',1),
 ('RB3-issuer-bound-in-chars','!header.issuer.is_empty() && header.issuer.len() <= 80','!header.issuer.is_empty() && header.issuer.chars().count() <= 80',1),
 ('RB4-put-initial-check-removed','fn put(&mut self, bytes: &[u8]) -> Result<()> {\n        self.meter.check()?;','fn put(&mut self, bytes: &[u8]) -> Result<()> {',1),
]
ALL = ["cargo","test","--offline","--no-fail-fast","--features","v2-crypto"]
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
def main():
    os.makedirs(OUT, exist_ok=True)
    original = open(FILE,'rb').read(); assert hashlib.sha256(original).hexdigest()==FROZEN
    text = original.decode(); summary=[]
    try:
        for name, old, new, count in cases:
            n = text.count(old)
            if n != count:
                summary.append(f"{name}\tNOT-APPLIED count={n}"); print(summary[-1], flush=True); continue
            open(FILE,'w').write(text.replace(old,new))
            logs=[]; rcs=[]
            for args in (["--lib","evidence_recovery_commitment::polling_tests"],
                         ["--test","evidence_recovery_commitment","--test","evidence_recovery_commitment_review_regressions"]):
                cmd = ALL+args
                p = subprocess.run(cmd,cwd=EXPORT,capture_output=True,text=True,timeout=1800)
                logs.append(f"## cmd: {' '.join(cmd)}\n## exit={p.returncode}\n"+p.stdout+p.stderr); rcs.append(p.returncode)
            open(FILE,'wb').write(original); assert sha(FILE)==FROZEN
            log="\n".join(logs)
            failed = re.findall(r'^test (\S+) \.\.\. FAILED', log, re.M)
            msgs = re.findall(r"assertion[^\n]*failed[^\n]*|must refuse|left: [^\n]*|right: [^\n]*", log)
            cerr = 'could not compile' in log
            status = "COMPILE-ERROR" if cerr else ("SURVIVED" if all(r==0 for r in rcs) else "KILLED")
            open(os.path.join(OUT,name+'.txt'),'w').write(f"# {name}\n# old: {old!r}\n# new: {new!r}\n# restored_sha256={sha(FILE)}\n\n"+log)
            line=f"{name}\t{status}\tfailed={','.join(failed) or '-'}\tmsgs={' | '.join(msgs[:4])}"
            summary.append(line); print(line, flush=True)
    finally:
        open(FILE,'wb').write(original); assert sha(FILE)==FROZEN
    open(os.path.join(OUT,'SUMMARY.tsv'),'w').write("\n".join(summary)+"\n")
if __name__=='__main__': main()
