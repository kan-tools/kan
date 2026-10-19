"""Reviewer-run compiled controls for the b11cbf4 correction round.

usage: python3 mutate.py <export_root> <manifest.json> [case ...]
Each case replaces exactly one anchored source string, runs the author suites plus the
temporarily placed reviewer probe file with --no-fail-fast, restores the exact bytes and
checks the restored sha256 against the frozen manifest. Logs: review-evidence/mutations/.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
MANIFEST = json.load(open(sys.argv[2]))["files"]
ONLY = set(sys.argv[3:])
OUT = ROOT / "review-evidence/mutations"
MEMBER = "src/evidence_recovery_member.rs"
FRAME = "src/evidence_recovery_commitment.rs"
AUTHOR = [
    "evidence_recovery_member",
    "evidence_recovery_member_review_regressions",
    "evidence_recovery_member_corrections",
    "evidence_recovery_commitment_review_regressions",
]
PROBES = "zz_corrections_review_probes"

CASES = [
    # (name, origin, file, old, new)
    ("M01-authenticated-length", "author", MEMBER,
     "!hash_valid || c.length.is_none_or(|n| n == object.bytes.len() as u64)",
     "true || !hash_valid || c.length.is_none_or(|n| n == object.bytes.len() as u64)"),
    ("M02-partial-length-kept", "author", MEMBER,
     "if !c.referenced {", "if false && !c.referenced {"),
    ("M03-partial-basis-verified", "author", MEMBER,
     "Basis::UnverifiedMembership\n", "Basis::VerifiedCopyRecipe\n"),
    ("M04-shared-request-allowed", "author", MEMBER,
     'require(!c.referenced, "reused service request CID")?;',
     'require(true || !c.referenced, "reused service request CID")?;'),
    ("M05-request-bound-removed", "author", MEMBER,
     "n <= service::MAX_REQUEST as u64", "true || n <= service::MAX_REQUEST as u64"),
    ("M06-request-bound-off-by-one", "reviewer", MEMBER,
     "n <= service::MAX_REQUEST as u64", "n < service::MAX_REQUEST as u64"),
    ("M07-clear-referenced-too", "reviewer", MEMBER,
     "if !c.referenced {", "if true {"),
    ("M08-clear-in-complete-copies", "reviewer", MEMBER,
     "if !recipe_metadata_complete {\n        for c in keys.values_mut()",
     "if true {\n        for c in keys.values_mut()"),
    ("M09-orphan-basis-as-membership", "reviewer", MEMBER,
     "basis: if !c.member {", "basis: if false && !c.member {"),
    ("M10-length-check-on-all-bytes", "reviewer", MEMBER,
     "!hash_valid || c.length.is_none_or(|n| n == object.bytes.len() as u64)",
     "c.length.is_none_or(|n| n == object.bytes.len() as u64)"),
    ("M11-occurrence-basis-as-recipe", "reviewer", MEMBER,
     "basis: Basis::IssuerMetadata,", "basis: Basis::VerifiedCopyRecipe,"),
    ("M12-issuer-utf8-chars", "author", FRAME,
     "!header.issuer.is_empty() && header.issuer.len() <= 80",
     "!header.issuer.is_empty() && header.issuer.chars().count() <= 80"),
]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def summarise(log):
    per = {}
    current = None
    for line in log.splitlines():
        m = re.search(r"Running tests/(\w+)\.rs", line)
        if m:
            current = m.group(1)
            per.setdefault(current, [])
        m = re.match(r"test (\S+) \.\.\. FAILED", line)
        if m and current:
            per[current].append(m.group(1))
    return per


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    originals = {f: (ROOT / f).read_bytes() for f in [MEMBER, FRAME]}
    for f, b in originals.items():
        assert hashlib.sha256(b).hexdigest() == MANIFEST[f], f + " not at frozen bytes before run"
    summary = []
    try:
        for name, origin, f, old, new in CASES:
            if ONLY and name not in ONLY:
                continue
            src = originals[f].decode()
            assert src.count(old) == 1, (name, src.count(old))
            (ROOT / f).write_text(src.replace(old, new))
            cmd = ["cargo", "test", "--offline", "--features", "v2-crypto", "--no-fail-fast"]
            for t in AUTHOR + [PROBES]:
                cmd += ["--test", t]
            r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=900)
            log = r.stdout + r.stderr
            (OUT / (name + ".txt")).write_text(
                f"# origin={origin} file={f}\n# old={old!r}\n# new={new!r}\n# cmd={' '.join(cmd)}\n"
                + log + f"\n# exit={r.returncode}\n")
            (ROOT / f).write_bytes(originals[f])
            assert sha(ROOT / f) == MANIFEST[f], name + " restore mismatch"
            compile_fail = "could not compile" in log
            per = summarise(log)
            author_fail = {k: v for k, v in per.items() if k != PROBES and v}
            probe_fail = per.get(PROBES, [])
            line = (f"{name} [{origin}] exit={r.returncode} compile_fail={compile_fail} "
                    f"author_failures={json.dumps(author_fail)} reviewer_probe_failures={json.dumps(probe_fail)}")
            print(line, flush=True)
            summary.append(line)
    finally:
        for f, b in originals.items():
            (ROOT / f).write_bytes(b)
        for f in originals:
            assert sha(ROOT / f) == MANIFEST[f], f + " final restore mismatch"
    (OUT / "SUMMARY.txt").write_text("\n".join(summary) + "\nall sources restored to frozen sha256\n")
    print("all sources restored to frozen sha256")


if __name__ == "__main__":
    main()
