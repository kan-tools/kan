#!/usr/bin/env python3
"""Verify every tracked export file against the identity manifest.
Usage: python3 -I verify_identity.py <export_root> <manifest> [label]
Extra (untracked) files are listed; review-evidence/ is excluded."""
import hashlib, json, os, sys
root, manifest = sys.argv[1], sys.argv[2]
label = sys.argv[3] if len(sys.argv) > 3 else "check"
m = json.load(open(manifest))
files = m["files"]
bad, missing = [], []
for rel, want in sorted(files.items()):
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        missing.append(rel); continue
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    if h != want:
        bad.append((rel, want, h))
extra = []
for dp, dn, fn in os.walk(root):
    reld = os.path.relpath(dp, root)
    if reld == "review-evidence" or reld.startswith("review-evidence" + os.sep):
        continue
    for f in fn:
        rel = os.path.normpath(os.path.join(reld, f))
        if rel not in files:
            extra.append(rel)
print(f"[{label}] commit={m['commit']} tracked={len(files)} ok={len(files)-len(bad)-len(missing)} mismatched={len(bad)} missing={len(missing)} extra_untracked={len(extra)}")
for r in bad: print("MISMATCH", *r)
for r in missing: print("MISSING", r)
for r in sorted(extra): print("EXTRA", r)
sys.exit(1 if (bad or missing) else 0)
