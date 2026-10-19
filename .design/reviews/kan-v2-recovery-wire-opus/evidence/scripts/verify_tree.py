#!/usr/bin/env python3
"""Verify export file set and hashes against manifest and pinned git tree blobs."""
import hashlib, json, os, subprocess, sys
REPO = "/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-bundle-codec"
EXPORT = os.path.join(REPO, ".local-state/reviews/recovery-wire")
MAN = os.path.join(REPO, ".local-state/reviews/recovery-wire-identity.json")
man = json.load(open(MAN))
commit = man["commit"]
files = man["files"]
out = subprocess.run(["git", "-C", REPO, "ls-tree", "-r", "--full-tree", "-z", commit], check=True, capture_output=True).stdout
tree = {}
for ent in out.split(b"\0"):
    if not ent: continue
    meta, path = ent.split(b"\t", 1)
    mode, typ, sha = meta.split()
    tree[path.decode()] = (mode.decode(), typ.decode(), sha.decode())
problems = []
if set(tree) != set(files):
    problems.append(("manifest-vs-tree", sorted(set(tree) ^ set(files))[:20]))
# blob hashes from git
blobs = {}
p = subprocess.Popen(["git", "-C", REPO, "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
for path, (mode, typ, sha) in sorted(tree.items()):
    if typ != "blob": problems.append(("nonblob", path, typ)); continue
    p.stdin.write(sha.encode() + b"\n"); p.stdin.flush()
    hdr = p.stdout.readline().split()
    n = int(hdr[2]); data = p.stdout.read(n); p.stdout.read(1)
    blobs[path] = hashlib.sha256(data).hexdigest()
p.stdin.close(); p.wait()
for path in files:
    if blobs.get(path) != files[path]: problems.append(("manifest-vs-blob", path))
# export walk
actual = {}
skip_top = {"review-evidence"}
for root, dirs, fns in os.walk(EXPORT):
    rel = os.path.relpath(root, EXPORT)
    if rel == ".": dirs[:] = [d for d in dirs if d not in skip_top]
    for fn in fns:
        full = os.path.join(root, fn)
        rp = os.path.normpath(os.path.join(rel, fn))
        if os.path.islink(full): actual[rp] = "LINK"; continue
        actual[rp] = hashlib.sha256(open(full, "rb").read()).hexdigest()
extra = sorted(set(actual) - set(files)); missing = sorted(set(files) - set(actual))
changed = sorted(p for p in files if p in actual and actual[p] != files[p])
print("commit", commit, "manifest_files", len(files), "tree_files", len(tree), "export_files", len(actual))
print("extra", extra); print("missing", missing); print("changed", changed)
print("manifest_problems", problems)
ok = not problems and not missing and not changed and extra == ["north-star.json"]
print("RESULT", "OK" if ok else "MISMATCH")
sys.exit(0 if ok else 1)
