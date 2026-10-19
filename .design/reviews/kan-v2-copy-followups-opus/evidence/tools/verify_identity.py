"""Verify the frozen export against the identity manifest and the git tree.

Usage: python3 -I verify_identity.py EXPORT_ROOT MANIFEST GIT_WORKTREE

Checks (1) every manifest file's sha256, (2) no unexpected files outside the
allowed review-evidence/ and north-star.json extras, (3) manifest file set and
blob content equal `git ls-tree -r <commit>` in the read-only git worktree.
"""
import hashlib
import json
import os
import subprocess
import sys

root, manifest_path, git_root = sys.argv[1:4]
manifest = json.load(open(manifest_path))
commit = manifest["commit"]
files = manifest["files"]
EXTRA_ALLOWED = {"north-star.json"}
EXTRA_PREFIX = ("review-evidence/",)

bad = 0
for rel, want in sorted(files.items()):
    p = os.path.join(root, rel)
    try:
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    except OSError as e:
        print("MISSING", rel, e)
        bad += 1
        continue
    if h != want:
        print("HASH-MISMATCH", rel, h, want)
        bad += 1

on_disk = set()
for dp, dns, fns in os.walk(root):
    for fn in fns:
        rel = os.path.relpath(os.path.join(dp, fn), root)
        on_disk.add(rel)
extra = sorted(
    r for r in on_disk - set(files)
    if r not in EXTRA_ALLOWED and not r.startswith(EXTRA_PREFIX)
)
for r in extra:
    print("UNEXPECTED", r)
    bad += 1

out = subprocess.run(
    ["git", "-C", git_root, "ls-tree", "-r", "-z", commit],
    capture_output=True, check=True,
).stdout.split(b"\0")
tree = {}
for ent in out:
    if not ent:
        continue
    meta, path = ent.split(b"\t", 1)
    mode, typ, oid = meta.split()
    tree[path.decode()] = (mode.decode(), oid.decode())
if set(tree) != set(files):
    for r in sorted(set(tree) - set(files)):
        print("IN-TREE-NOT-MANIFEST", r)
    for r in sorted(set(files) - set(tree)):
        print("IN-MANIFEST-NOT-TREE", r)
    bad += 1
for rel, (mode, oid) in sorted(tree.items()):
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        continue
    data = open(p, "rb").read()
    blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if blob != oid:
        print("BLOB-MISMATCH", rel, blob, oid)
        bad += 1
print(f"commit={commit} manifest_files={len(files)} tree_files={len(tree)} "
      f"extras_allowed_present={sorted(EXTRA_ALLOWED & on_disk)} problems={bad}")
sys.exit(1 if bad else 0)
