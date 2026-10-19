#!/usr/bin/env python3 -I
"""Verify the frozen export against the identity manifest and the git tree.

Usage: verify_export.py <export_dir> <manifest.json> <repo_path>
Read-only: uses git ls-tree --full-tree and git cat-file only.
"""
import hashlib
import json
import os
import subprocess
import sys

export, manifest_path, repo = sys.argv[1:4]
manifest = json.load(open(manifest_path))
commit = manifest["commit"]
files = manifest["files"]

tree = subprocess.run(
    ["git", "-C", repo, "ls-tree", "-r", "-z", "--full-tree", commit],
    check=True, capture_output=True,
).stdout.split(b"\0")
blobs = {}
for entry in tree:
    if not entry:
        continue
    meta, path = entry.split(b"\t", 1)
    mode, kind, oid = meta.split(b" ")
    blobs[path.decode()] = (mode.decode(), kind.decode(), oid.decode())

problems = []
tree_files = {p for p, (_, k, _) in blobs.items() if k == "blob"}
if set(files) != tree_files:
    problems.append(("manifest!=tree", sorted(set(files) ^ tree_files)[:50]))

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

git_mismatch = 0
for rel, want in sorted(files.items()):
    p = os.path.join(export, rel)
    if not os.path.isfile(p):
        problems.append(("missing", rel))
        continue
    got = sha(p)
    if got != want:
        problems.append(("export!=manifest", rel, got, want))
    oid = blobs.get(rel, (None, None, None))[2]
    if oid:
        data = subprocess.run(["git", "-C", repo, "cat-file", "blob", oid],
                              check=True, capture_output=True).stdout
        if hashlib.sha256(data).hexdigest() != want:
            git_mismatch += 1
            problems.append(("tree!=manifest", rel))

extra = []
for root, dirs, names in os.walk(export):
    for n in names:
        rel = os.path.relpath(os.path.join(root, n), export)
        if rel not in files:
            extra.append(rel)
extra_top = sorted({e.split(os.sep)[0] if not e.startswith("review-evidence") else "review-evidence/" for e in extra})

print(f"commit {commit}")
print(f"manifest files {len(files)}; tree blobs {len(tree_files)}")
print(f"extra paths outside manifest (top-level grouping): {extra_top}")
print(f"extra non-evidence files: {sorted(e for e in extra if not e.startswith('review-evidence'))}")
print(f"problems {len(problems)}")
for p in problems[:100]:
    print("  ", p)
sys.exit(1 if problems else 0)
