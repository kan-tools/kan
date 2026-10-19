#!/usr/bin/env python3
"""Verify export path set + SHA256 vs manifest, and git blob ids at pinned commit."""
import hashlib, json, os, subprocess, sys
REPO = "/Users/m/code/kan-tools/kan/.worktrees/kan-v2-recovery-replay"
EXPORT = os.path.join(REPO, ".local-state/reviews/recovery-replay")
MAN = os.path.join(REPO, ".local-state/reviews/recovery-replay-identity.json")
allowed_extra = set(sys.argv[1:])  # top-level extras allowed (north-star.json, review-evidence)
m = json.load(open(MAN))
commit = m["commit"]; files = m["files"]
present = set()
for root, dirs, fs in os.walk(EXPORT):
    rel_root = os.path.relpath(root, EXPORT)
    if rel_root == ".":
        dirs[:] = [d for d in dirs if d not in allowed_extra]
    for f in fs:
        rel = os.path.normpath(os.path.join(rel_root, f))
        if rel in allowed_extra: continue
        present.add(rel)
missing = sorted(set(files) - present); extra = sorted(present - set(files))
bad = []
for p, h in files.items():
    fp = os.path.join(EXPORT, p)
    if os.path.islink(fp) or not os.path.isfile(fp): continue
    if hashlib.sha256(open(fp, "rb").read()).hexdigest() != h: bad.append(p)
head = subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
commit_full = subprocess.run(["git", "-C", REPO, "rev-parse", commit + "^{commit}"], capture_output=True, text=True).stdout.strip()
ls = subprocess.run(["git", "-C", REPO, "ls-tree", "-r", "-z", "--full-tree", commit], capture_output=True).stdout
tree = {}
for ent in ls.split(b"\0"):
    if not ent: continue
    meta, path = ent.split(b"\t", 1)
    mode, typ, oid = meta.decode().split()
    tree[path.decode()] = (mode, typ, oid)
tree_missing = sorted(set(tree) - set(files)); man_not_tree = sorted(set(files) - set(tree))
blob_bad = []
for p in files:
    if p not in tree: continue
    fp = os.path.join(EXPORT, p)
    data = open(fp, "rb").read()
    oid = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if oid != tree[p][2]: blob_bad.append(p)
# git object hashes of tracked blobs vs manifest sha256 (from repo object db)
print(json.dumps({"commit": commit, "commit_resolved": commit_full, "repo_HEAD": head,
  "manifest_files": len(files), "export_files": len(present), "missing": missing, "extra": extra,
  "sha256_mismatch": bad, "tree_files": len(tree), "tree_not_in_manifest": tree_missing,
  "manifest_not_in_tree": man_not_tree, "blob_mismatch": blob_bad}, indent=1))
ok = not (missing or extra or bad or tree_missing or man_not_tree or blob_bad) and commit_full == commit and head == commit
print("IDENTITY_OK" if ok else "IDENTITY_FAIL")
