#!/usr/bin/env python3
"""Verify the frozen export and source repository against the pinned identity.

Usage: verify_identity.py IDENTITY_JSON EXPORT_DIR SOURCE_REPO
Checks:
  1. export path set == manifest paths + {north-star.json} (+ review-evidence/ ignored)
  2. every export file SHA256 == manifest
  3. every export file git-blob hash (sha1 "blob N\\0") == pinned git_blobs
  4. source repo `git ls-tree -r <commit>` path->blob == pinned git_blobs
  5. source repo HEAD == commit and `git status --porcelain` output (reported)
"""
import hashlib, json, os, subprocess, sys

ident_path, export, repo = sys.argv[1:4]
ident = json.load(open(ident_path))
files, blobs, commit = ident["files"], ident["git_blobs"], ident["commit"]
ok = True

def fail(msg):
    global ok
    ok = False
    print("FAIL", msg)

if set(files) != set(blobs):
    fail("manifest files/git_blobs key sets differ")

seen = set()
for root, dirs, names in os.walk(export):
    rel_root = os.path.relpath(root, export)
    if rel_root == "review-evidence" or rel_root.startswith("review-evidence" + os.sep):
        dirs[:] = []
        continue
    for n in names:
        p = os.path.normpath(os.path.join(rel_root, n))
        seen.add(p)
extra = sorted(seen - set(files))
missing = sorted(set(files) - seen)
print("export_files", len(seen), "manifest_files", len(files))
print("extra", extra)
print("missing", missing)
if extra != ["north-star.json"]:
    fail("unexpected extra set %r" % extra)
if missing:
    fail("missing files")

sha_bad = blob_bad = 0
for p in sorted(set(files) & seen):
    full = os.path.join(export, p)
    if os.path.islink(full):
        data = os.readlink(full).encode()
    else:
        data = open(full, "rb").read()
    if hashlib.sha256(data).hexdigest() != files[p]:
        sha_bad += 1
        fail("sha256 mismatch " + p)
    gb = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if gb != blobs[p]:
        blob_bad += 1
        fail("git blob mismatch " + p)
print("sha256_mismatches", sha_bad, "blob_mismatches", blob_bad)

out = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "-z", commit],
                     capture_output=True, check=True).stdout
tree = {}
for ent in out.split(b"\0"):
    if not ent:
        continue
    meta, path = ent.split(b"\t", 1)
    mode, typ, obj = meta.split()
    tree[path.decode()] = obj.decode()
if tree != blobs:
    d1 = set(tree) ^ set(blobs)
    d2 = [p for p in set(tree) & set(blobs) if tree[p] != blobs[p]]
    fail("commit tree != pinned blobs: pathdiff=%r blobdiff=%r" % (sorted(d1)[:20], d2[:20]))
print("commit_tree_entries", len(tree), "matches_pinned", tree == blobs)
head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
print("source_HEAD", head, "pinned", commit, "equal", head == commit)
if head != commit:
    fail("HEAD differs")
st = subprocess.run(["git", "-C", repo, "status", "--porcelain=v1", "--untracked-files=no"],
                    capture_output=True, text=True).stdout
print("source_tracked_status_porcelain", repr(st))
if st:
    fail("source tracked tree dirty")
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
