# Usage: python3 -I verify_identity.py <export_root> <identity.json> <git_repo_dir>
# Checks: every manifest sha256 matches; set of files on disk (excluding
# review-evidence/) equals manifest set; every manifest file's git blob hash
# equals the blob at the manifest commit (git ls-tree -r).
import hashlib, json, os, subprocess, sys
root, ident, repo = sys.argv[1:4]
d = json.load(open(ident))
commit, files = d["commit"], d["files"]
bad = []
for rel, h in sorted(files.items()):
    p = os.path.join(root, rel)
    try:
        got = hashlib.sha256(open(p, "rb").read()).hexdigest()
    except OSError as e:
        bad.append(("missing", rel, str(e))); continue
    if got != h: bad.append(("sha256", rel, got))
disk = set()
for dp, dns, fns in os.walk(root):
    rp = os.path.relpath(dp, root)
    if rp == "review-evidence" or rp.startswith("review-evidence" + os.sep):
        dns[:] = []; continue
    for f in fns:
        disk.add(os.path.normpath(os.path.join(rp, f)))
extra = sorted(disk - set(files)); missing = sorted(set(files) - disk)
ls = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "-z", commit], capture_output=True, check=True).stdout
tree = {}
for ent in ls.split(b"\0"):
    if not ent: continue
    meta, path = ent.split(b"\t", 1)
    _, typ, obj = meta.split()
    tree[path.decode()] = obj.decode()
tree_only = sorted(set(tree) - set(files)); man_only = sorted(set(files) - set(tree))
blobmis = []
for rel in sorted(set(tree) & set(files)):
    p = os.path.join(root, rel)
    data = open(p, "rb").read()
    bh = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
    if bh != tree[rel]: blobmis.append(rel)
tree_id = subprocess.run(["git", "-C", repo, "rev-parse", commit + "^{tree}"], capture_output=True, text=True).stdout.strip()
print("commit", commit, "tree", tree_id)
print("manifest_files", len(files), "git_tree_files", len(tree))
print("sha256_mismatch_or_missing", bad)
print("disk_extra_not_in_manifest", extra)
print("manifest_missing_on_disk", missing)
print("git_tree_not_in_manifest", tree_only)
print("manifest_not_in_git_tree", man_only)
print("git_blob_mismatch", blobmis)
ok = not (bad or extra or missing or tree_only or man_only or blobmis)
print("RESULT", "OK" if ok else "MISMATCH")
