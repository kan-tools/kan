# usage: python3 -I verify_identity.py <export_root> <identity.json> <repo_path> <label>
import hashlib, json, os, subprocess, sys
root, ident, repo, label = sys.argv[1:5]
d = json.load(open(ident))
commit = d["commit"]
files = d["files"]
tree = subprocess.run(["git", "-C", repo, "ls-tree", "-r", "--full-tree", "--name-only", "-z", commit],
                      check=True, capture_output=True).stdout.split(b"\0")
tree = sorted(t.decode() for t in tree if t)
head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
actual = []
for dp, dn, fn in os.walk(root):
    rel = os.path.relpath(dp, root)
    if rel == "review-evidence" or rel.startswith("review-evidence" + os.sep):
        dn[:] = []
        continue
    for f in fn:
        actual.append(os.path.normpath(os.path.join(rel, f)))
    for x in list(dn):
        p = os.path.join(dp, x)
        if os.path.islink(p):
            actual.append(os.path.normpath(os.path.join(rel, x)))
actual = sorted(actual)
bad = 0
for p, h in files.items():
    fp = os.path.join(root, p)
    if os.path.islink(fp):
        got = hashlib.sha256(os.readlink(fp).encode()).hexdigest()
    elif not os.path.isfile(fp):
        print("MISSING", p); bad += 1; continue
    else:
        got = hashlib.sha256(open(fp, "rb").read()).hexdigest()
    if got != h:
        print("HASH MISMATCH", p); bad += 1
print(f"[{label}] repo={repo} HEAD={head} manifest_commit={commit} head_match={head==commit}")
print(f"[{label}] manifest files={len(files)} git ls-tree files={len(tree)} export files(excl review-evidence)={len(actual)}")
print(f"[{label}] manifest==ls-tree: {sorted(files)==tree}")
extra = sorted(set(actual) - set(tree)); missing = sorted(set(tree) - set(actual))
print(f"[{label}] extra vs ls-tree: {extra}")
print(f"[{label}] missing vs ls-tree: {missing}")
print(f"[{label}] hash mismatches/missing: {bad}")
print(f"[{label}] RESULT: {'OK' if bad==0 and sorted(files)==tree and extra==['north-star.json'] and not missing and head==commit else 'FAIL'}")
