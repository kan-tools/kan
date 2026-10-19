import subprocess, hashlib, os, sys
commit, root = sys.argv[1], sys.argv[2]
out = subprocess.run(["git","ls-tree","--full-tree","-r","-z",commit],capture_output=True,check=True).stdout.decode().split("\0")
bad=[]; n=0; missing=[]; paths=set()
for line in out:
    if not line: continue
    meta, path = line.split("\t",1); mode, typ, oid = meta.split(); n+=1; paths.add(path)
    p=os.path.join(root,path)
    if mode=="160000": continue
    if not os.path.lexists(p): missing.append(path); continue
    data=open(p,'rb').read() if mode!="120000" else os.readlink(p).encode()
    if hashlib.sha1(b"blob %d\0"%len(data)+data).hexdigest()!=oid: bad.append(path)
extra=[]
for d,dn,fn in os.walk(root):
    rd=os.path.relpath(d,root)
    if rd.split(os.sep)[0]=="review-evidence": dn[:]=[]; continue
    for f in fn:
        r=os.path.normpath(os.path.join(rd,f))
        if r not in paths: extra.append(r)
print("tree entries",n,"mismatch",bad,"missing",missing,"extra",extra)
