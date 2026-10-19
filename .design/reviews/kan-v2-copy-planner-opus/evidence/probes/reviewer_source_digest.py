#!/usr/bin/env python3
"""Reviewer-only independent copy-source digest, written from the design text
(.design/kan-v2-evidence-availability.md "Draft read-only source planner").
No import of repository code. Sorting happens in Python, not SQL. Read-only URI.
"""
import base64, hashlib, sqlite3, sys
from pathlib import Path

def u64(n):
    return n.to_bytes(8, 'big')

def frame(b):
    return u64(len(b)) + b

class Dec:
    def __init__(self, b): self.b, self.i = b, 0
    def take(self, n):
        r = self.b[self.i:self.i + n]; self.i += n; assert len(r) == n; return r
    def arg(self, low):
        if low < 24: return low
        return int.from_bytes(self.take({24: 1, 25: 2, 26: 4, 27: 8}[low]), 'big')
    def item(self):
        ib = self.take(1)[0]; major, low = ib >> 5, ib & 31
        if major == 7:
            return {20: False, 21: True, 22: None}[low]
        n = self.arg(low)
        if major == 0: return n
        if major == 1: return -1 - n
        if major == 2: return self.take(n)
        if major == 3: return self.take(n).decode()
        if major == 4: return [self.item() for _ in range(n)]
        if major == 5: return {self.item(): self.item() for _ in range(n)}
        if major == 6:
            assert n == 42
            raw = self.item(); assert raw[0] == 0
            return ('cid', raw[1:])
        raise ValueError(ib)

def cid_str_to_bytes(s):
    assert s.startswith('b')
    t = s[1:].upper(); t += '=' * (-len(t) % 8)
    return base64.b32decode(t)

def digest(path):
    conn = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    conn.execute('BEGIN')
    commits = conn.execute('SELECT sequence,manifest,receipt FROM commits').fetchall()
    objects = conn.execute('SELECT cid,bytes FROM objects').fetchall()
    conn.close()
    commits.sort(key=lambda r: r[0])
    objects.sort(key=lambda r: r[0])  # lexical CID-string order, in Python
    out = b'tools.kan.archive.copy-source.v1\x00' + frame(b'commits') + u64(len(commits))
    for expected, (seq, manifest, receipt) in enumerate(commits, 1):
        assert seq == expected
        m = Dec(manifest).item()
        entries = m['body']['entries']; assert len(entries) == 1
        kind, request_cid = entries[0]['ciphertext']; assert kind == 'cid'
        out += u64(seq) + frame(manifest) + frame(receipt) + frame(request_cid)
    out += frame(b'objects') + u64(len(objects))
    for cid, body in objects:
        raw = cid_str_to_bytes(cid)
        assert raw == bytes([1, 0x55, 0x12, 0x20]) + hashlib.sha256(body).digest(), cid
        out += frame(raw) + u64(len(body))
    return hashlib.sha256(out).hexdigest()

if __name__ == '__main__':
    print(digest(sys.argv[1]))
