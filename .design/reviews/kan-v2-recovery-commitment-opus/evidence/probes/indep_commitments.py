#!/usr/bin/env python3
"""Reviewer-independent M1/O1/R1 framing, written from codec-doc prose only:
.design/kan-v2-recovery-bundle-codec.md "Initial member commitment M1" (1-6),
"O1 has exactly M1 framing with the initial domain replaced", and the R1 paragraph.

Does not import the author oracle. Emits (a) a cross-check of the stored author
fixture, (b) new reviewer vectors with exact work-byte budgets for the Rust probe.
Usage: indep_commitments.py <fixture.json> <out-vectors.json>
"""
import base64, hashlib, json, random, sys

def N(n): return n.to_bytes(8, "big")
def F(b): return N(len(b)) + b

def cid_raw(data):  # CIDv1, raw codec 0x55, sha2-256 multihash
    return bytes([1, 0x55, 0x12, 0x20]) + hashlib.sha256(data).digest()

def cid_text(raw):
    return "b" + base64.b32encode(raw).decode().lower().rstrip("=")

def text_to_raw(t):
    s = t[1:].upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))

def member_stream(m, domain):
    for sec in ('membership', 'objects'):
        keys = [r[0] for r in m[sec]]
        assert len(keys) == len(set(keys)), 'duplicate key in ' + sec
    out = [domain, N(m["profile"]), F(m["archive"]), F(m["scope"]), F(m["issuer"].encode())]
    out.append(F(b"plan"))
    if m["plan"] is None:
        out.append(N(0))
    else:
        out += [N(1), F(m["plan"])]
    ms = sorted(m["membership"], key=lambda r: r[0])           # canonical CID text order
    out += [F(b"original-membership"), N(len(ms))]
    for t, length in ms:
        out += [F(text_to_raw(t)), N(length)]
    out += [F(b"records"), N(len(m["records"]))]
    for seq, man, rec, proof in m["records"]:
        out += [N(seq), F(man), F(rec), F(proof)]
    objs = sorted(m["objects"], key=lambda r: r[0])
    out += [F(b"original-objects"), N(len(objs))]
    for t, data in objs:
        out += [F(text_to_raw(t)), N(len(data)), F(data)]
    return b"".join(out)

MEMBER = b"tools.kan.recovery.member.v1\0"
OUTPUT = b"tools.kan.recovery.output.v1\0"
RESTORE = b"tools.kan.recovery.restorations.v1\0"

def r1_stream(cands):
    cs = sorted(cands, key=lambda r: r[0])
    out = [RESTORE, N(len(cs))]
    for t, data in cs:
        assert cid_text(cid_raw(data)) == t
        out += [F(text_to_raw(t)), N(len(data)), F(data)]
    return b"".join(out)

def decode(v):
    if isinstance(v, dict):
        if set(v) == {"$bytes"}: return bytes.fromhex(v["$bytes"])
        return {k: decode(x) for k, x in v.items()}
    if isinstance(v, list): return [decode(x) for x in v]
    return v

def hexify(v):
    if isinstance(v, bytes): return v.hex()
    if isinstance(v, dict): return {k: hexify(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)): return [hexify(x) for x in v]
    return v

def main():
    fixture = json.load(open(sys.argv[1]))
    lines = []
    ok = True
    for row in fixture["member"]:
        m = decode(row["member"])
        m1 = hashlib.sha256(member_stream(m, MEMBER)).hexdigest()
        o1 = hashlib.sha256(member_stream(m, OUTPUT)).hexdigest()
        good = (m1 == row["M1"] and o1 == row["O1"])
        ok &= good
        lines.append(f"fixture-member {row['name']}: M1 {'match' if m1==row['M1'] else 'MISMATCH'} O1 {'match' if o1==row['O1'] else 'MISMATCH'}")
    for i, row in enumerate(fixture["restorations"]):
        c = decode(row["candidates"])
        r1 = hashlib.sha256(r1_stream(c)).hexdigest()
        ok &= (r1 == row["R1"])
        lines.append(f"fixture-R1 #{i} ({len(c)} candidates): {'match' if r1==row['R1'] else 'MISMATCH'}")

    # Order discrimination census over the fixture's member/R1 multi-key cases.
    for row in fixture["member"]:
        m = decode(row["member"])
        for sec in ("membership", "objects"):
            keys = [r[0] for r in m[sec]]
            if len(keys) > 1:
                t = sorted(keys); b = sorted(keys, key=text_to_raw)
                lines.append(f"order-census {row['name']}.{sec}: text==binary? {t == b}")
    for i, row in enumerate(fixture["restorations"]):
        keys = [r[0] for r in decode(row["candidates"])]
        if len(keys) > 1:
            lines.append(f"order-census R1#{i}: text==binary? {sorted(keys) == sorted(keys, key=text_to_raw)}")

    # Reviewer vectors. Deterministic public synthetic data only.
    rnd = random.Random(20261019)
    blobs = [f"reviewer synthetic object {n}".encode() for n in range(40)]
    keyed = [(cid_text(cid_raw(b)), b) for b in blobs]
    # Distinguishing pairs (text order != binary order).
    pairs = [(a, b) for a in keyed for b in keyed if a[0] < b[0] and not (text_to_raw(a[0]) < text_to_raw(b[0]))]
    lines.append(f"reviewer pool: {len(keyed)} CIDs, {len(pairs)} text-vs-binary disagreeing ordered pairs")
    issuer = "did:key:zDnaeReviewerFramingOnlyNotAValidKeyxxxxxxxxxxxxxxxxxxxxx"
    vectors = []
    def add(name, m, cands=None):
        ms = member_stream(m, MEMBER); os_ = member_stream(m, OUTPUT)
        v = {"name": name, "member": hexify(m), "M1": hashlib.sha256(ms).hexdigest(),
             "O1": hashlib.sha256(os_).hexdigest(), "member_work": len(ms), "output_work": len(os_)}
        if cands is not None:
            rs = r1_stream(cands)
            v["candidates"] = hexify(cands); v["R1"] = hashlib.sha256(rs).hexdigest()
            v["r1_work"] = len(rs) + sum(len(c[1]) for c in cands)  # verify + framing
        vectors.append(v)
    base = {"profile": 2, "archive": bytes(range(32)), "scope": bytes(range(32, 64)), "issuer": issuer,
            "plan": None, "membership": [], "records": [], "objects": []}
    # 1. three contiguous records + mixed objects (correct, corrupt, empty) chosen from disagreeing pairs.
    p = pairs[0]; q = next(x for x in pairs if not ({x[0][0], x[1][0]} & {p[0][0], p[1][0]}))  # run1 bug: pairs[1] shared a key
    m = dict(base); m["records"] = [(1, b"\xa1m1", b"\xa1r1", b"\xa1p1"), (2, bytes(300), b"r" * 70000 if False else b"r2", b"p2"), (3, b"m3", b"r3", b"\x00")]
    m["objects"] = [(p[0][0], p[0][1]), (p[1][0], b"corrupt"), (q[0][0], b""), (q[1][0], q[1][1])]
    add("rv-records3-mixed-objects-disagreeing", m, [p[0], p[1], q[0], q[1]])
    # 2. profile 3, five membership keys spanning disagreeing order, plan, staged objects.
    sel = rnd.sample(keyed, 7)
    m = dict(base); m.update(profile=3, plan=b"\xa1\x64plan\x01" * 10,
                             membership=[(k, len(b)) for k, b in sel[:5]],
                             objects=[(k, b) for k, b in sel[3:7]])
    add("rv-profile3-membership5-objects4", m, [(k, b) for k, b in sel])
    # 3. objects of chunk-boundary sizes (64KiB-1, 64KiB, 64KiB+1), and an empty member framing.
    sizes = [65535, 65536, 65537, 3 * 65536]
    big = [bytes([n % 251]) * s for n, s in enumerate(sizes)]
    m = dict(base); m["objects"] = [(cid_text(cid_raw(b)), b) for b in big]
    add("rv-chunk-boundary-objects", m, [(cid_text(cid_raw(b)), b) for b in big])
    m = dict(base); m["profile"] = 3; m["plan"] = b"p"
    add("rv-profile3-empty-membership", m, [])
    # 4. maximum record field sizes and 4096-byte plan.
    m = dict(base); m.update(profile=3, plan=bytes(4096), records=[(1, bytes(65536), b"\x01" * 65536, b"\x02" * 16384)])
    add("rv-max-record-and-plan", m)
    json.dump({"vectors": vectors, "pairs": [[a[0], a[1].hex(), b[0], b[1].hex()] for a, b in pairs[:3]]},
              open(sys.argv[2], "w"), indent=1)
    lines.append(f"wrote {len(vectors)} reviewer vectors")
    print("\n".join(lines))
    print("RESULT:", "ALL-FIXTURE-MATCH" if ok else "FIXTURE-MISMATCH")
    sys.exit(0 if ok else 1)

main()
