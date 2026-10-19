# Independent lenient CBOR decoder (reviewer-written; does not import the author's codec).
import json, sys
def dec(b, i=0):
    ib = b[i]; mt, ai = ib >> 5, ib & 31; i += 1
    if ai < 24: arg = ai; minimal = True
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24); arg = int.from_bytes(b[i:i+n], 'big'); i += n
        minimal = arg >= (24 if n == 1 else 1 << (8 * (n // 2)))
    else: raise ValueError("indef/reserved")
    hdr = [minimal]
    if mt == 0: return ('u', arg), i, hdr
    if mt == 1: return ('n', -1 - arg), i, hdr
    if mt in (2, 3): v = b[i:i+arg]; return (('b' if mt == 2 else 's'), bytes(v)), i + arg, hdr
    if mt == 4:
        out = []
        for _ in range(arg): v, i, h = dec(b, i); out.append(v); hdr += h
        return ('a', tuple(out)), i, hdr
    if mt == 5:
        keys = []; out = []
        for _ in range(arg):
            k, i, h1 = dec(b, i); v, i, h2 = dec(b, i); hdr += h1 + h2; keys.append(k); out.append((k, v))
        return ('m', tuple(out)), i, hdr
    if mt == 6: v, i, h = dec(b, i); return ('t', arg, v), i, hdr + h
    if mt == 7: return ('x', ai, arg), i, hdr
fx = json.load(open(sys.argv[1]))
pos, _, _ = dec(bytes.fromhex(fx["positive"][0]["hex"]))
posmap = dict(pos[1])
def canon_key(k): enc = k[1]; return (len(enc), enc)
for v in fx["negative"]:
    if v["name"] not in ("reversed-map-keys", "nonminimal-map-length", "nonminimal-recipe", "duplicate-map-key"): continue
    raw = bytes.fromhex(v["hex"]); val, end, hdr = dec(raw)
    keys = [k for k, _ in val[1]]
    order_ok = all(canon_key(a) < canon_key(b) for a, b in zip(keys, keys[1:]))
    dup = len(keys) != len(set(keys))
    same = dict(val[1]) == posmap
    print(f'{v["name"]:22} consumed_all={end==len(raw)} all_headers_minimal={all(hdr)} key_order_canonical={order_ok} duplicate_keys={dup} logical_value_equals_positive0={same} nkeys={len(keys)}')
