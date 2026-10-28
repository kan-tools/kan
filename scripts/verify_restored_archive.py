#!/usr/bin/env python3
"""Synthetic-test oracle: independent archive -> selected bytes.

Reads raw `objects` rows of a standalone archive (immutable, read-only), verifies
ECDSA P-256 signatures over exact retained request bytes, opens RFC9180
X25519/HKDF-SHA256/ChaCha20Poly1305 frames with OpenSSL-backed `cryptography`,
reassembles KANI v1 frames for an externally pinned plan, and compares every
selected byte with a restored directory. Shares no code with kan.
Does NOT check commits/receipts (separate Rust regressions do); bytes only.
Test fixtures only: unbounded allocations and path reads are intentional here.
Never use this script as a production archive reader or with untrusted inputs.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

CHUNK = 512 * 1024
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def need(ok, why):
    if not ok:
        raise ValueError(why)


def b58(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw


def p256_key(did):
    need(did.startswith("did:key:z"), "did:key")
    raw = b58(did[len("did:key:z"):])
    need(raw[:2] == b"\x80\x24" and len(raw) == 35, "p256 multicodec")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw[2:])


def verify(pub, sig, msg):
    need(len(sig) == 64, "sig length")
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    pub.verify(der, msg, ec.ECDSA(hashes.SHA256()))


def ext(salt, ikm):
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def exp(prk, info, n):
    out = blk = b""
    i = 1
    while len(out) < n:
        blk = hmac.new(prk, blk + info + bytes([i]), hashlib.sha256).digest()
        out += blk
        i += 1
    return out[:n]


def open_frame(private, scope, frame):
    need(frame[:11] == b"KANE\x01\x00\x20\x00\x01\x00\x03", "profile")
    sk = X25519PrivateKey.from_private_bytes(private)
    pk = sk.public_key().public_bytes_raw()
    need(hashlib.sha256(pk).digest() == frame[11:43], "recipient")
    enc = frame[43:75]
    need(int.from_bytes(frame[75:79], "big") == len(frame) - 79, "length")
    dh = sk.exchange(X25519PublicKey.from_public_bytes(enc))
    kem = b"KEM\x00\x20"
    lext = lambda suite, salt, label, ikm: ext(salt, b"HPKE-v1" + suite + label + ikm)
    lexp = lambda suite, prk, label, info, n: exp(prk, n.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, n)
    shared = lexp(kem, lext(kem, b"", b"eae_prk", dh), b"shared_secret", enc + pk, 32)
    suite = b"HPKE\x00\x20\x00\x01\x00\x03"
    info = b"tools.kan.archive.hpke.v1\x00" + scope
    ctx = b"\x00" + lext(suite, b"", b"psk_id_hash", b"") + lext(suite, b"", b"info_hash", info)
    secret = lext(suite, shared, b"secret", b"")
    key = lexp(suite, secret, b"key", ctx, 32)
    nonce = lexp(suite, secret, b"base_nonce", ctx, 12)
    return ChaCha20Poly1305(key).decrypt(nonce, frame[79:], frame[:79])


def strict(pairs):
    d = {}
    for k, v in pairs:
        need(k not in d, "dup key")
        d[k] = v
    return d


def main(db, plan_id, scope_hex, writer, key_path, restored):
    private = open(key_path, "rb").read()
    need(len(private) == 32, "key")
    scope = bytes.fromhex(scope_hex)
    pub = p256_key(writer)
    con = sqlite3.connect(f"file:{db}?mode=ro&immutable=1", uri=True)
    by_id = {}
    for (raw,) in con.execute("SELECT bytes FROM objects"):
        raw = bytes(raw)
        prefix = b'{"request":'
        if not raw.startswith(prefix):
            continue
        cut = raw.rfind(b',"signature":"')
        request_bytes = raw[len(prefix):cut]
        tail = raw[cut + len(b',"signature":"'):]
        need(tail.endswith(b'"}') and len(tail) == 130, "signature tail")
        req = json.loads(request_bytes, object_pairs_hook=strict)
        if req["scope"] != scope_hex or req["principal"] != writer:
            continue
        cmd = req["command"]
        if cmd.get("operation") != "append":
            continue
        pre = b"tools.kan.service.request.v1\x00" + hashlib.sha256(request_bytes).digest()
        verify(pub, bytes.fromhex(tail[:-2].decode()), pre)  # raises on forgery
        need(cmd["id"] not in by_id, "duplicate operation id in objects")
        by_id[cmd["id"]] = bytes.fromhex(cmd["ciphertext"])

    def frame(i):
        h = hashlib.sha256(b"tools.kan.import.operation.v1\x00" + plan_id.encode() + struct.pack(">Q", i)).digest()[:16].hex()
        plain = open_frame(private, scope, by_id[h])
        need(plain[:5] == b"KANI\x01", "KANI")
        (n,) = struct.unpack(">I", plain[5:9])
        hdr = json.loads(plain[9:9 + n], object_pairs_hook=strict)
        need(hdr["plan"] == plan_id and hdr["ordinal"] == i and hdr["version"] == 1, "frame identity")
        return hdr, plain[9 + n:]

    h0, _ = frame(0)
    parts = h0["parts"]
    doc = b""
    for i in range(parts):
        h, d = frame(i)
        need((h["kind"], h["file"], h["part"], h["parts"]) == ("inventory", None, i, parts), "inv coords")
        doc += d
    need(hashlib.sha256(b"tools.kan.import.plan.v1\x00" + doc).hexdigest() == plan_id, "plan hash")
    plan = json.loads(doc, object_pairs_hook=strict)
    need(open(os.path.join(restored, "plan.json"), "rb").read() == doc, "plan.json differs")
    ordinal = parts
    seen = []
    for fi, f in enumerate(plan["files"]):
        whole = b""
        for j, c in enumerate(f["chunks"]):
            h, d = frame(ordinal)
            need((h["kind"], h["file"], h["part"], h["parts"]) == ("data", fi, j, len(f["chunks"])), "data coords")
            need(len(d) == c["length"] and hashlib.sha256(d).hexdigest() == c["sha256"], "chunk")
            whole += d
            ordinal += 1
        need(hashlib.sha256(whole).hexdigest() == f["sha256"] and len(whole) == f["length"], "file")
        got = open(os.path.join(restored, "files", *f["path"].split("/")), "rb").read()
        need(got == whole, "restored bytes differ: " + f["path"])
        seen.append(f["path"])
    h, d = frame(ordinal)
    need(h["kind"] == "complete", "complete")
    on_disk = []
    for base, dirs, files in os.walk(os.path.join(restored, "files")):
        for name in files:
            on_disk.append(os.path.relpath(os.path.join(base, name), os.path.join(restored, "files")))
    need(sorted(on_disk) == sorted(seen), "extra or missing restored files")
    report = json.load(open(os.path.join(restored, "report.json")))
    need([x["path"] for x in report["files"]] == seen, "report file list")
    print(json.dumps({"oracle": "ok", "files": len(seen), "operations": ordinal + 1,
                      "bytes": sum(f["length"] for f in plan["files"])}))


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except Exception as e:  # never echo key material
        print("oracle rejected: " + type(e).__name__ + ": " + str(e)[:120], file=sys.stderr)
        sys.exit(1)
