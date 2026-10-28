#!/usr/bin/env python3
"""Independent RFC9180 receiver oracle (cryptography==46.0.3).

Uses OpenSSL-backed X25519 and ChaCha20Poly1305, not the Rust HPKE library.
Input JSON on stdin contains synthetic private/scope/frame/plaintext hex.
Always verifies the published vector before checking the supplied frame.
"""
import hashlib
import hmac
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def extract(salt, ikm):
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def expand(prk, info, length):
    out = block = b""
    for i in range(1, (length + 31) // 32 + 1):
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
    return out[:length]


def labeled_extract(suite, salt, label, ikm):
    return extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite, prk, label, info, length):
    return expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def schedule(private, enc, info):
    key = X25519PrivateKey.from_private_bytes(private)
    public = key.public_key().public_bytes_raw()
    dh = key.exchange(X25519PublicKey.from_public_bytes(enc))
    return key_schedule(dh, enc, public, info)


def key_schedule(dh, enc, public, info):
    kem = b"KEM\x00\x20"
    eae = labeled_extract(kem, b"", b"eae_prk", dh)
    shared = labeled_expand(kem, eae, b"shared_secret", enc + public, 32)
    suite = b"HPKE\x00\x20\x00\x01\x00\x03"
    context = (b"\x00" + labeled_extract(suite, b"", b"psk_id_hash", b"")
               + labeled_extract(suite, b"", b"info_hash", info))
    secret = labeled_extract(suite, shared, b"secret", b"")
    return (labeled_expand(suite, secret, b"key", context, 32),
            labeled_expand(suite, secret, b"base_nonce", context, 12))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def vectors():
    v = json.loads((Path(__file__).resolve().parent.parent /
                    "tests/fixtures/hpke/rfc9180-x25519-chacha.json").read_text())
    b = lambda name: bytes.fromhex(v[name])
    key, nonce = schedule(b("skRm"), b("enc"), b("info"))
    require(key == b("key") and nonce == b("base_nonce"), "RFC key schedule mismatch")
    for i, case in enumerate(v["encryptions"]):
        actual_nonce = (int.from_bytes(nonce, "big") ^ i).to_bytes(12, "big")
        pt = ChaCha20Poly1305(key).decrypt(actual_nonce, bytes.fromhex(case["ct"]),
                                         bytes.fromhex(case["aad"]))
        require(pt == bytes.fromhex(case["pt"]), "RFC plaintext mismatch")


def check(value):
    private, scope, frame, expected = (bytes.fromhex(value[n]) for n in
                                       ["private", "scope", "frame", "plaintext"])
    require(len(scope) == 32 and 95 <= len(frame) <= 1048576, "invalid bounds")
    require(frame[:11] == b"KANE\x01\x00\x20\x00\x01\x00\x03", "invalid profile")
    public = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()
    require(hashlib.sha256(public).digest() == frame[11:43], "wrong recipient")
    require(int.from_bytes(frame[75:79], "big") == len(frame) - 79, "invalid length")
    key, nonce = schedule(private, frame[43:75], b"tools.kan.archive.hpke.v1\x00" + scope)
    plaintext = ChaCha20Poly1305(key).decrypt(nonce, frame[79:], frame[:79])
    require(plaintext == expected, "archive plaintext mismatch")


def seal(value):
    public, scope, plaintext = (bytes.fromhex(value[n]) for n in ["recipient", "scope", "plaintext"])
    require(len(public) == 32 and int.from_bytes(public, "little") < 2**255 - 19, "noncanonical recipient")
    require(len(scope) == 32 and len(plaintext) <= 1048576 - 95, "invalid bounds")
    ephemeral = X25519PrivateKey.generate()
    enc = ephemeral.public_key().public_bytes_raw()
    dh = ephemeral.exchange(X25519PublicKey.from_public_bytes(public))
    header = (b"KANE\x01\x00\x20\x00\x01\x00\x03" + hashlib.sha256(public).digest()
              + enc + (len(plaintext) + 16).to_bytes(4, "big"))
    key, nonce = key_schedule(dh, enc, public, b"tools.kan.archive.hpke.v1\x00" + scope)
    return header + ChaCha20Poly1305(key).encrypt(nonce, plaintext, header)


if __name__ == "__main__":
    try:
        vectors()
        value = json.load(sys.stdin)
        if sys.argv[1:] == ["--seal"]:
            print(seal(value).hex())
            sys.exit(0)
        check(value)
    except Exception as error:
        # Never echo input, plaintext or key material.
        print("encryption oracle rejected: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
    print("RFC vectors and archive chunk verified")
