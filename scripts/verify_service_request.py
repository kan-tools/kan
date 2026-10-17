#!/usr/bin/env python3
"""Independent Python JSON/hash + OpenSSL P-256 oracle for synthetic service fixtures."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

MAXIMUM = 2 * 1024 * 1024 + 4096

def fail(message):
    raise ValueError(message)

def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            fail("duplicate key")
        result[key] = value
    return result

def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()

def base58(value):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for character in value:
        number = number * 58 + alphabet.index(character)
    return b"\0" * (len(value) - len(value.lstrip("1"))) + number.to_bytes((number.bit_length()+7)//8, "big")

def integer(raw):
    raw = raw.lstrip(b"\0") or b"\0"
    if raw[0] & 128:
        raw = b"\0" + raw
    return bytes([2, len(raw)]) + raw

def verify(path):
    with open(path, "rb") as source:
        raw = source.read(MAXIMUM + 1)
    if len(raw) > MAXIMUM:
        fail("oversized input")
    envelope = json.loads(raw, object_pairs_hook=pairs)
    if list(envelope) != ["request", "signature"] or compact(envelope) != raw:
        fail("noncanonical envelope")
    request = envelope["request"]
    if list(request) != ["version", "scope", "principal", "expires", "command"] or type(request["version"]) is not int or request["version"] != 1:
        fail("request fields")
    principal = request["principal"]
    if not principal.startswith("did:key:z"):
        fail("not base58 did:key")
    public = base58(principal[len("did:key:z"):])
    if len(public) != 35 or public[:2] != b"\x80\x24":
        fail("oracle requires P-256 public key")
    signature = bytes.fromhex(envelope["signature"])
    if len(signature) != 64 or signature.hex() != envelope["signature"]:
        fail("signature format")
    message = b"tools.kan.service.request.v1\0" + hashlib.sha256(compact(request)).digest()
    # Expand SEC1 compression for Apple's LibreSSL verifier, which rejects
    # compressed points through its platform EC backend. Verification itself
    # remains OpenSSL/LibreSSL, independent of Rust's crypto implementation.
    prime = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    curve_b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    x = int.from_bytes(public[3:], "big")
    squared = (pow(x, 3, prime) - 3*x + curve_b) % prime
    y = pow(squared, (prime+1)//4, prime)
    if x >= prime or y*y % prime != squared or public[2] not in (2, 3):
        fail("invalid compressed P-256 key")
    if y % 2 != public[2] % 2:
        y = prime-y
    # RFC 5480 SPKI with id-ecPublicKey and prime256v1.
    spki = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + public[3:] + y.to_bytes(32, "big")
    integers = integer(signature[:32]) + integer(signature[32:])
    der = bytes([0x30, len(integers)]) + integers
    with tempfile.TemporaryDirectory(prefix="kan-service-oracle-") as directory:
        root = Path(directory)
        (root / "public.der").write_bytes(spki)
        (root / "signature.der").write_bytes(der)
        (root / "message").write_bytes(message)
        result = subprocess.run(["openssl", "dgst", "-sha256", "-keyform", "DER", "-verify", str(root / "public.der"), "-signature", str(root / "signature.der"), str(root / "message")], capture_output=True)
        if result.returncode != 0:
            fail("OpenSSL signature verification failed: " + result.stderr.decode(errors="replace"))
    return {"signature": "verified", "request_sha256": hashlib.sha256(raw).hexdigest()}

if __name__ == "__main__":
    try:
        print(json.dumps(verify(sys.argv[1]), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError, IndexError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
