#!/usr/bin/env python3
"""Independent full-set reference for the v1 serving-index codec.

Rust updates a single path; this oracle sorts the complete map and rebuilds each
canonical split from its first/last key. No runtime service or filesystem index
is exercised by these vectors.
"""
import argparse
import hashlib
import json
from pathlib import Path

NODE_DOMAIN = b"tools.kan.serving-index.node.v1\0"
KEY_DOMAIN = b"tools.kan.serving-index.key.v1\0"
DESTINATION = Path(__file__).resolve().parents[1] / "tests/fixtures/serving-index-v1.json"


def key(namespace, opaque):
    return hashlib.sha256(KEY_DOMAIN + len(namespace).to_bytes(2, "big") + namespace
                          + len(opaque).to_bytes(4, "big") + opaque).hexdigest()


def build(entries):
    if not entries:
        return None, {}
    blocks = {}

    def emit(body):
        digest = hashlib.sha256(NODE_DOMAIN + body).hexdigest()
        blocks[digest] = body.hex()
        return bytes.fromhex(digest)

    def tree(rows):
        if len(rows) == 1:
            k, value = rows[0]
            return emit(b"\0" + k.to_bytes(32, "big") + len(value).to_bytes(4, "big") + value)
        xor = rows[0][0] ^ rows[-1][0]
        at = 256 - xor.bit_length()
        shift = 255 - at
        split = next(i for i, (k, _) in enumerate(rows) if (k >> shift) & 1)
        prefix = (rows[0][0] >> (256-at)) << (256-at) if at else 0
        left, right = tree(rows[:split]), tree(rows[split:])
        return emit(b"\1" + at.to_bytes(2, "big") + prefix.to_bytes(32, "big") + left + right)

    root = tree(sorted((int(k, 16), bytes.fromhex(v)) for k, v in entries.items()))
    return root.hex(), blocks


def vectors():
    zero, high, tail = "00" * 32, "80" + "00" * 31, "00" * 31 + "01"
    derived = key(b"sequence", (7).to_bytes(8, "big"))
    operations = [(zero, ""), (tail, "ff"), (high, "010203"), (derived, "616263"),
                  (tail, "626967676572"), (zero, "00")]
    entries, steps = {}, []
    for k, value in operations:
        entries[k] = value
        root, blocks = build(entries)
        steps.append({"key": k, "value": value, "root": root,
                      "entries": dict(sorted(entries.items())), "blocks": blocks})
    return {"format": "kan-serving-index-v1-vectors", "empty_root": None,
            "derived_key": {"namespace": "73657175656e6365", "opaque": "0000000000000007", "key": derived},
            "steps": steps}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = json.dumps(vectors(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if DESTINATION.read_text() != expected:
            raise SystemExit("serving-index reference vectors differ")
        print("serving-index reference vectors match (full-set canonical reconstruction)")
    else:
        DESTINATION.write_text(expected)


if __name__ == "__main__":
    main()
