#!/usr/bin/env python3
"""Change only a synthetic fixture's valid observer signature, not its statement.

The only key is the public test scalar [10;32]; refuse a different observer.
Used to prove a matching replay checkpoint does not imply byte-identical history.
"""
import sqlite3
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
import recovery_observation_vectors as observation

key, author = observation.crypto.identity(int.from_bytes(bytes([10]) * 32, 'big'))
with sqlite3.connect(Path(sys.argv[1]).resolve()) as db:
    assert db.execute('SELECT observer FROM bundle_identity').fetchone()[0] == author['principal']
    before = db.execute('SELECT envelope FROM observations WHERE sequence=1').fetchone()[0]
    env = observation.codec.decode(before)
    r, s = utils.decode_dss_signature(key.sign(observation.preimage(env['statement']), ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, 'big') + min(s, observation.crypto.ORDER - s).to_bytes(32, 'big')
    after = observation.codec.encode({'statement': observation.codec.blob(env['statement']), 'signature': observation.codec.blob(signature)})
    assert before != after
    statement = observation.codec.decode(env['statement'])
    context = {name: statement[name] for name in observation.CONTEXT}
    observation.verify(after, context)
    db.execute('UPDATE observations SET envelope=? WHERE sequence=1', [after])
