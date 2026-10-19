#!/usr/bin/env python3
"""Independent framing/signature check of synthetic physical publication.

Reads the actual bundle and output via SQLite, authenticates the entire retained
history using the independent Python implementation, and compares the output's
O1 with its named intent. Not a power-loss or filesystem-custody oracle.
"""
import json
import sqlite3
import sys
from pathlib import Path
import recovery_replay_vectors as oracle


def connect(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)


with connect(sys.argv[1]) as db:
    bundle, observer, profile, archive, scope, issuer = db.execute(
        'SELECT bundle,observer,profile,archive,scope,issuer FROM bundle_identity').fetchone()
    plan = db.execute('SELECT envelope FROM member_plan').fetchone()
    member = dict(profile=profile, archive=archive, scope=scope, issuer=issuer,
                  plan=plan[0] if plan else None,
                  membership=[list(r) for r in db.execute('SELECT cid,length FROM member_membership ORDER BY cid')],
                  records=[list(r) for r in db.execute('SELECT sequence,manifest,receipt,envelope FROM member_records ORDER BY sequence')],
                  objects=[list(r) for r in db.execute('SELECT cid,bytes FROM member_objects ORDER BY cid')])
    history = oracle.History(member, observer)
    history.context['bundle'] = bundle
    history.candidates = [list(r) for r in db.execute('SELECT cid,bytes FROM restored_objects ORDER BY cid')]
    result = oracle.replay(history, [r[0] for r in db.execute('SELECT envelope FROM observations ORDER BY sequence')])

with connect(sys.argv[2]) as db:
    assert db.execute('PRAGMA application_id').fetchone()[0] == 1263940097
    assert db.execute('PRAGMA user_version').fetchone()[0] == profile
    assert db.execute('SELECT archive,scope,issuer FROM archive_identity').fetchall() == [(archive, scope, issuer)]
    actual_plan = db.execute('SELECT envelope FROM upgrade_plan').fetchone()[0] if profile == 3 else None
    actual_membership = [list(r) for r in db.execute('SELECT cid,length FROM upgrade_objects ORDER BY cid')] if profile == 3 else []
    output = dict(profile=profile, archive=archive, scope=scope, issuer=issuer,
                  plan=actual_plan, membership=actual_membership,
                  records=[list(r) for r in db.execute('SELECT c.sequence,c.manifest,c.receipt,a.envelope FROM commits c JOIN attestations a USING(sequence) ORDER BY c.sequence')],
                  objects=[list(r) for r in db.execute('SELECT cid,bytes FROM objects ORDER BY cid')])
    assert output['records'] == member['records']
    assert output['membership'] == member['membership']
    assert output['plan'] == member['plan']
    assert db.execute('SELECT count(*) FROM attestations').fetchone()[0] == len(output['records'])
    digest = oracle.frame.member_digest(output, True).hex()
    attempt = next(a for a in result['attempts'] if a['id'] == sys.argv[3])
    assert attempt['output'] == digest
    assert attempt['observedAt'] is not None
print(json.dumps({'O1': digest, 'attempt': attempt, 'latestSequence': result['latestSequence']}, sort_keys=True))
