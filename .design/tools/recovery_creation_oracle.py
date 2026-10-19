#!/usr/bin/env python3
"""Inspect synthetic Rust-created bundles with the independent Python state oracle.

This verifies M1, loss partition and observer signatures over the actual output.
It is not an independent general SQLite schema or metadata-admission validator;
those inputs are created/checked separately by the fixture and Rust verifier.
No production keys or live files; the caller supplies a synthetic fixture path.
"""
import json, sqlite3, sys
from pathlib import Path
import recovery_replay_vectors as oracle

path = Path(sys.argv[1]).resolve()
with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
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
    envelopes = [r[0] for r in db.execute('SELECT envelope FROM observations ORDER BY sequence')]
    result = oracle.replay(history, envelopes)
    result['member'] = oracle.frame.member_digest(member).hex()
    result['losses'] = oracle.members.losses(member)[0]
print(json.dumps(result, sort_keys=True))
