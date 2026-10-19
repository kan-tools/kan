#!/usr/bin/env python3
"""Compare synthetic bundle copies and independently replay their actual history.

No kan invocation, production keys, or filesystem durability claim.
"""
import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def cells(path):
    with sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True) as db:
        db.execute('BEGIN')
        return {table: db.execute('SELECT * FROM ' + table + ' ORDER BY 1').fetchall()
                for table in ('bundle_identity', 'member_records', 'member_objects',
                              'member_plan', 'member_membership', 'observations', 'restored_objects')}


source, target = sys.argv[1:]
assert cells(source) == cells(target), 'logical cells differ'
oracle = Path(__file__).with_name('recovery_creation_oracle.py')
results = [json.loads(subprocess.check_output([sys.executable, '-B', str(oracle), p]))
           for p in (source, target)]
assert results[0] == results[1], 'independent history differs'
print(json.dumps(results[1], sort_keys=True))
