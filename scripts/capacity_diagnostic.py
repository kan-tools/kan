"""Read-only, checkpointed archive accounting; does not scan payload BLOBs.

Binding lengths are declared lengths, not independently verified object bytes.
This diagnostic explains a mismatch; it never grants capacity qualification.
"""
import json
from pathlib import Path
import sqlite3
import time


def inspect(path, save, expected_records, max_records=200000):
    path = Path(path)
    state = {'status': 'running', 'expected_records': expected_records,
             'archive_file_bytes': path.stat().st_size, 'steps': {}}

    def record(name, value):
        state['steps'][name] = value
        state['last_completed_step'] = name
        save(state)

    def keys(db, table):
        # Explicit covering unique CID index: do not traverse the BLOB table.
        index = None
        for row in db.execute(f'PRAGMA index_list({table})'):
            if row[2] and not row[4]:
                quoted = '"' + row[1].replace('"', '""') + '"'
                columns = [r[2] for r in db.execute(f'PRAGMA index_info({quoted})')]
                if columns == ['cid']:
                    index = quoted
                    break
        if index is None:
            raise ValueError(f'{table}: no covering unique CID index')
        query = f'SELECT cid FROM {table} INDEXED BY {index}'
        record(table + '_query_plan', list(db.execute('EXPLAIN QUERY PLAN ' + query)))
        values = set()
        for (cid,) in db.execute(query):
            values.add(cid)
            if len(values) > max_records:
                raise ValueError('diagnostic record bound exceeded')
        record(table + '_count', len(values))
        return values

    save(state)
    try:
        wal = Path(str(path) + '-wal')
        if wal.exists() and wal.stat().st_size:
            raise ValueError('uncheckpointed WAL; refusing immutable read')
        with sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True) as db:
            deadline = time.monotonic() + 1800
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            record('schema', list(db.execute("SELECT name,sql FROM sqlite_schema WHERE type='table'")))
            commits = keys(db, 'commits')
            objects = keys(db, 'objects')
            refs, total, count, missing_commits = set(), 0, 0, set()
            for object_id, size, commit_id in db.execute('SELECT ciphertext,length,first_manifest FROM bindings'):
                refs.add(object_id)
                total += size
                count += 1
                if commit_id not in commits:
                    missing_commits.add(commit_id)
                if count > max_records:
                    raise ValueError('diagnostic binding bound exceeded')
                if count % 4096 == 0:
                    record('binding_progress', count)
            missing = sorted(refs - objects)
            unreferenced = sorted(objects - refs)
            record('bindings', {'count': count, 'distinct_objects': len(refs),
                   'declared_bytes': total, 'missing_object_count': len(missing),
                   'missing_objects': missing[:32], 'missing_commit_count': len(missing_commits),
                   'missing_commits': sorted(missing_commits)[:32],
                   'unreferenced_object_count': len(unreferenced),
                   'unreferenced_objects': unreferenced[:32]})
            # Read metadata for at most 32 unreferenced rows, never all BLOBs.
            for cid in unreferenced[:32]:
                size, kind = db.execute('SELECT length(bytes),typeof(bytes) FROM objects WHERE cid=?', (cid,)).fetchone()
                record('unreferenced_' + cid, {'bytes': size, 'storage_type': kind})
        state['status'] = 'complete'
    except BaseException as error:
        state.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        save(state)
    return state


def save_json(path, state):
    path = Path(path)
    temporary = path.with_suffix('.pending')
    temporary.write_text(json.dumps(state, indent=2) + '\n')
    temporary.replace(path)
