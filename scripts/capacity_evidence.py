"""Bounded evidence checks shared by the capacity driver and Modal verifier."""
import hashlib
from pathlib import Path

GIB = 1024 ** 3


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def snapshot(directory):
    """Read every retained byte; reject links instead of following them."""
    files = {}
    for path in sorted(Path(directory).rglob('*')):
        if path.is_symlink():
            raise ValueError('fixture contains a symlink')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('fixture contains a non-regular file')
        files[str(path.relative_to(directory))] = {
            'bytes': path.stat().st_size, 'sha256': digest(path),
        }
    if not files:
        raise ValueError('empty fixture')
    return files


def verify_snapshot(directory, expected):
    actual = snapshot(directory)
    if actual != expected:
        raise ValueError('retained fixture files differ from committed manifest')
    return {'files': len(actual), 'bytes_read': sum(f['bytes'] for f in actual.values())}


def validate_report(report, gib, samples):
    if (report.get('status') != 'complete'
            or report.get('opaque_payload_gib') != gib
            or report.get('samples_per_operation') != samples
            or report.get('chunk_bytes') != 1024 ** 2
            or report.get('fixture_file_bytes', 0) < gib * GIB):
        raise ValueError('incomplete or mismatched capacity report')
    if report.get('version', 1) >= 3:
        baseline = report.get('baseline_records', -1)
        extras = report.get('unmeasured_append_records', -1)
        if (report.get('seeded_records') != gib * 1024
                or not 0 <= extras <= 4096 or baseline != gib * 1024 + extras
                or report.get('expected_records') != baseline + samples):
            raise ValueError('invalid retained seed/append accounting')
    if report.get('version', 1) >= 4:
        if report.get('rss_source') == 'rusage':
            calibration = report.get('rss_calibration', {})
            if calibration.get('status') != 'complete':
                raise ValueError('missing completed peak RSS calibration')
            validate_peak_calibration(calibration)
            source = 'getrusage(RUSAGE_CHILDREN).ru_maxrss:linux-kib:fresh-supervisor'
        elif report.get('rss_source') == 'proc-vmhwm':
            source = 'proc-vmhwm'
        else:
            raise ValueError('unknown RSS accounting source')
        if any(row.get('rss_source') != source for row in report.get('samples', [])):
            raise ValueError('sample RSS source does not match report')
    rows = report.get('samples', [])
    if len(rows) != samples * 4:
        raise ValueError('incomplete operation samples')
    for operation in ('open', 'append', 'page', 'source'):
        if sum(row.get('operation') == operation for row in rows) != samples:
            raise ValueError('incorrect per-operation sample count')
    for row in rows:
        rss = row.get('process_peak_rss_kib')
        if not isinstance(rss, (int, float)) or not 0 < rss <= 512 * 1024:
            raise ValueError('serving process exceeds or lacks the 512 MiB RSS gate')


def inspect_archive(path, expected_records, minimum_object_bytes, *, expected_staged=None, progress=None):
    """Check committed evidence separately from explicitly pinned staged objects.

    Staging is durable before admission. Extras are never discovered and accepted
    implicitly: a diagnostic must supply their exact CID/length allowlist.
    """
    import base64
    import sqlite3
    expected_staged = dict(expected_staged or {})
    if len(expected_staged) > 32 or any(type(n) is not int or not 0 < n <= 4194304 for n in expected_staged.values()):
        raise ValueError('invalid staged-object allowance')
    progress = progress or (lambda phase, value: None)
    path = Path(path)
    wal = Path(str(path) + '-wal')
    if wal.exists() and wal.stat().st_size:
        raise ValueError('archive still has an uncheckpointed WAL')
    with sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True) as db:
        commits = db.execute('SELECT count(*) FROM commits').fetchone()[0]
        objects = db.execute('SELECT count(*) FROM objects').fetchone()[0]
        progress('counts', {'commits': commits, 'objects': objects})
        if commits != expected_records or objects != expected_records + len(expected_staged):
            raise ValueError(f'retained archive mismatch: commits={commits}, objects={objects}, '
                             f'expected_records={expected_records}, expected_staged={len(expected_staged)}')
        bindings, bound_commits = {}, set()
        for cid, length, present in db.execute('SELECT b.ciphertext,b.length,c.cid FROM bindings b LEFT JOIN commits c ON c.cid=b.first_manifest'):
            if present is None or present in bound_commits or cid in bindings or type(length) is not int or not 0 < length <= 4194304:
                raise ValueError('missing commit, duplicate object binding or invalid binding length')
            bindings[cid] = length
            bound_commits.add(present)
            if len(bindings) > expected_records:
                raise ValueError('extra committed object bindings')
        if len(bindings) != expected_records or set(bindings) & set(expected_staged):
            raise ValueError('missing bindings or staged allowance overlaps committed evidence')
        progress('bindings', {'count': len(bindings)})
        byte_count, referenced_bytes, staged, seen = 0, 0, {}, set()
        # Rowid order avoids CID-order random seeks. Read only record headers for
        # bound payload lengths; full file bytes are independently hash-checked.
        for cid, length, kind in db.execute('SELECT cid,length(bytes),typeof(bytes) FROM objects NOT INDEXED'):
            if kind != 'blob' or not 0 < length <= 4194304:
                raise ValueError('invalid stored object')
            if cid in bindings:
                if length != bindings[cid]:
                    raise ValueError('committed object length mismatch')
                referenced_bytes += length
            elif expected_staged.get(cid) == length:
                payload = db.execute('SELECT bytes FROM objects WHERE cid=?', (cid,)).fetchone()[0]
                actual = 'b' + base64.b32encode(b'\x01\x55\x12\x20' + hashlib.sha256(payload).digest()).decode().lower().rstrip('=')
                if actual != cid:
                    raise ValueError('staged object CID does not match retained bytes')
                staged[cid] = length
            else:
                raise ValueError('unexpected unreferenced object')
            seen.add(cid)
            byte_count += length
            if len(seen) % 1024 == 0:
                progress('object_lengths', {'checked': len(seen), 'referenced_bytes': referenced_bytes})
        if seen != set(bindings) | set(expected_staged) or staged != expected_staged:
            raise ValueError('missing retained objects')
        if referenced_bytes < minimum_object_bytes:
            raise ValueError(f'referenced object bytes={referenced_bytes}, minimum_object_bytes={minimum_object_bytes}')
        progress('sqlite_quick_check', {'objects': len(seen)})
        if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise ValueError('retained SQLite archive failed quick_check')
    return {'commits': commits, 'objects': objects, 'object_bytes': byte_count,
            'referenced_objects': len(bindings), 'referenced_object_bytes': referenced_bytes,
            'staged_objects': staged, 'sqlite_quick_check': 'ok'}


def atomic_json(path, value):
    import json
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.pending')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def prepare_attempt(directory, revision, gib, samples, resume, adopt_seed_prefix=False):
    """Never silently reuse metrics from an interrupted timing attempt."""
    import json
    import uuid
    directory = Path(directory)
    report_path = directory / 'report.json'
    old = json.loads(report_path.read_text()) if report_path.exists() else None
    if old:
        if not resume or old.get('opaque_payload_gib') != gib or old.get('samples_per_operation') != samples:
            raise ValueError('resume parameters differ from retained measurement')
        if old.get('source_revision') != revision:
            if not adopt_seed_prefix or old.get('samples') or old.get('status') == 'complete':
                raise ValueError('source revision differs; only explicit unsampled seed adoption is permitted')
        if old.get('status') == 'complete':
            validate_report(old, gib, samples)
            return None
    elif (directory / 'archive').exists():
        raise ValueError('archive exists without a retained measurement identity')
    attempt = directory / 'attempts' / uuid.uuid4().hex
    attempt.mkdir(parents=True)
    if old:
        atomic_json(attempt / 'prior-report.json', old)
    return attempt


def retain_logs(source, destination):
    """Copy small root/attempt evidence, never walk or copy the archive."""
    import shutil
    source, destination = Path(source), Path(destination)
    if not source.exists():
        return
    paths = list(source.iterdir())
    attempts = source / 'attempts'
    if attempts.exists():
        paths.extend(attempts.rglob('*'))
    for path in paths:
        if path.is_symlink():
            raise ValueError('evidence contains a symlink')
        if not path.is_file() or path.suffix not in ('.json', '.jsonl', '.log'):
            continue
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + '.pending')
        shutil.copyfile(path, temporary)
        temporary.replace(target)


def seed_frontier(lines):
    """Read one worker frontier, including libtest's same-line test prefix."""
    import re
    marker = 'KAN_CAPACITY_FRONTIER='
    values = [line.split(marker, 1)[1].strip() for line in lines if marker in line]
    if len(values) != 1 or not re.fullmatch(r'[0-9]+', values[0]):
        raise ValueError('missing, ambiguous or malformed authenticated seed frontier')
    return int(values[0])


def attach_peak(sample, usage):
    source = 'getrusage(RUSAGE_CHILDREN).ru_maxrss:linux-kib:fresh-supervisor'
    peak = usage.get('process_peak_rss_kib')
    if (sample.get('rss_source') != 'pending-external-rusage'
            or sample.get('process_peak_rss_kib') is not None
            or usage.get('source') != source or usage.get('status') != 'complete'
            or usage.get('returncode') != 0 or usage.get('calibration') is not False
            or not isinstance(peak, int) or not 0 < peak <= 512 * 1024):
        raise ValueError('invalid external peak RSS evidence')
    sample.update(process_peak_rss_kib=peak, rss_source=source)


def validate_peak_calibration(report):
    c = report.get('allocation_probe', {})
    keys = ('before_rss_kib', 'during_rss_kib', 'after_rss_kib', 'during_peak_kib', 'after_peak_kib')
    if (report.get('source') != 'getrusage(RUSAGE_CHILDREN).ru_maxrss:linux-kib:fresh-supervisor'
            or report.get('returncode') != 0 or report.get('calibration') is not True
            or any(type(c.get(k)) is not int or c[k] <= 0 for k in keys)
            or type(report.get('process_peak_rss_kib')) is not int):
        raise ValueError('missing kernel peak calibration evidence')
    if (c['during_rss_kib'] - c['before_rss_kib'] < 48 * 1024
            or c['during_rss_kib'] - c['after_rss_kib'] < 48 * 1024
            or c['during_peak_kib'] - c['before_rss_kib'] < 48 * 1024
            or c['after_peak_kib'] < c['during_peak_kib']
            or not c['after_peak_kib'] <= report['process_peak_rss_kib'] <= 512 * 1024):
        raise ValueError('kernel peak accounting failed allocate/free calibration')
