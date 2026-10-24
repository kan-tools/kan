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


def inspect_archive(path, expected_records, minimum_object_bytes):
    """Verify the closed SQLite archive's retained rows on the fresh mount."""
    import sqlite3
    path = Path(path)
    wal = Path(str(path) + '-wal')
    if wal.exists() and wal.stat().st_size:
        raise ValueError('archive still has an uncheckpointed WAL')
    with sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True) as db:
        commits = db.execute('SELECT count(*) FROM commits').fetchone()[0]
        objects, byte_count = db.execute('SELECT count(*), coalesce(sum(length(bytes)),0) FROM objects').fetchone()
        if commits != expected_records or objects != expected_records or byte_count < minimum_object_bytes:
            raise ValueError('retained archive record count or object bytes mismatch')
        if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise ValueError('retained SQLite archive failed quick_check')
    return {'commits': commits, 'objects': objects, 'object_bytes': byte_count,
            'sqlite_quick_check': 'ok'}
