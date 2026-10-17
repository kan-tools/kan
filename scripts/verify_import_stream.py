#!/usr/bin/env python3
"""Independent verification of ordered, decrypted synthetic import frames.

Input is a directory of ordinal-named .bin frames, not an archive or key file.
Verifies reconstruction hashes; does not promote trust or certify backup/cutover.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

CHUNK = 512 * 1024

def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON member')
        value[key] = item
    return value

def decode(raw):
    assert raw[:5] == b'KANI\x01' and len(raw) >= 9
    length, = struct.unpack('>I', raw[5:9])
    assert 0 < length <= 4096 and 9 + length <= len(raw) <= CHUNK + 4096
    header = json.loads(raw[9:9+length], object_pairs_hook=unique)
    assert set(header) == {'version', 'plan', 'ordinal', 'kind', 'file', 'part', 'parts'}
    assert header['version'] == 1
    return header, raw[9+length:]

def main():
    paths = sorted(Path(sys.argv[1]).glob('*.bin'), key=lambda path: int(path.stem))
    frames = [decode(path.read_bytes()) for path in paths]
    assert frames
    plan_id = frames[0][0]['plan']
    assert all(h['ordinal'] == i and h['plan'] == plan_id for i, (h, _) in enumerate(frames))
    count = frames[0][0]['parts']
    assert 0 < count <= 64 and len(frames) > count
    document = bytearray()
    for i in range(count):
        header, data = frames[i]
        assert header['kind'] == 'inventory' and header['file'] is None and header['part'] == i and header['parts'] == count
        assert len(data) == CHUNK if i + 1 < count else 0 < len(data) <= CHUNK
        document.extend(data)
    assert hashlib.sha256(b'tools.kan.import.plan.v1\0' + document).hexdigest() == plan_id
    plan = json.loads(document, object_pairs_hook=unique)
    assert json.dumps(plan, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() == document
    assert plan['profile'] == 1
    inventory = {item['path']: item for item in plan['inventory']['files']}
    assert len(inventory) == len(plan['files'])
    cursor = count
    result = []
    for index, source in enumerate(plan['files']):
        full = hashlib.sha256()
        length = 0
        original = inventory.pop(source['path'])
        assert original['length'] == source['length'] and original['sha256'] == source['sha256']
        assert source['chunks']
        for part, expected in enumerate(source['chunks']):
            header, data = frames[cursor]
            assert header['kind'] == 'data' and header['file'] == index and header['part'] == part and header['parts'] == len(source['chunks'])
            assert len(data) == expected['length'] <= CHUNK
            assert len(data) == CHUNK if part + 1 < len(source['chunks']) else True
            assert hashlib.sha256(data).hexdigest() == expected['sha256']
            full.update(data)
            length += len(data)
            cursor += 1
        assert length == source['length'] and full.hexdigest() == source['sha256']
        result.append({'path': source['path'], 'length': length, 'sha256': full.hexdigest()})
    assert cursor + 1 == len(frames)
    header, data = frames[cursor]
    assert header['kind'] == 'complete' and header['file'] is None and header['part'] == 0 and header['parts'] == 1
    complete = json.loads(data, object_pairs_hook=unique)
    assert complete == {'plan': plan_id, 'observation': 'selected-snapshot-queued', 'recovery_verified': False, 'independent_backup': False, 'ready_for_cutover': False}
    print(json.dumps({'plan': plan_id, 'files': result, 'verified_raw_snapshot': True, 'claim_signatures': 'not-verified', 'ready_for_cutover': False}))

if __name__ == '__main__':
    main()
