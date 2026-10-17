#!/usr/bin/env python3
"""Independent verification of ordered, decrypted synthetic import frames.

Input is a directory of ordinal-named .bin frames, not an archive or key file.
Requires an operator-pinned plan, which commits source lineage, route and recipient.
Verifies selected file bytes and preserves coverage notices; does not authenticate
archive transport, promote semantic trust, or certify backup/cutover.
"""
import argparse
import hashlib
import re
import json
from pathlib import Path
import struct
import sys

CHUNK = 512 * 1024

def require(condition):
    if not condition:
        raise ValueError('import stream verification failed')


def hex32(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON member')
        value[key] = item
    return value

def decode(raw):
    require(raw[:5] == b'KANI\x01' and len(raw) >= 9)
    length, = struct.unpack('>I', raw[5:9])
    require(0 < length <= 4096 and 9 + length <= len(raw) <= CHUNK + 4096)
    header = json.loads(raw[9:9+length], object_pairs_hook=unique)
    require(set(header) == {'version', 'plan', 'ordinal', 'kind', 'file', 'part', 'parts'})
    require(type(header['version']) is int and header['version'] == 1)
    require(all(type(header[key]) is int and header[key] >= 0 for key in ['ordinal', 'part', 'parts']))
    require(header['file'] is None or (type(header['file']) is int and header['file'] >= 0))
    require(hex32(header['plan']))
    return header, raw[9+length:]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('frames')
    parser.add_argument('--expected-plan', required=True, help='operator-pinned plan commitment, not a value read from the stream')
    args = parser.parse_args()
    require(hex32(args.expected_plan))
    paths = sorted(Path(args.frames).glob('*.bin'), key=lambda path: int(path.stem))
    frames = [decode(path.read_bytes()) for path in paths]
    require(frames)
    plan_id = frames[0][0]['plan']
    require(plan_id == args.expected_plan)
    require(all(h['ordinal'] == i and h['plan'] == plan_id for i, (h, _) in enumerate(frames)))
    count = frames[0][0]['parts']
    require(0 < count <= 64 and len(frames) > count)
    document = bytearray()
    for i in range(count):
        header, data = frames[i]
        require(header['kind'] == 'inventory' and header['file'] is None and header['part'] == i and header['parts'] == count)
        require(len(data) == CHUNK if i + 1 < count else 0 < len(data) <= CHUNK)
        document.extend(data)
    require(hashlib.sha256(b'tools.kan.import.plan.v1\0' + document).hexdigest() == args.expected_plan)
    plan = json.loads(document, object_pairs_hook=unique)
    require(json.dumps(plan, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode() == document)
    require(type(plan['profile']) is int and plan['profile'] == 1)
    require(hex32(plan['source_id']) and hex32(plan['recipient']))
    require(set(plan['route']) == {'scope', 'writer', 'audience'})
    require(hex32(plan['route']['scope']))
    require(all(isinstance(plan['route'][key], str) for key in ['writer', 'audience']))
    require(type(plan['inventory']['selected_inventory_complete']) is bool)
    require(isinstance(plan['inventory']['notices'], list))
    inventory = {item['path']: item for item in plan['inventory']['files']}
    require(len(inventory) == len(plan['files']))
    cursor = count
    result = []
    for index, source in enumerate(plan['files']):
        full = hashlib.sha256()
        length = 0
        original = inventory.pop(source['path'])
        require(original['length'] == source['length'] and original['sha256'] == source['sha256'])
        require(source['chunks'])
        for part, expected in enumerate(source['chunks']):
            header, data = frames[cursor]
            require(header['kind'] == 'data' and header['file'] == index and header['part'] == part and header['parts'] == len(source['chunks']))
            require(len(data) == expected['length'] <= CHUNK)
            require(len(data) == CHUNK if part + 1 < len(source['chunks']) else True)
            require(hashlib.sha256(data).hexdigest() == expected['sha256'])
            full.update(data)
            length += len(data)
            cursor += 1
        require(length == source['length'] and full.hexdigest() == source['sha256'])
        result.append({'path': source['path'], 'length': length, 'sha256': full.hexdigest()})
    require(cursor + 1 == len(frames))
    header, data = frames[cursor]
    require(header['kind'] == 'complete' and header['file'] is None and header['part'] == 0 and header['parts'] == 1)
    complete = json.loads(data, object_pairs_hook=unique)
    require(complete == {'plan': plan_id, 'observation': 'selected-snapshot-queued', 'recovery_verified': False, 'independent_backup': False, 'ready_for_cutover': False})
    print(json.dumps({'plan': plan_id, 'source_id': plan['source_id'], 'recipient': plan['recipient'],
                      'route': plan['route'], 'files': result, 'verified_selected_file_bytes': True,
                      'selected_inventory_complete': plan['inventory']['selected_inventory_complete'],
                      'notices': plan['inventory']['notices'], 'transport_authentication': 'not-verified',
                      'claim_signatures': 'not-verified', 'ready_for_cutover': False}))

if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, IndexError, OSError, struct.error):
        print('invalid import stream or expected plan', file=sys.stderr)
        sys.exit(1)
