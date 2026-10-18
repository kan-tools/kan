#!/usr/bin/env python3
"""Independent synthetic gateway-spool witness. Not a production archive reader.
Reads SQLite/JSON and HPKE directly, without kan's decoder. The fixture supplies
writer/scope/body expectations. This does not independently verify the outer
signature or certify archive admission. Unknown events retain their raw frame.
"""
import hashlib
import importlib.util
import json
import pathlib
import sqlite3
import sys


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def parse_frame(raw):
    require(raw[:5] == b'KANC2' and len(raw) >= 9, 'magic')
    n = int.from_bytes(raw[5:9], 'big')
    require(0 < n <= 131072 and 9+n <= len(raw), 'header bound')
    h = json.loads(raw[9:9+n]); body = raw[9+n:]
    require(len(body) <= 65536, 'body bound')
    known = {'started', 'transport-link', 'request-chunk', 'request-end',
             'forwarding-intent', 'response-head', 'response-chunk', 'terminal',
             'http-metadata', 'http-metadata-chunk'}
    # Preserve unfamiliar semantics, including their exact bytes; never coerce
    # an unknown event to an absent event or infer its effect on lifecycle.
    unknown = raw.hex() if h['event']['type'] not in known else None
    return h, body, unknown


def verify(oracle_path, spool, expected_path, writer, observer):
    spec = importlib.util.spec_from_file_location('oracle', oracle_path)
    oracle = importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)
    oracle.vectors()
    expected = json.loads(pathlib.Path(expected_path).read_text())
    private = bytes.fromhex(expected['private']); scope = bytes.fromhex(expected['scope'])
    pub = oracle.X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()
    groups = {}
    require(pathlib.Path(spool).is_file(), 'spool missing: '+str(spool))
    # Synthetic fixtures may need WAL recovery/bookkeeping when opened by a
    # different SQLite build. SQL writes are disabled immediately; no live store
    # is accepted by this test utility's calling convention.
    with sqlite3.connect(pathlib.Path(spool).as_uri()+'?mode=rw', uri=True) as db:
        db.execute('PRAGMA query_only=ON')
        for (request,) in db.execute('SELECT request FROM pending ORDER BY position'):
            outer = json.loads(request)['request']; command = outer['command']
            require(outer['scope'] == scope.hex() and outer['principal'] == writer, 'outer pins')
            require(command['operation'] == 'append', 'append')
            ct = bytes.fromhex(command['ciphertext'])
            require(ct[:11] == b'KANE\x01\x00\x20\x00\x01\x00\x03', 'HPKE profile')
            require(ct[11:43] == hashlib.sha256(pub).digest(), 'recipient')
            require(int.from_bytes(ct[75:79], 'big') == len(ct)-79, 'ciphertext length')
            key, nonce = oracle.schedule(private, ct[43:75], b'tools.kan.archive.hpke.v1\0'+scope)
            raw = oracle.ChaCha20Poly1305(key).decrypt(nonce, ct[79:], ct[:79])
            h, body, unknown = parse_frame(raw)
            require(h['version'] == 2 and h['observer'] == observer and h['unconfirmed_before'] == 0, 'header pins')
            frames = groups.setdefault(h['attempt'], [])
            require(h['ordinal'] == len(frames), 'ordinal')
            require(type(h['observed_at_unix_micros']) is int and h['observed_at_unix_micros'] > 0, 'time')
            require(type(h['elapsed_micros']) is int and h['elapsed_micros'] >= 0, 'elapsed')
            op = hashlib.sha256(b'tools.kan.capture.operation.v1\0'+bytes.fromhex(h['attempt'])
                 +bytes([0 if observer == 'collector' else 1])+len(frames).to_bytes(8,'big')).hexdigest()[:32]
            require(command['id'] == op, 'operation')
            frames.append((h['event'], body, unknown))
    require(bool(groups), 'empty spool')
    actual = []; links = []; unknowns = []
    for frames in groups.values():
        phase = 'start'; bodies = {'request': bytearray(), 'response': bytearray()}
        metadata = {}; partial = {}; exchange = None; status = None
        for event, body, unknown in frames:
            kind = event['type']
            if unknown is not None:
                unknowns.append(unknown); continue
            if kind == 'started':
                require(phase == 'start' and event['method'] == 'POST', 'start'); phase = 'request'
            elif kind == 'transport-link':
                require(phase == 'request' and exchange is None and len(bytes.fromhex(event['exchange'])) == 32, 'exchange')
                exchange = event['exchange']
            elif kind in ('request-chunk', 'response-chunk'):
                direction = kind.split('-')[0]
                require(phase == direction and event['offset'] == len(bodies[direction]), 'body coordinates')
                bodies[direction].extend(body)
            elif kind == 'request-end':
                require(phase == 'request' and event['bytes'] == len(bodies['request']), 'request end'); phase = 'intent'
            elif kind == 'forwarding-intent':
                require(phase == 'intent', 'intent'); phase = 'head'
            elif kind == 'response-head':
                require(phase == 'head', 'head'); status = event['status']; phase = 'response'
            elif kind == 'terminal':
                require(phase == 'response' and event['outcome'] == 'completed', 'terminal'); phase = 'done'
            elif kind in ('http-metadata', 'http-metadata-chunk'):
                direction = event['direction']
                require(phase == {'request': 'request', 'request-outgoing': 'head', 'response': 'response'}[direction], 'metadata phase')
                if kind == 'http-metadata-chunk':
                    total, buf = partial.setdefault(direction, (event['total'], bytearray()))
                    require(total == event['total'] and event['offset'] == len(buf) and len(buf)+len(body) <= total, 'metadata coordinates')
                    buf.extend(body)
                    if len(buf) != total: continue
                    event = json.loads(buf)
                    require(event['type'] == 'http-metadata' and event['direction'] == direction, 'metadata reconstruction')
                require(direction not in metadata, 'duplicate metadata')
                require(all(name not in ('authorization','x-api-key','cookie','set-cookie','proxy-authorization') for name, value in event['headers']), 'secret header')
                for name, value in event['headers']:
                    require(bytes.fromhex(value).hex() == value and name == name.lower(), 'header encoding')
                metadata[direction] = event
            if kind not in ('request-chunk','response-chunk','http-metadata-chunk'):
                require(not body, 'stray body')
        require(phase == 'done' and exchange is not None, 'complete exchange')
        require(set(metadata) == {'request','request-outgoing','response'}, 'metadata coverage')
        require(all(len(buf) == total for total, buf in partial.values()), 'incomplete metadata')
        if observer == 'gateway':
            require('x-api-key' in metadata['request-outgoing']['omitted'], 'provider credential omission')
        actual.append({'request': bodies['request'].hex(), 'response': bodies['response'].hex(), 'status': status})
        links.append(exchange)
    require(sorted(actual, key=lambda x:x['request']) == sorted(expected['exchanges'], key=lambda x:x['request']), 'external body expectations')
    return {'exchanges': sorted(links), 'unknown_frames': unknowns}


if __name__ == '__main__':
    print(json.dumps(verify(*sys.argv[1:]), sort_keys=True))
