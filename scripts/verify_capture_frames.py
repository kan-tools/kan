#!/usr/bin/env python3
"""Independent synthetic KANC2 fixture decoder, not a production archive reader.
Inputs: numbered .bin frames/.op IDs and expected request/response files.
Checks complete, gap-free gateway fixture order and byte bodies without Rust code.
"""
import hashlib
import json
import pathlib
import sys

def require(value, reason):
    if not value:
        raise ValueError(reason)

def verify(root):
    files = sorted(root.glob('*.bin'), key=lambda p: int(p.stem))
    require(bool(files), 'empty capture')
    bodies = {'request': bytearray(), 'response': bytearray()}
    attempt = None
    phase = 'start'
    for ordinal, path in enumerate(files):
        require(int(path.stem) == ordinal, 'missing ordinal')
        frame = path.read_bytes()
        require(frame[:5] == b'KANC2' and len(frame) >= 9, 'magic')
        length = int.from_bytes(frame[5:9], 'big')
        require(0 < length <= 16384 and 9+length <= len(frame), 'header bound')
        h = json.loads(frame[9:9+length])
        body = frame[9+length:]
        require(set(h) == {'version','attempt','observer','ordinal','observed_at_unix_micros','elapsed_micros','unconfirmed_before','event'}, 'fields')
        require(h['version'] == 2 and h['ordinal'] == ordinal and h['unconfirmed_before'] == 0, 'coordinates')
        require(h['observer'] == 'gateway', 'observer')
        require(type(h['observed_at_unix_micros']) is int and h['observed_at_unix_micros'] > 0, 'capture time')
        require(type(h['elapsed_micros']) is int and h['elapsed_micros'] >= 0, 'elapsed time')
        require(len(h['attempt']) == 64 and bytes.fromhex(h['attempt']).hex() == h['attempt'], 'attempt')
        attempt = attempt or h['attempt']
        require(h['attempt'] == attempt, 'attempt changed')
        expected = hashlib.sha256(b'tools.kan.capture.operation.v1\0' + bytes.fromhex(attempt) + b'\1' + ordinal.to_bytes(8,'big')).hexdigest()[:32]
        require(path.with_suffix('.op').read_text() == expected, 'operation')
        require(len(body) <= 65536, 'chunk bound')
        event = h['event']; kind = event['type']
        if kind == 'started':
            require(phase == 'start' and event['method'] == 'POST', 'start')
            phase = 'request'
        elif kind == 'request-chunk' or kind == 'response-chunk':
            direction = kind.split('-')[0]
            require(phase == direction and event['offset'] == len(bodies[direction]), 'chunk order')
            bodies[direction].extend(body)
        elif kind == 'request-end':
            require(phase == 'request' and event['bytes'] == len(bodies['request']), 'request end')
            phase = 'intent'
        elif kind == 'forwarding-intent':
            require(phase == 'intent', 'forward intent'); phase = 'head'
        elif kind == 'response-head':
            require(phase == 'head' and event['status'] == 201, 'response head'); phase = 'response'
        elif kind == 'terminal':
            require(phase == 'response' and event['outcome'] == 'completed', 'terminal'); phase = 'done'
        else:
            raise ValueError('unknown event')
        if kind not in ('request-chunk','response-chunk'):
            require(not body, 'unexpected body')
    require(phase == 'done', 'incomplete')
    for direction, body in bodies.items():
        require(body == (root / direction).read_bytes(), direction + ' bytes')
    print(json.dumps({'frames':len(files),'request_bytes':len(bodies['request']),'response_bytes':len(bodies['response'])}))

if __name__ == '__main__':
    verify(pathlib.Path(sys.argv[1]))
