#!/usr/bin/env python3
"""Find Write/Edit tool calls in a stream-json transcript whose content holds UPb, report
paths and compare the last full Write against the imported file.
Usage: python3 -I extract_original_probe.py <transcript.jsonl> <imported.cjs> <out_dir>"""
import json, sys, hashlib, os
tr, imported, out = sys.argv[1:4]
writes = []
for n, line in enumerate(open(tr, encoding='utf-8', errors='replace')):
    try: ev = json.loads(line)
    except Exception: continue
    msg = ev.get('message') or {}
    for c in msg.get('content') or [] if isinstance(msg.get('content'), list) else []:
        if c.get('type') == 'tool_use' and c.get('name') in ('Write', 'Edit'):
            inp = c.get('input', {})
            blob = inp.get('content') or inp.get('new_string') or ''
            if 'UPb' in blob or 'UPa' in blob:
                writes.append((n, c['name'], inp.get('file_path'), blob, inp))
for n, name, p, blob, inp in writes:
    print(f'line {n}: {name} {p} len={len(blob)} sha256={hashlib.sha256(blob.encode()).hexdigest()}')
imp = open(imported, 'rb').read()
print('imported sha256', hashlib.sha256(imp).hexdigest(), 'len', len(imp))
full = [w for w in writes if w[1] == 'Write']
if full:
    n, _, p, blob, _ = full[-1]
    os.makedirs(out, exist_ok=True)
    open(os.path.join(out, 'original-probe-from-transcript.cjs'), 'w').write(blob)
    print('last Write byte-identical to imported:', blob.encode() == imp)
    print('edits after last Write:', [ (w[0], w[2]) for w in writes if w[1]=='Edit' and w[0]>n ])
