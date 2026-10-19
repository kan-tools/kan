#!/usr/bin/env python3
"""Concrete inputs for non-equivalent mutant survivors in mutate_extended.log.
Shows the oracle logic rejects them (logic present) while no fixture vector
exists (gate does not discriminate). Usage: python -I probe_survivors.py <root>"""
import copy, importlib.util, json, sys
from pathlib import Path
ROOT = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location('oracle', ROOT/'.design/tools/attestation_vectors.py')
O = importlib.util.module_from_spec(spec); sys.modules['oracle'] = O; spec.loader.exec_module(O)
C = O.codec
D = json.loads((ROOT/'.design/fixtures/service-attestation-v1.json').read_text())
K1, CUR = O.identity(1)
ARCH, SCOPE = bytes.fromhex(D['archiveHex']), bytes.fromhex(D['scopeHex'])
R0 = D['positive'][0]

def attempt(name, man, rec, st_mod=None, prev=None):
    mraw, rraw = C.encode(man), C.encode(rec)
    st = copy.deepcopy(R0['statement'])
    st['body'].update(manifest=C.link(C.cid(mraw)), receipt=C.link(C.cid(rraw)))
    if st_mod: st_mod(st)
    try:
        O.verify(O.sign(st, K1), D['pinnedIssuer'], ARCH, SCOPE, prev, mraw, rraw); out = 'accept'
    except O.Rejected as e: out = 'reject:'+str(e)
    except Exception as e: out = 'unexpected:'+type(e).__name__
    print(f'{name}: oracle={out}')

def bound(man, rec):
    rec['body'].update(manifest=C.link(C.cid(C.encode(man))))
    return man, rec

# 1. manifest of a foreign scope, receipt correctly bound to it, statement claims configured scope
man = copy.deepcopy(R0['manifest']); man['body']['scopeToken'] = C.blob(b'\x07'*32)
rec = copy.deepcopy(R0['receipt']); rec['body']['scopeToken'] = C.blob(b'\x07'*32)
attempt('foreign-scope manifest under configured-scope statement', *bound(man, rec))
# 2. receipt position/operation differ from manifest while manifest CID matches
for f, v in [('position', 99), ('operation', C.blob(b'\x05'*16))]:
    man = copy.deepcopy(R0['manifest']); rec = copy.deepcopy(R0['receipt']); man, rec = bound(man, rec)
    rec['body'][f] = v
    attempt(f'receipt {f} != manifest {f}', man, rec)
# 3. sequence 2 with null predecessors and no verified previous row
attempt('sequence>1 with null predecessors, no previous', copy.deepcopy(R0['manifest']), copy.deepcopy(R0['receipt']),
        st_mod=lambda s: s['body'].update(sequence=2, previousSequence=1))
# 4. admitted receipt issuer: same principal, different verificationMethod
rec = copy.deepcopy(R0['receipt']); rec['body']['issuer'] = dict(rec['body']['issuer'], verificationMethod=CUR['principal']+'#other')
attempt('admitted receipt issuer same principal, other method', copy.deepcopy(R0['manifest']), rec)
print('fixture labels present:', sorted({n['expected'] for n in D['negative']}))
print('fixture negatives touching receipt operation/position or manifest scope:',
      [n['name'] for n in D['negative'] if any(k in n['name'] for k in ('operation', 'position', 'manifest-scope'))])
