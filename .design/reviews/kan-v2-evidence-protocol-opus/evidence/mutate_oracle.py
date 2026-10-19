#!/usr/bin/env python3
"""In-memory assertion-removal mutants of the attestation oracle's verify().

Answers: does `attestation_vectors.py --check` FAIL when a named binding check
is deleted? A surviving mutant means the shipped fixture/negative set does not
cover that binding. Never writes to the reviewed tree.
Usage: python mutate_oracle.py <tree-root>
"""
import io
import json
import sys
import types
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
SRC_PATH = ROOT / '.design/tools/attestation_vectors.py'
SOURCE = SRC_PATH.read_text()
DATA = json.loads((ROOT / '.design/fixtures/service-attestation-v1.json').read_text())

MUTANTS = {
    'chain commitments removed': "        assert b['previousManifest'] == previous['manifest'] and b['previousAttestation'] == previous['statementCid'], 'chain commitments'\n",
    'chain position/scope removed': "        assert b['previousSequence'] == previous['sequence'] and b['scopeToken'] == previous['scopeToken'], 'chain position/scope'\n",
    'genesis rule removed': "        assert b['sequence'] == 1 and b['previousManifest'] is None and b['previousAttestation'] is None, 'genesis'\n",
    'sequence arithmetic removed': "    assert b['sequence'] > 0 and b['previousSequence'] == b['sequence']-1, 'sequence'\n",
    'purpose allow-list removed': "    assert b['purpose'] in ['admitted', 'retained-verified'], 'purpose'\n",
    'scope length removed': "    assert isinstance(b['scopeToken'], bytes) and len(b['scopeToken']) == 32, 'scope'\n",
    'closed body removed': "    closed(b, ['issuer', 'scopeToken', 'sequence', 'manifest', 'receipt', 'previousSequence', 'previousManifest', 'previousAttestation', 'purpose', 'issuedAt'])\n",
    'profile v/kind removed': "    assert type(statement['v']) is int and statement['v'] == 1 and statement['kind'] == 'service-attestation', 'profile'\n",
    'low-S/range removed': "    assert 0 < r < ORDER and 0 < s <= ORDER//2, 'canonical low-S'\n",
    'pinned issuer removed': "    assert b['issuer'] == expected_author and b['issuer']['principal'] == pinned, 'pinned issuer'\n",
    'envelope bound removed': "    assert len(raw) <= 16384, 'envelope bound'\n",
    'closed envelope removed': "    closed(env, ['statement', 'signature'])\n",
    'record CID shape removed': "    assert isinstance(value, codec.Link) and len(value.raw) == 36 and value.raw[:4] == b'\\x01\\x71\\x12\\x20', 'record CID'\n",
}


def run(source):
    mod = types.ModuleType('mutant')
    mod.__file__ = str(SRC_PATH)
    code = compile(source.replace("if __name__ == '__main__':", 'if False:'), str(SRC_PATH), 'exec')
    exec(code, mod.__dict__)
    with redirect_stdout(io.StringIO()):
        mod.check(DATA)


run(SOURCE)  # baseline must pass
print('baseline check: pass')
survivors = 0
for name, line in MUTANTS.items():
    assert line in SOURCE, 'mutant anchor not found: ' + name
    replacement = line[:len(line) - len(line.lstrip())] + 'pass\n'
    try:
        run(SOURCE.replace(line, replacement, 1))
        verdict = 'SURVIVED (check still passes)'
        survivors += 1
    except Exception as e:
        verdict = 'killed (%s: %s)' % (type(e).__name__, str(e)[:60])
    print('%-30s %s' % (name, verdict))
print('%d/%d mutants survived' % (survivors, len(MUTANTS)))
