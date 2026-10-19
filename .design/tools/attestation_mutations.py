#!/usr/bin/env python3
"""In-memory semantic-check removal probes; source and fixture files never change."""
import ast
import contextlib
import io
import json
from pathlib import Path
import types
ROOT=Path(__file__).resolve().parents[2]
PATH=ROOT/'.design/tools/attestation_vectors.py'
SOURCE=PATH.read_text()
DATA=json.loads((ROOT/'.design/fixtures/service-attestation-v1.json').read_text())
# Independent acceptance obligations; redundant parser/bound checks are not
# claimed as separately discriminated. Each of these has an exact labelled case.
LABELS=['envelope-bound','envelope-fields','statement-bytes','statement-fields',
        'profile','body-fields','issuer-fields','issuer-algorithm','issuer-method',
        'issuer-version','pinned-issuer','archive-length','scope-length',
        'configured-archive','configured-scope','safe-integer','sequence',
        'record-cid','purpose','genesis','chain-position','chain-commitments',
        'record-binding','receipt-binding','admitted-issuer','signature-encoding','signature-range']
def run(source):
    module=types.ModuleType('oracle_mutant');module.__file__=str(PATH)
    exec(compile(source,str(PATH),'exec'),module.__dict__)
    with contextlib.redirect_stdout(io.StringIO()):module.check(DATA)
run(SOURCE)
tree=ast.parse(SOURCE);lines=SOURCE.splitlines(keepends=True)
for label in LABELS:
    matches=[n for n in ast.walk(tree) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call)
             and isinstance(n.value.func,ast.Name) and n.value.func.id in ['require','closed']
             and n.value.args and isinstance(n.value.args[-1],ast.Constant) and n.value.args[-1].value==label]
    assert len(matches)==1,(label,len(matches))
    n=matches[0]
    # Some lines have two calls. AST byte offsets preserve surrounding code.
    start=sum(len(s) for s in lines[:n.lineno-1])+n.col_offset
    end=sum(len(s) for s in lines[:n.end_lineno-1])+n.end_col_offset
    mutant=SOURCE[:start]+'pass'+SOURCE[end:]
    try:run(mutant)
    except AssertionError as error:
        assert 'expected' in str(error) or 'accepted negative' in str(error),str(error)
        print(label+': killed by labelled negative assertion')
    else:raise AssertionError('SURVIVED: '+label)
print(f'{len(LABELS)}/{len(LABELS)} semantic-check removals killed; zero survivors. No runtime admission claim.')
