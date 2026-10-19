#!/usr/bin/env python3
"""Reviewer probe: conjunct-level removal mutants of the attestation oracle.

In-memory only; never writes source or fixtures. For every require(cond, label)
call, each atomic conjunct/disjunct of cond is neutralised independently:
  - an `and` operand is replaced by True; an `or` operand by False
  - a chained comparison a<b<c is split and each link replaced by True
  - each element of `all(... for f in [..])` lists is dropped
A mutant SURVIVES if check(DATA) still passes. argv[1] = repository root.
"""
import ast, contextlib, copy, io, json, sys, types
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
PATH = ROOT / '.design/tools/attestation_vectors.py'
SOURCE = PATH.read_text()
DATA = json.loads((ROOT / '.design/fixtures/service-attestation-v1.json').read_text())


def run(tree):
    module = types.ModuleType('oracle_conjunct_mutant')
    module.__file__ = str(PATH)
    exec(compile(ast.fix_missing_locations(tree), str(PATH), 'exec'), module.__dict__)
    with contextlib.redirect_stdout(io.StringIO()):
        module.check(DATA)


def requires(tree):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == 'require' and len(n.args) == 2]


def label(call):
    a = call.args[1]
    return a.value if isinstance(a, ast.Constant) else ast.unparse(a)


def expand(node):
    """Rewrite chained comparisons into explicit `and` so each link is an atom."""
    class T(ast.NodeTransformer):
        def visit_Compare(self, n):
            self.generic_visit(n)
            if len(n.ops) == 1:
                return n
            left, parts = n.left, []
            for op, right in zip(n.ops, n.comparators):
                parts.append(ast.Compare(left=copy.deepcopy(left), ops=[op], comparators=[copy.deepcopy(right)]))
                left = right
            return ast.BoolOp(op=ast.And(), values=parts)
    return T().visit(node)


def sites(node, path=()):
    """Yield (path, description) for every neutralisable atom under node."""
    if isinstance(node, ast.BoolOp):
        neutral = isinstance(node.op, ast.And)
        for i, v in enumerate(node.values):
            yield path + (('bool', i, neutral),), ast.unparse(v)
            yield from sites(v, path + (('child', i),))
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'all'
          and node.args and isinstance(node.args[0], ast.GeneratorExp)
          and isinstance(node.args[0].generators[0].iter, ast.List)):
        for i, e in enumerate(node.args[0].generators[0].iter.elts):
            yield path + (('elt', i),), 'all(...) element ' + ast.unparse(e)


def apply(node, path):
    step = path[0]
    if step[0] == 'child':
        node.values[step[1]] = apply(node.values[step[1]], path[1:])
        return node
    if step[0] == 'bool':
        node.values[step[1]] = ast.Constant(value=step[2])
        return node
    if step[0] == 'elt':
        del node.args[0].generators[0].iter.elts[step[1]]
        return node
    raise AssertionError(step)


base = ast.parse(SOURCE)
run(copy.deepcopy(base))  # unmutated must pass
for call in requires(base):
    call.args[0] = expand(call.args[0])
run(copy.deepcopy(base))  # expansion must be semantics-preserving

total = survivors = 0
for index, call in enumerate(requires(base)):
    for path, text in list(sites(call.args[0])):
        tree = copy.deepcopy(base)
        target = requires(tree)[index]
        target.args[0] = apply(target.args[0], path)
        total += 1
        where = f'line {call.lineno} [{label(call)}] drop: {text}'
        try:
            run(tree)
        except AssertionError as e:
            print('killed   ', where, '|', str(e).splitlines()[0][:90])
        except Exception as e:  # noqa: BLE001 -- classify, do not hide
            print('crashed  ', where, '|', type(e).__name__, str(e)[:80])
        else:
            survivors += 1
            print('SURVIVED ', where)
print(f'{total} conjunct mutants; {survivors} survived')
