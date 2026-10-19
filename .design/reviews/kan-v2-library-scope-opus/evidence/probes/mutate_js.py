import hashlib, re, subprocess, sys, pathlib
root = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2]); out.mkdir(exist_ok=True)
app = root / 'web/library/app.js'; orig = app.read_bytes(); h0 = hashlib.sha256(orig).hexdigest()
CALL = "    validateScopes(value.scopes);\n"
M = {
 'U01 delete validateScopes call': [(CALL, '')],
 'U02 drop >16 limit': [(" || value.length > 16", '')],
 'U03 drop scope >256': [(" || entry.scope.length > 256", '')],
 'U04 drop request >8192': [(" || entry.pin.request.length > 8192", '')],
 'U05 drop duplicate check': [(" || seen.has(entry.scope)", '')],
 'U06 drop empty scope check': [("!entry.scope.length || ", '')],
 'U07 drop empty request check': [(" || !entry.pin.request.length", '')],
 'U08 drop reply object check': [(" || !object(entry.pin.reply)", '')],
 'U09 drop isArray(value)': [("!Array.isArray(value) || ", '')],
 'U10 object() accepts arrays': [("&& !Array.isArray(v);", ';')],
 'U11 drop seen.add': [("      seen.add(entry.scope);\n", '')],
 'U12 validate after option render': [(CALL, ''), ("    $('login').hidden = true; $('library').hidden = false;", CALL + "    $('login').hidden = true; $('library').hidden = false;")],
 'U13 validate after library unhide': [(CALL, ''), ("$('lock').disabled = false;\n", "$('lock').disabled = false;\n" + CALL)],
 'U14 drop typeof scope string': [("typeof entry.scope !== 'string' || ", '')],
 'U15 drop object(entry)': [("!object(entry) || ", '')],
 'U16 drop object(entry.pin)': [(" || !object(entry.pin)", '')],
 'U17 drop typeof request string': [(" typeof entry.pin.request !== 'string' ||", '')],
 'U18 validate after renderCapabilities': [(CALL, ''), ("    renderCapabilities(value);\n", "    renderCapabilities(value);\n" + CALL)],
 'U19 drop catalog-start clearInspector': [("  async function catalog() {\n    clearInspector(); ", "  async function catalog() {\n    ")],
 'U20 drop clearInspector at start and in run catch': [("  async function catalog() {\n    clearInspector(); ", "  async function catalog() {\n    "), ("else { clearInspector(); if (!pin)", "else { if (!pin)")],
 'U21 drop catalog-start rows clear': [("buttons.clear(); $('rows').replaceChildren(); $('scope').replaceChildren();\n    scopes = [];", "buttons.clear(); $('scope').replaceChildren();\n    scopes = [];")],
 'U22 drop catalog-start pin reset': [("    scopes = []; pin = null; history = []; after = 0; next = null;\n    $('coverage')", "    scopes = []; history = []; after = 0; next = null;\n    $('coverage')")],
 'U23 drop catalog-start scopes reset': [("    scopes = []; pin = null; history = []; after = 0; next = null;\n    $('coverage')", "    pin = null; history = []; after = 0; next = null;\n    $('coverage')")],
}
summary = []
for name, edits in M.items():
    src = orig.decode()
    ok = True
    for old, new in edits:
        if src.count(old) != 1: ok = False; summary.append(f'{name}: INVALID (pattern count {src.count(old)})'); break
        src = src.replace(old, new)
    if not ok: continue
    app.write_text(src)
    try:
        res = {}
        for label, f in [('committed', 'tests/library_ui.test.cjs'), ('probes', str(out.parent / 'probes/scope_probes.test.cjs'))]:
            p = subprocess.run(['node', '--test', f], cwd=root, capture_output=True, text=True, timeout=120)
            log = p.stdout + p.stderr
            (out / f"{name.split()[0]}-{label}.txt").write_text(log)
            failed = re.findall(r'^✖ (.*?) \(', log, re.M)
            failed = sorted(set(failed) - {'failing tests:'})
            kinds = sorted(set(re.findall(r'(AssertionError|SyntaxError|TypeError|ReferenceError)', log)))
            res[label] = (p.returncode, failed, kinds)
        c, pr = res['committed'], res['probes']
        verdict = 'KILLED-by-committed' if c[0] else ('KILLED-by-probes-only' if pr[0] else 'SURVIVED')
        summary.append(f"{name}: {verdict}\n   committed rc={c[0]} kinds={c[2]} failed={c[1]}\n   probes rc={pr[0]} kinds={pr[2]} failed={pr[1]}")
    finally:
        app.write_bytes(orig)
        assert hashlib.sha256(app.read_bytes()).hexdigest() == h0
summary.append(f'restored app.js sha256={hashlib.sha256(app.read_bytes()).hexdigest()} original={h0}')
(out / 'SUMMARY.txt').write_text('\n'.join(summary) + '\n'); print('\n'.join(summary))
