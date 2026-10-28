#!/usr/bin/env python3
"""Fresh correction-review mutants against a8cbf21: exact single-occurrence
replacement, run, restore, verify hash. Compile failures and timeouts are
reported as such and never counted as semantic kills."""
import hashlib, os, subprocess, sys, time
ROOT = os.getcwd()
RUST = ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_reader', '--test', 'evidence_library_cli']
NODE = ['node', '--test', 'tests/library_ui.test.cjs']
R, L, J = 'src/evidence_reader.rs', 'src/evidence_library.rs', 'web/library/app.js'
M = [
 # First-review survivors, re-targeted at current code.
 ('M01 pin principal check removed', R, "if signed.request.principal != self.signer.did().as_str()\n            || signed.request.audience", "if false\n            || signed.request.audience", RUST),
 ('M02 pin audience check removed', R, "|| signed.request.audience != access.issuer\n            || !matches!", "|| false\n            || !matches!", RUST),
 ('M04 page tip binding removed', R, "if row.sequence == through && Some(record.manifest.cid().to_string()) != tip {", "if false {", RUST),
 ('M05 page completeness removed', R, "if complete != (last == through) || (!complete && records.is_empty()) {", "if false {", RUST),
 ('M05a empty-incomplete clause removed', R, "if complete != (last == through) || (!complete && records.is_empty()) {", "if complete != (last == through) {", RUST),
 ('M05b complete==last clause removed', R, "if complete != (last == through) || (!complete && records.is_empty()) {", "if !complete && records.is_empty() {", RUST),
 ('M13 Reader >16 scopes allowed', R, "if scopes.is_empty() || scopes.len() > 16 {", "if scopes.is_empty() {", RUST),
 ('M13b duplicate scopes allowed', R, "if selected.insert(service::hex(&scope.scope), scope).is_some() {\n                return Err(Failure::Invalid);\n            }", "selected.insert(service::hex(&scope.scope), scope);", RUST),
 ('M14 page after>through local check removed', R, "if after > through {\n            return Err(Failure::Invalid);\n        }\n        let (_, reply)", "let (_, reply)", RUST),
 ('M25 pin reply signature not verified', R, "let reply = pin.reply.verify(&bytes, &access.issuer)?;", "let reply = &pin.reply.reply;", RUST),
 ('M17 duplicate Authorization check removed', L, "if r.headers().get_all(\"authorization\").iter().count() != 1\n        ||", "if", RUST),
 ('M18 content-type check removed', L, "        .and_then(|v| v.to_str().ok())\n        != Some(\"application/json\")", "        .and_then(|v| v.to_str().ok())\n        == Some(\"never\")", RUST),
 ('M19 catalog swallows every failure', L, "Err(Failure::AccessLimited) => {}\n                    Err(e) => return Err(e),", "Err(_) => {}", RUST),
 ('M20 nosniff removed', L, "(\"x-content-type-options\",\"nosniff\"),", "", RUST),
 ('M20b frame-ancestors removed', L, " frame-ancestors 'none';", "", RUST),
 ('M21 serve loopback check removed', L, "if !addr.ip().is_loopback()\n        ||", "if", RUST),
 ('M22 token length floor removed', L, "|| token.len() < 32\n", "", RUST),
 # Correction-specific mutants.
 ('N01 signer==issuer refusal removed', R, "if signer.did().as_str() == scope.issuer {", "if false {", RUST),
 ('N02 transport AccessLimited not reclassified', R, "Failure::AccessLimited => Failure::Corrupt,", "Failure::AccessLimited => Failure::AccessLimited,", RUST),
 ('N03 second verify map_err removed', R, ".verify(&request, &access.issuer)\n            .map_err(|_| Failure::Corrupt)?;", ".verify(&request, &access.issuer)?;", RUST),
 ('Q01 execution bound removed (4 -> 1000)', L, "let requests = Arc::new(Semaphore::new(4));", "let requests = Arc::new(Semaphore::new(1000));", RUST),
 ('Q02 execution permit dropped before serving', L, "let Ok(Ok(_request)) =", "let Ok(Ok(_)) =", RUST),
 ('Q03 accepted-socket bound 12 -> 1000', L, "let slots = Arc::new(Semaphore::new(12));", "let slots = Arc::new(Semaphore::new(1000));", RUST),
 ('Q04 accepted-socket bound 12 -> 5', L, "let slots = Arc::new(Semaphore::new(12));", "let slots = Arc::new(Semaphore::new(5));", RUST),
 ('Q05 six-second queue deadline removed', L, "tokio::time::timeout(Duration::from_secs(6), requests.acquire_owned()).await", "Ok::<_, ()>(requests.acquire_owned().await)", RUST),
 ('Q06 overall 35s deadline removed', L, "let _=tokio::time::timeout(Duration::from_secs(35),connection).await;", "connection.await;", RUST),
 ('Q07 header read deadline removed', L, ".timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(Duration::from_secs(5));", ".timer(hyper_util::rt::TokioTimer::new());", RUST),
 ('K01 every error locks', J, "if (error.accessDenied || $('library').hidden) lock(message);\n    else { clearInspector(); notice(message, true); }", "lock(message);", NODE),
 ('K02 access denial no longer locks while browsing', J, "if (error.accessDenied || $('library').hidden) lock(message);", "if ($('library').hidden) lock(message);", NODE),
 ('K03 401 not treated as denial', J, "const denied = response.status === 401 || response.status === 403;", "const denied = response.status === 403;", NODE),
 ('K04 403 not treated as denial', J, "const denied = response.status === 401 || response.status === 403;", "const denied = response.status === 401;", NODE),
 ('K05 non-auth error keeps plaintext', J, "else { clearInspector(); notice(message, true); }", "else { notice(message, true); }", NODE),
 ('K07 page keeps old rows during load', J, "clearInspector(); buttons.clear(); $('rows').replaceChildren();\n    $('count')", "clearInspector();\n    $('count')", NODE),
 ('K08 page keeps Next enabled during load', J, "$('previous').disabled = true; $('next').disabled = true;\n    notice('Reading", "$('previous').disabled = true;\n    notice('Reading", NODE),
 ('K08b page keeps Previous enabled during load', J, "$('previous').disabled = true; $('next').disabled = true;\n    notice('Reading", "$('next').disabled = true;\n    notice('Reading", NODE),
 ('K09 page keeps old count/coverage during load', J, "$('count').textContent = ''; $('coverage').textContent = ''; $('page-position').textContent = 'Loading…';", "$('page-position').textContent = 'Loading…';", NODE),
 ('K10 directional controls not forced to hex', J, "\\u061c\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]", "]", NODE),
 ('K10b isolates U+2066-2069 not forced to hex', J, "\\u202a-\\u202e\\u2066-\\u2069]", "\\u202a-\\u202e]", NODE),
 ('K10c LRM/RLM/ALM not forced to hex', J, "\\u061c\\u200e\\u200f\\u202a", "\\u202a", NODE),
 ('K11 lock keeps capability matrix', J, "$('scope').replaceChildren(); $('capability-list').replaceChildren();", "$('scope').replaceChildren();", NODE),
 ('K12 unknown capability shown Available', J, "(supported.has(capability) ? 'Available' : 'Client unsupported')", "'Available'", NODE),
 ('K13 duplicate capability accepted', J, "if (typeof capability !== 'string' || seen.has(capability))", "if (typeof capability !== 'string')", NODE),
 ('K14 capability shape check removed', J, "if (!Array.isArray(value.capabilities) || !Array.isArray(value.unavailable)) throw new Error('Unsupported capability response.');", "", NODE),
 ('J08 both late-response epoch checks removed', J, "if (current !== epoch) return null;\n    if (!response.ok)", "if (!response.ok)", NODE),
 ('A01 API claims semantic search available', L, '"capabilities":["snapshot-inventory","source-ranges","provenance"],"unavailable":["semantic-search",', '"capabilities":["snapshot-inventory","source-ranges","provenance","semantic-search"],"unavailable":[', RUST),
 ('A02 API capability fields removed', L, ',"capabilities":["snapshot-inventory","source-ranges","provenance"],"unavailable":["semantic-search","normalized-sessions","annotations","saved-views","analysis","administrative-jobs"]', '', RUST),
]
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
only = set(sys.argv[1:])
results = []
for name, path, old, new, cmd in M:
    tag = name.split()[0]
    if only and tag not in only: continue
    orig = open(path, 'rb').read(); h = sha(path)
    text = orig.decode()
    if text.count(old) != 1:
        results.append((name, f'NOT-APPLIED count={text.count(old)}')); print(name, 'NOT-APPLIED', text.count(old), flush=True); continue
    try:
        mutated = text.replace(old, new)
        if tag == 'J08': mutated = mutated.replace("const value = await response.json(); if (current !== epoch) return null; return value;", "const value = await response.json(); return value;")
        open(path, 'w').write(mutated); os.utime(path, None)
        t = time.time()
        try:
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=300)
            out = p.stdout + p.stderr; rc = p.returncode
        except subprocess.TimeoutExpired:
            out = 'TIMEOUT'; rc = 'timeout'
        open(f'review-evidence/mutants/{tag}.txt', 'w').write(f'# {name}\n# file {path}\n# rc {rc} elapsed {time.time()-t:.1f}s\n' + out)
        if rc == 'timeout': verdict = 'TIMEOUT (not a semantic kill)'
        elif 'error[E' in out or 'could not compile' in out: verdict = 'COMPILE-FAIL (not a semantic kill)'
        elif rc == 0: verdict = 'SURVIVED'
        else:
            fails = [l for l in out.splitlines() if (l.startswith('test ') and l.endswith('FAILED')) or l.startswith('✖')]
            verdict = 'KILLED by ' + '; '.join(dict.fromkeys(fails[:6]))
    finally:
        open(path, 'wb').write(orig); os.utime(path, None)
        assert sha(path) == h, 'restore failed ' + path
    results.append((name, verdict)); print(name, '=>', verdict, flush=True)
with open('review-evidence/06-mutation-summary.txt', 'a') as f:
    f.write('\n'.join(f'{n}\t{v}' for n, v in results) + '\n')
