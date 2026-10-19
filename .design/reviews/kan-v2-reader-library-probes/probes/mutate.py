#!/usr/bin/env python3
"""Independent review mutants: exact single-occurrence replacement, run, restore, verify hash."""
import hashlib, os, subprocess, sys, time, json
ROOT = os.getcwd()
RUST = ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_reader', '--test', 'evidence_library_cli']
NODE = ['node', '--test', 'tests/library_ui.test.cjs']
R, L, J = 'src/evidence_reader.rs', 'src/evidence_library.rs', 'web/library/app.js'
M = [
 ('M01 pin principal check removed', R, "if signed.request.principal != self.signer.did().as_str()\n            || signed.request.audience", "if false\n            || signed.request.audience", RUST),
 ('M02 pin audience check removed', R, "|| signed.request.audience != access.issuer\n            || !matches!", "|| false\n            || !matches!", RUST),
 ('M03 page continuity removed', R, "if row.sequence != last.checked_add(1).ok_or(Failure::Invalid)?\n                || row.sequence > through", "if row.sequence > through", RUST),
 ('M04 page tip binding removed', R, "if row.sequence == through && Some(record.manifest.cid().to_string()) != tip {", "if false {", RUST),
 ('M05 page completeness removed', R, "if complete != (last == through) || (!complete && records.is_empty()) {", "if false {", RUST),
 ('M06 source membership page removed', R, "let mut membership = self.page(pin, sequence - 1, 1).await?;\n        let expected = membership.records.pop().ok_or(Failure::Missing)?;", "", RUST),
 ('M06b membership checked at fresh (not pinned) snapshot', R, "let mut membership = self.page(pin, sequence - 1, 1).await?;", "let fresh = self.snapshot(&service::hex(&access.scope)).await?;\n        let mut membership = self.page(&fresh, sequence - 1, 1).await?;", RUST),
 ('M07 source read==pinned comparison removed', R, "if record != expected {", "if false {", RUST),
 ('M08 retained request scope/audience check removed', R, "if signed.request.scope != service::hex(&access.scope)\n            || signed.request.audience != access.issuer\n        {", "if false {", RUST),
 ('M09 decode_record scopeToken check removed', R, "|| manifest.body()[\"scopeToken\"] != atproto_dasl::Ipld::Bytes(access.scope.to_vec())", "", RUST),
 ('M10 decode_record issuer check removed', R, "|| receipt.body()[\"issuer\"] != service::author(&access.issuer)?", "", RUST),
 ('M11 verify_retained_request skipped', R, "let signed = service::verify_retained_request(&committed, &bytes)?;", "let signed = service::SignedRequest::decode(&bytes)?;", RUST),
 ('M12 range limit removed', R, "if sequence == 0 || length == 0 || length > RANGE_LIMIT {", "if sequence == 0 || length == 0 {", RUST),
 ('M13 Reader >16 scopes allowed', R, "if scopes.is_empty() || scopes.len() > 16 {", "if scopes.is_empty() {", RUST),
 ('M14 page after>through local check removed', R, "if after > through {\n            return Err(Failure::Invalid);\n        }\n        let (_, reply)", "let (_, reply)", RUST),
 ('M15 Host check removed', L, "if r.headers().get(\"host\").and_then(|v| v.to_str().ok()) != Some(host.as_str())\n        ||", "if", RUST),
 ('M16 Origin check removed', L, "        || r.headers()\n            .get(\"origin\")\n            .is_some_and(|v| v.to_str().ok() != Some(format!(\"http://{host}\").as_str()))\n", "", RUST),
 ('M17 duplicate Authorization check removed', L, "if r.headers().get_all(\"authorization\").iter().count() != 1\n        ||", "if", RUST),
 ('M18 content-type check removed', L, "        .and_then(|v| v.to_str().ok())\n        != Some(\"application/json\")", "        .and_then(|v| v.to_str().ok())\n        == Some(\"never\")", RUST),
 ('M19 catalog swallows every failure', L, "Err(Failure::AccessLimited) => {}\n                    Err(e) => return Err(e),", "Err(_) => {}", RUST),
 ('M20 CSP frame-ancestors/nosniff weakened', L, "(\"x-content-type-options\",\"nosniff\"),", "", RUST),
 ('M21 serve loopback check removed', L, "if !addr.ip().is_loopback()\n        ||", "if", RUST),
 ('M22 token length floor removed', L, "|| token.len() < 32\n", "", RUST),
 ('M23 connection deadline removed', L, "let _=tokio::time::timeout(Duration::from_secs(35),builder.serve_connection(TokioIo::new(stream),service)).await;", "let _=builder.serve_connection(TokioIo::new(stream),service).await;", RUST),
 ('M24 cache-control removed', L, "(\"cache-control\",\"no-store\"),", "", RUST),
 ('M25 pin reply signature not verified', R, "let reply = pin.reply.verify(&bytes, &access.issuer)?;", "let reply = &pin.reply.reply;", RUST),
 ('J08 both late-response epoch checks removed', J, "if (current !== epoch) return null;\n    if (!response.ok)", "if (!response.ok)", NODE),
 ('J01 late fetch epoch check removed', J, "if (current !== epoch) return null;\n    if (!response.ok)", "if (!response.ok)", NODE),
 ('J02 lock does not abort', J, "epoch++; if (controller) controller.abort(); controller = null; token = '';", "epoch++; controller = null; token = '';", NODE),
 ('J03 export reuses displayed source', J, "const value = await rpc({action:'source',pin,sequence,offset,length:65536}); if (!value) return;\n    const bytes", "const value = source;\n    const bytes", NODE),
 ('J04 pagehide lock removed', J, "window.addEventListener('pagehide', () => lock());", "", NODE),
 ('J05 lock keeps export URLs', J, "for (const url of exports.keys()) releaseExport(url);\n", "", NODE),
 ('J06 page late epoch check after json removed', J, "const value = await response.json(); if (current !== epoch) return null; return value;", "const value = await response.json(); return value;", NODE),
 ('J07 scope change keeps stale rows clickable (control: buttons cleared?)', J, "pin = chosen.pin; history = []; await page(0); }));", "pin = chosen.pin; history = []; await page(0); }));", NODE),
]
def sha(p): return hashlib.sha256(open(p,'rb').read()).hexdigest()
only = set(sys.argv[1:])
results = []
for name, path, old, new, cmd in M:
    if only and name.split()[0] not in only: continue
    if old == new: results.append((name, 'SKIPPED-identity')); continue
    orig = open(path, 'rb').read(); h = sha(path)
    text = orig.decode()
    if text.count(old) != 1:
        results.append((name, f'NOT-APPLIED count={text.count(old)}')); print(name, 'NOT-APPLIED', flush=True); continue
    try:
        mutated = text.replace(old, new)
        if name.startswith('J08'): mutated = mutated.replace("const value = await response.json(); if (current !== epoch) return null; return value;", "const value = await response.json(); return value;")
        open(path, 'w').write(mutated); os.utime(path, None)
        t = time.time()
        try:
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600)
            out = p.stdout + p.stderr; rc = p.returncode
        except subprocess.TimeoutExpired as e:
            out = 'TIMEOUT'; rc = 'timeout'
        log = f'review-evidence/mutants/{name.split()[0]}.txt'
        os.makedirs('review-evidence/mutants', exist_ok=True)
        open(log, 'w').write(f'# {name}\n# file {path}\n# rc {rc} elapsed {time.time()-t:.1f}s\n' + out)
        if rc == 'timeout': verdict = 'TIMEOUT (not a semantic kill)'
        elif 'error[E' in out or 'could not compile' in out: verdict = 'COMPILE-FAIL (not a semantic kill)'
        elif rc == 0: verdict = 'SURVIVED'
        else:
            fails = [l for l in out.splitlines() if l.startswith('test ') and l.endswith('FAILED') or l.startswith('not ok') or l.startswith('✖')]
            verdict = 'KILLED by ' + '; '.join(fails[:4])
    finally:
        open(path, 'wb').write(orig); os.utime(path, None)
        assert sha(path) == h, 'restore failed ' + path
    results.append((name, verdict)); print(name, '=>', verdict, flush=True)
open('review-evidence/08-mutation-summary.txt', 'a').write('\n'.join(f'{n}\t{v}' for n, v in results) + '\n')
