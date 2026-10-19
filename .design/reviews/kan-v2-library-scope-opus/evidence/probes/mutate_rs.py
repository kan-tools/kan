import hashlib, subprocess, sys, pathlib, re
root = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2]); out.mkdir(exist_ok=True)
T = 'tests/evidence_capture_contention.rs'; S = 'src/evidence_spool.rs'
files = {f: (root / f).read_bytes() for f in (T, S)}
H = {f: hashlib.sha256(b).hexdigest() for f, b in files.items()}
M = {
 'W1 first window takes no lock (BEGIN deferred)': [(T, '''        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        let first_start''', '''        c.execute_batch("BEGIN").unwrap();
        let first_start''')],
 'W2 wrapper drops wait parameter (passes ZERO)': [(T, 'self.inner.admit_with_wait(operation, frame, wait);', 'self.inner.admit_with_wait(operation, frame, Duration::ZERO);')],
 'W3 wrapper reports ZERO on spent channel': [(T, 'spent.send(result.1).unwrap();', 'spent.send(Duration::ZERO).unwrap();')],
 'W4 wrapper returns ZERO spent to production': [(T, '''            spent.send(result.1).unwrap();
        }
        result''', '''            spent.send(result.1).unwrap();
        }
        (result.0, Duration::ZERO)''')],
 'W5 wrapper override removed (default trait)': [(T, """    fn admit_with_wait(
        &mut self,
        operation: &[u8; 16],
        frame: &[u8],
        wait: Duration,
    ) -> (Result<(), capture::Unconfirmed>, Duration) {
        let first = self.first_window();
        let result = self.inner.admit_with_wait(operation, frame, wait);
        if let Some(spent) = first {
            spent.send(result.1).unwrap();
        }
        result
    }
""", "")],
 'W6 production busy handler does not accumulate spent': [(S, '        wait.spent = wait.spent.saturating_add(elapsed);\n', '')],
 'W7 writer releases lock before signalling': [(T, '''        let first_start = Instant::now();
        locked.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        c.execute_batch("ROLLBACK").unwrap();''', '''        let first_start = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        c.execute_batch("ROLLBACK").unwrap();
        locked.send(()).unwrap();''')],
}
summary = []
for name, edits in [(k,v) for k,v in M.items() if k.startswith(tuple(sys.argv[3:]) or '')]:
    src = {f: b.decode() for f, b in files.items()}; ok = True
    for f, old, new in edits:
        if src[f].count(old) != 1: summary.append(f'{name}: INVALID pattern count {src[f].count(old)}'); ok = False; break
        src[f] = src[f].replace(old, new)
    if not ok: continue
    try:
        for f in files: (root / f).write_text(src[f])
        cmd = ['cargo', 'test', '--features', 'v2-crypto', '--test', 'evidence_capture_contention', '--', '--nocapture']
        p = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=900)
        log = p.stdout + p.stderr; tag = name.split()[0]; (out / f'{tag}.txt').write_text(log)
        compiled = 'Running tests/evidence_capture_contention.rs' in log
        failed = re.findall(r'^    (\w+)$', log.split('failures:')[-1], re.M) if 'FAILED' in log else []
        panics = re.findall(r"panicked at ([^\n]+)\n([^\n]+)", log)
        v = ('COMPILE-FAIL' if not compiled else ('KILLED' if p.returncode else 'SURVIVED'))
        summary.append(f'{name}: {v} rc={p.returncode} failed={failed}\n   ' + '\n   '.join(f'{a} :: {b}' for a, b in panics))
    finally:
        for f, b in files.items(): (root / f).write_bytes(b)
        for f in files: assert hashlib.sha256((root / f).read_bytes()).hexdigest() == H[f]
summary.append('restored: ' + ', '.join(f'{f}={hashlib.sha256((root/f).read_bytes()).hexdigest()[:16]} (orig {H[f][:16]})' for f in files))
(out / ('SUMMARY-'+'-'.join(sys.argv[3:])+'.txt' if sys.argv[3:] else 'SUMMARY.txt')).write_text('\n'.join(summary) + '\n'); print('\n'.join(summary))
