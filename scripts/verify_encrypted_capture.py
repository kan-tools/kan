"""Reviewer-written independent decoder: HPKE-open spool ciphertexts with the
OpenSSL-backed oracle key schedule, then parse KANC2 without any Rust code.
argv: oracle_module_path fixture_dir
fixture_dir: N.ct (ciphertext), N.op (Append id hex), private, scope, route,
             request, response, status
"""
import hashlib, importlib.util, json, pathlib, sys

spec = importlib.util.spec_from_file_location("oracle", sys.argv[1])
oracle = importlib.util.module_from_spec(spec); spec.loader.exec_module(oracle)
oracle.vectors()  # RFC 9180 self-check before trusting the schedule
root = pathlib.Path(sys.argv[2])
private = (root / "private").read_bytes(); scope = (root / "scope").read_bytes()
route = (root / "route").read_text(); status = int((root / "status").read_text())

def fail(m):
    raise SystemExit("REJECT: " + m)

def open_frame(frame):
    if frame[:11] != b"KANE\x01\x00\x20\x00\x01\x00\x03": fail("profile")
    pub = oracle.X25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()
    if hashlib.sha256(pub).digest() != frame[11:43]: fail("recipient")
    key, nonce = oracle.schedule(private, frame[43:75], b"tools.kan.archive.hpke.v1\x00" + scope)
    return oracle.ChaCha20Poly1305(key).decrypt(nonce, frame[79:], frame[:79])

files = sorted(root.glob("*.ct"), key=lambda p: int(p.stem))
bodies = {"request": bytearray(), "response": bytearray()}
attempt = None; kinds = []
for i, path in enumerate(files):
    plain = open_frame(path.read_bytes())
    if plain[:5] != b"KANC2": fail("magic")
    n = int.from_bytes(plain[5:9], "big"); h = json.loads(plain[9:9 + n]); body = plain[9 + n:]
    if set(h) != {"version", "attempt", "observer", "ordinal", "observed_at_unix_micros", "elapsed_micros", "unconfirmed_before", "event"}: fail("fields")
    if h["version"] != 2 or h["ordinal"] != i or h["unconfirmed_before"] != 0: fail("coords %d" % i)
    if h["observer"] != "gateway": fail("observer")
    if type(h["observed_at_unix_micros"]) is not int or h["observed_at_unix_micros"] <= 0: fail("capture time")
    if type(h["elapsed_micros"]) is not int or h["elapsed_micros"] < 0: fail("elapsed time")
    attempt = attempt or h["attempt"]
    if h["attempt"] != attempt or len(bytes.fromhex(attempt)) != 32: fail("attempt")
    op = hashlib.sha256(b"tools.kan.capture.operation.v1\0" + bytes.fromhex(attempt) + b"\1"
                        + i.to_bytes(8, "big")).hexdigest()[:32]
    if (root / (path.stem + ".op")).read_text() != op: fail("operation id %d" % i)
    if len(body) > 65536: fail("chunk bound")
    e = h["event"]; k = e["type"]; kinds.append(k)
    if k == "started":
        if e != {"type": "started", "method": "POST", "route": route}: fail("started %r" % e)
    elif k in ("request-chunk", "response-chunk"):
        d = k.split("-")[0]
        if e["offset"] != len(bodies[d]): fail("offset")
        bodies[d].extend(body)
    elif k == "request-end":
        if e["bytes"] != len(bodies["request"]): fail("request-end")
    elif k == "response-head":
        if e["status"] != status: fail("status")
    elif k == "terminal":
        if e["outcome"] != "completed": fail("terminal")
    elif k != "forwarding-intent":
        fail("kind " + k)
    if k not in ("request-chunk", "response-chunk") and body: fail("stray body")
compressed = [k for k in kinds if k != "request-chunk" and k != "response-chunk"]
order = ["started", "request-end", "forwarding-intent", "response-head", "terminal"]
if compressed != order: fail("lifecycle %r" % compressed)
# chunk kinds must sit in their phase
if kinds.index("request-end") < max(i for i, k in enumerate(kinds) if k == "request-chunk"): fail("phase")
if kinds.index("response-head") > min(i for i, k in enumerate(kinds) if k == "response-chunk"): fail("phase")
for d in bodies:
    if bytes(bodies[d]) != (root / d).read_bytes(): fail(d + " bytes")
print(json.dumps({"frames": len(files), "request": len(bodies["request"]),
                  "response": len(bodies["response"]), "attempt_len": len(attempt)}))
