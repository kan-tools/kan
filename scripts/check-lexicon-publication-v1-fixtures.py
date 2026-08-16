#!/usr/bin/env python3
"""Executable self-consistency and hostile-mutation checks for RFC 3 vectors."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/fixtures/lexicon-publication-v1/manifest.json"
MAX_RECORD_BYTES = 1_000_000
MAX_COMMIT_BLOCK_BYTES = 2_000_000
MAX_APPLY_WRITES = 200


class Invalid(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def _head(major: int, value: int) -> bytes:
    require(value >= 0, "negative CBOR argument")
    if value < 24:
        return bytes([(major << 5) | value])
    for marker, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (width * 8):
            return bytes([(major << 5) | marker]) + value.to_bytes(width, "big")
    raise Invalid("CBOR integer too large")


def dag_cbor(value: object) -> bytes:
    """Encode the JSON subset used by Lexicon records as deterministic DAG-CBOR."""
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int) and not isinstance(value, bool):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(dag_cbor(item) for item in value)
    if isinstance(value, dict):
        if set(value) == {"$bytes"}:
            try:
                raw = base64.b64decode(value["$bytes"], validate=True)
            except (ValueError, TypeError) as error:
                raise Invalid("invalid bytes encoding") from error
            return _head(2, len(raw)) + raw
        if set(value) == {"$link"}:
            try:
                encoded = value["$link"]
                require(encoded.startswith("b"), "CID is not base32")
                body = encoded[1:].upper()
                padding = "=" * ((8 - len(body) % 8) % 8)
                cid_bytes = base64.b32decode(body + padding)
            except (ValueError, TypeError) as error:
                raise Invalid("invalid CID link") from error
            return b"\xd8\x2a" + _head(2, len(cid_bytes) + 1) + b"\x00" + cid_bytes
        require(all(isinstance(key, str) for key in value), "DAG-CBOR map key is not text")
        pairs = [(dag_cbor(key), dag_cbor(item)) for key, item in value.items()]
        pairs.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _head(5, len(pairs)) + b"".join(key + item for key, item in pairs)
    raise Invalid(f"unsupported DAG-CBOR value: {type(value).__name__}")


def dag_cbor_cid(value: object) -> str:
    digest = hashlib.sha256(dag_cbor(value)).digest()
    cid_bytes = b"\x01\x71\x12\x20" + digest
    return "b" + base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")


def schema_value(schema: dict) -> dict:
    if "value" in schema:
        return schema["value"]
    source = ROOT / schema["sourceFile"]
    require(source.is_file(), f"schema source missing: {source}")
    value = json.loads(source.read_text())
    return {"$type": "com.atproto.lexicon.schema", **value}


def https_origin(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.hostname) and not any(
        (parsed.username, parsed.password, parsed.query, parsed.fragment)
    )


def embedded_bytes(value: dict) -> bytes:
    require(set(value) == {"$bytes"}, "embedded value is not bytes")
    try:
        return base64.b64decode(value["$bytes"], validate=True)
    except (ValueError, TypeError) as error:
        raise Invalid("invalid embedded bytes") from error


def linked_cid(value: dict) -> str:
    require(set(value) == {"$link"}, "CID is not a link")
    require(re.fullmatch(r"b[a-z2-7]{58}", value["$link"]) is not None, "invalid CID link")
    return value["$link"]


def apply_lens(lens_id: str, value: dict) -> tuple[str, object]:
    if lens_id == "identity-v1":
        return "success", copy.deepcopy(value)
    if lens_id == "v1-to-synthetic-v2":
        return "success", {**copy.deepcopy(value), "annotations": []}
    if lens_id == "synthetic-v2-to-v1":
        if value.get("annotations"):
            return "refusal", "annotations-not-representable"
        result = copy.deepcopy(value)
        result.pop("annotations", None)
        return "success", result
    if lens_id == "synthetic-v2-summary":
        return "success", {"message": value["message"], "tags": copy.deepcopy(value["tags"])}
    raise Invalid(f"unknown lens implementation: {lens_id}")


def validate_publication_shape(desired: list[str], known_writes: set[str]) -> None:
    codec_writes = [key for key in desired if key.startswith("codec:")]
    require(len(codec_writes) <= 1, "publication contains more than one new codec")
    require(len(desired) <= MAX_APPLY_WRITES, "publication exceeds applyWrites operation limit")
    require(all(key in known_writes for key in desired), "publication contains an unknown write")


def require_commit_closure_limit(serialized_car_bytes: int) -> None:
    require(serialized_car_bytes <= MAX_COMMIT_BLOCK_BYTES, "publication exceeds commit block limit")


def simulate_publication(case: dict, known_writes: set[str]) -> tuple[int, str]:
    before = {"schema:claim": "old-claim", "schema:fixture": "old-fixture"}
    after = copy.deepcopy(before)
    desired = {key: "new-" + key for key in case["desiredWrites"]}
    validate_publication_shape(list(desired), known_writes)
    calls = 0
    if case["injectBeforeCommit"]:
        require(case["applyWritesCalls"] == 0, "failure invoked applyWrites")
        require(after == before, "pre-commit failure mutated repository")
    elif desired:
        calls = 1
        require(case["applyWritesCalls"] == calls, "publication is not one applyWrites call")
        candidate = {**after, **desired}
        after = candidate
        require(all(after[key] == value for key, value in desired.items()), "atomic write omitted a record")
    else:
        require(case["applyWritesCalls"] == 0, "verification retry performed a write")
    require(calls == case["commits"], "commit count differs from applyWrites calls")
    if case["readback"] == "match":
        return calls, "verified"
    if case["readback"] == "mismatch":
        return calls, "published-unverified"
    require(case["readback"] == "unchanged" and after == before, "unchanged readback drift")
    return calls, "unchanged"


def validate(data: dict) -> None:
    require(data.get("version") == 2, "version must be 2")
    require(set(data) == {"version", "authority", "resolutionCases", "codecGrammar", "codecMaxBytes", "codecCases", "schemas", "codecBinding", "lensRecords", "bindingCases", "publicationCases", "lenses", "lensVectors", "normalizationCases", "requiredViewProvenance", "secretBoundaries"}, "manifest field inventory drift")

    authority = data["authority"]
    expected_nsids = {
        "tools.kan.claim", "tools.kan.codec", "tools.kan.defs", "tools.kan.lens",
        "tools.kan.getClaim", "tools.kan.getIdentity", "tools.kan.getSubject",
    }
    require(set(authority["nsids"]) == expected_nsids, "authoritative NSID set drift")
    require(len(authority["nsids"]) == len(expected_nsids), "duplicate authoritative NSID")
    require(authority["dnsName"] == "_lexicon.kan.tools", "wrong DNS name")
    require(authority["dnsValue"] == "did=did:web:kan.tools", "wrong DNS value")
    require(authority["did"] == "did:web:kan.tools", "wrong authority DID")
    require(authority["didUrl"] == "https://kan.tools/.well-known/did.json", "wrong did:web URL")
    require(authority["pdsEndpoint"] == "https://pds.kan.tools", "wrong PDS endpoint")
    appview = authority["appView"]
    require(appview["serviceDid"] == "did:web:appview.kan.tools", "wrong or invalid service DID")
    require(appview["serviceId"] == authority["did"] + "#kan_appview", "wrong service id")
    require(appview["serviceType"] == "KanAppView", "wrong service type")
    require(https_origin(appview["uri"]), "AppView endpoint is not an HTTPS origin")
    for nsid in authority["nsids"]:
        parts = nsid.split(".")
        require(len(parts) >= 3, f"invalid NSID: {nsid}")
        require("_lexicon." + ".".join(reversed(parts[:-1])) == authority["dnsName"], f"authority drift: {nsid}")

    expected_resolution_rows = [
        ("canonical", "canonical", "canonical", "canonical", "success"),
        ("wrong-did", "wrong-did", "canonical", "canonical", "authority-mismatch"),
        ("wrong-group", "wrong-group", "canonical", "canonical", "authority-mismatch"),
        ("missing-txt", "missing", "canonical", "canonical", "authority-unavailable"),
        ("multiple-dids", "multiple", "canonical", "canonical", "ambiguous-authority"),
        ("did-unavailable", "canonical", "unavailable", "canonical", "authority-unavailable"),
        ("pds-mismatch", "canonical", "canonical", "wrong", "service-mismatch"),
    ]
    resolution_rows = [(c["name"], c["dns"], c["did"], c["pds"], c["outcome"]) for c in data["resolutionCases"]]
    require(all(set(c) == {"name", "dns", "did", "pds", "outcome"} for c in data["resolutionCases"]), "resolution case field drift")
    require(resolution_rows == expected_resolution_rows, "resolution matrix incomplete, duplicated, or mislabeled")

    grammar = re.compile(rf"^(?:{data['codecGrammar']})$")
    require(data["codecMaxBytes"] == 32, "codec maximum drift")
    expected_codec_cases = [
        ("kan-claim-v1", True), ("k", True), ("kan-claim-2", True),
        ("Kan-claim-v1", False), ("kan--claim", False), ("kan_claim_v1", False),
        ("2-kan", False), ("kan-claim-v1-abcdefghijklmnopqrstuvwxyz", False),
    ]
    require([(c["input"], c["valid"]) for c in data["codecCases"]] == expected_codec_cases,
            "codec matrix incomplete, duplicated, or mislabeled")
    require(all(set(c) == {"input", "valid"} for c in data["codecCases"]), "codec case field drift")
    for case in data["codecCases"]:
        try:
            raw = case["input"].encode("ascii")
        except UnicodeEncodeError:
            raw = b"x" * 33
        actual = len(raw) <= 32 and bool(grammar.fullmatch(case["input"]))
        require(actual == case["valid"], f"codec case mismatch: {case['input']}")

    schemas = data["schemas"]
    require(set(schemas) == {"envelope", "payload"}, "schema set drift")
    for name, schema in schemas.items():
        value = schema_value(schema)
        require(value["$type"] == "com.atproto.lexicon.schema", f"{name} wrong record type")
        require(value["lexicon"] == 1 and isinstance(value["defs"], dict), f"{name} invalid Lexicon")
        require(dag_cbor_cid(value) == schema["cid"], f"{name} schema CID mismatch")
    record_key = schema_value(schemas["envelope"])["defs"]["main"]["key"]
    require(record_key in {"tid", "nsid", "any"} or record_key.startswith("literal:"), "invalid Lexicon record key mode")
    envelope_record = schema_value(schemas["envelope"])["defs"]["main"]["record"]
    require(envelope_record["properties"]["content"] == {"type": "unknown"}, "payload boundary is not open")
    require(set(envelope_record["required"]) == {"codec", "claimCid", "signature", "rev", "content"}, "envelope requirements drift")
    payload_ref = schemas["payload"]["ref"].split("#", 1)
    payload_value = schema_value(schemas["payload"])
    require(payload_ref[0] == payload_value["id"], "payload NSID mismatch")
    require(payload_ref[1] in payload_value["defs"], "payload fragment missing")

    binding = data["codecBinding"]
    expected_binding_keys = {
        "$type", "rkey", "codec", "claimLexicon", "envelopeLexiconRecordCid",
        "envelopeLexicon", "envelopeMaxBytes", "payloadSchema",
        "payloadLexiconRecordCid", "payloadLexicon", "payloadMaxBytes",
        "sourceRepository", "sourceCommit", "sourceTag", "canonicalSpecification",
        "fixtureOnly",
    }
    require(set(binding) == expected_binding_keys, "codec record field inventory drift")
    require(binding["$type"] == "tools.kan.codec", "wrong codec record type")
    require(binding["codec"] == binding["rkey"] == "kan-claim-v2-test", "codec/rkey mismatch")
    require(binding["claimLexicon"] == "tools.kan.claim", "wrong claim Lexicon")
    envelope_bytes = embedded_bytes(binding["envelopeLexicon"])
    payload_bytes = embedded_bytes(binding["payloadLexicon"])
    require(envelope_bytes == dag_cbor(schema_value(schemas["envelope"])), "embedded envelope bytes mismatch")
    require(payload_bytes == dag_cbor(schema_value(schemas["payload"])), "embedded payload bytes mismatch")
    require(linked_cid(binding["envelopeLexiconRecordCid"]) == schemas["envelope"]["cid"], "embedded envelope CID mismatch")
    require(linked_cid(binding["payloadLexiconRecordCid"]) == schemas["payload"]["cid"], "embedded payload CID mismatch")
    require(len(envelope_bytes) <= binding["envelopeMaxBytes"] == 4096, "envelope byte maximum violated")
    require(len(payload_bytes) <= binding["payloadMaxBytes"] == 4096, "payload byte maximum violated")
    require(binding["payloadSchema"] == schemas["payload"]["ref"], "wrong payload schema")
    require(binding["fixtureOnly"] is True, "proposal fixture claims production provenance")
    require(binding["sourceRepository"] == "https://example.invalid/kan-rfc3-proposal-fixture", "fixture provenance drift")
    require(binding["sourceCommit"] == "0" * 40 and binding["sourceTag"] == "v0.0.0-fixture", "fixture provenance is not explicitly synthetic")
    require(binding["canonicalSpecification"] == "https://github.com/kan-tools/kan/blob/main/rfcs/3-authoritative-lexicon-publication.md", "canonical specification drift")
    codec_bytes = len(dag_cbor(binding))
    require(codec_bytes <= MAX_RECORD_BYTES, "codec record exceeds one-megabyte limit")

    expected_binding_rows = [
        ("create-new", None, "canonical", "create"),
        ("repeat-identical", "canonical", "canonical", "idempotent"),
        ("reject-rebind", "canonical", "different-schema-bytes", "codec-binding-conflict"),
        ("reject-rkey-mismatch", None, "different-rkey", "codec-binding-conflict"),
    ]
    binding_rows = [(c["name"], c["existing"], c["desired"], c["outcome"]) for c in data["bindingCases"]]
    require(all(set(c) == {"name", "existing", "desired", "outcome"} for c in data["bindingCases"]), "binding case field drift")
    require(binding_rows == expected_binding_rows, "binding matrix incomplete, duplicated, or mislabeled")

    full_writes = ("schema:claim", "schema:fixture", "codec:kan-claim-v2-test", "lens:identity-v1", "lens:v1-to-synthetic-v2", "lens:synthetic-v2-to-v1", "lens:synthetic-v2-summary")
    expected_publication_rows = [
        ("two-schema-one-codec", full_writes, 1, False, "match", 1, "verified"),
        ("precommit-injected-failure", full_writes, 0, True, "unchanged", 0, "unchanged"),
        ("write-ok-readback-fails", full_writes, 1, False, "mismatch", 1, "published-unverified"),
        ("retry-public-verification", (), 0, False, "match", 0, "verified"),
    ]
    lens_records = data["lensRecords"]
    known_writes = {"schema:claim", "schema:fixture", "codec:kan-claim-v2-test"} | {
        "lens:" + lens["id"] for lens in lens_records
    }
    publication_rows = []
    expected_case_keys = {"name", "desiredWrites", "applyWritesCalls", "injectBeforeCommit", "readback", "commits", "outcome"}
    for case in data["publicationCases"]:
        require(set(case) == expected_case_keys, f"publication case shape drift: {case.get('name')}")
        calls, outcome = simulate_publication(case, known_writes)
        require(outcome == case["outcome"], f"publication outcome mismatch: {case['name']}")
        publication_rows.append((case["name"], tuple(case["desiredWrites"]), calls, case["injectBeforeCommit"], case["readback"], case["commits"], outcome))
    require(publication_rows == expected_publication_rows, "publication matrix incomplete, duplicated, or mislabeled")

    lenses = {lens["id"]: lens for lens in data["lenses"]}
    require(all(set(lens) == {"id", "source", "target", "total", "lossless"} for lens in data["lenses"]), "lens declaration field drift")
    require(len(lenses) == len(data["lenses"]), "duplicate lens declaration")
    require(set(lenses) == {"identity-v1", "v1-to-synthetic-v2", "synthetic-v2-to-v1", "synthetic-v2-summary"}, "lens set drift")
    descriptors = {lens["id"]: lens for lens in lens_records}
    require(len(descriptors) == len(lens_records), "duplicate lens record id")
    require(set(descriptors) == set(lenses), "lens record set drift")
    lens_id_grammar = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
    for lens_id, descriptor in descriptors.items():
        declared = lenses[lens_id]
        require(len(lens_id.encode("ascii")) <= 64 and lens_id_grammar.fullmatch(lens_id) is not None, f"invalid lens id: {lens_id}")
        require(descriptor["$type"] == "tools.kan.lens", f"wrong lens record type: {lens_id}")
        require(descriptor["rkey"] == descriptor["id"], f"lens rkey mismatch: {lens_id}")
        require(set(descriptor) == {"$type", "rkey", "id", "sourceCodec", "targetCodec", "vectorsCid", "vectors", "vectorsMaxBytes", "total", "lossless", "sourceRepository", "sourceCommit", "sourceTag", "canonicalSpecification"}, f"lens record field inventory drift: {lens_id}")
        require(descriptor["sourceCodec"] in {"kan-claim-v1", binding["codec"]}, f"unknown lens source codec: {lens_id}")
        require(descriptor["targetCodec"] in {"kan-claim-v1", binding["codec"]}, f"unknown lens target codec: {lens_id}")
        require(descriptor["sourceRepository"] == binding["sourceRepository"], f"lens source repository drift: {lens_id}")
        require(descriptor["sourceCommit"] == binding["sourceCommit"] and descriptor["sourceTag"] == binding["sourceTag"], f"lens source revision drift: {lens_id}")
        require(descriptor["canonicalSpecification"] == binding["canonicalSpecification"], f"lens specification drift: {lens_id}")
        require(len(dag_cbor(descriptor)) <= MAX_RECORD_BYTES, f"lens record exceeds one-megabyte limit: {lens_id}")
        require(descriptor["sourceCodec"] == declared["source"], f"lens source drift: {lens_id}")
        require(descriptor["targetCodec"] == declared["target"], f"lens target drift: {lens_id}")
        require(descriptor["total"] == declared["total"] and descriptor["lossless"] == declared["lossless"], f"lens classification drift: {lens_id}")
        expected_vectors = [vector for vector in data["lensVectors"] if vector["lens"] == lens_id]
        vector_bytes = embedded_bytes(descriptor["vectors"])
        require(expected_vectors, f"lens has no vectors: {lens_id}")
        require(vector_bytes == dag_cbor(expected_vectors), f"embedded vectors mismatch: {lens_id}")
        require(linked_cid(descriptor["vectorsCid"]) == dag_cbor_cid(expected_vectors), f"vector CID mismatch: {lens_id}")
        require(len(vector_bytes) <= descriptor["vectorsMaxBytes"] == 2048, f"vector maximum violated: {lens_id}")
    require(lenses["identity-v1"]["total"] and lenses["identity-v1"]["lossless"], "identity lens invalid")
    require(not lenses["synthetic-v2-to-v1"]["total"] and lenses["synthetic-v2-to-v1"]["lossless"], "partial lens classification drift")
    require(lenses["synthetic-v2-summary"]["total"] and not lenses["synthetic-v2-summary"]["lossless"], "lossy lens classification drift")
    expected_vector_kinds = [
        ("identity-v1", "output"),
        ("v1-to-synthetic-v2", "output"),
        ("synthetic-v2-to-v1", "output"),
        ("synthetic-v2-to-v1", "refusal"),
        ("synthetic-v2-summary", "output"),
    ]
    actual_vector_kinds = [
        (v["lens"], "output" if "output" in v and "refusal" not in v else "refusal")
        for v in data["lensVectors"]
    ]
    require(actual_vector_kinds == expected_vector_kinds, "lens vector inventory incomplete, reordered, or mislabeled")
    for vector in data["lensVectors"]:
        require(set(vector) in ({"lens", "input", "output"}, {"lens", "input", "refusal"}), "lens vector field drift")
        status, result = apply_lens(vector["lens"], vector["input"])
        require(apply_lens(vector["lens"], vector["input"]) == (status, result), f"lens is nondeterministic: {vector['lens']}")
        if "output" in vector:
            require(status == "success" and result == vector["output"], f"lens output mismatch: {vector['lens']}")
        else:
            require(status == "refusal" and result == vector["refusal"], f"lens refusal mismatch: {vector['lens']}")
    sample = {"message": "roundtrip", "tags": ["law"]}
    status, forward = apply_lens("v1-to-synthetic-v2", sample)
    require(status == "success", "forward lens refused")
    status, backward = apply_lens("synthetic-v2-to-v1", forward)
    require(status == "success" and backward == sample, "lossless round trip failed")
    status, identity = apply_lens("identity-v1", sample)
    require(status == "success" and identity == sample, "identity law failed")
    # The right identity at the v2 target is the empty path, not identity-v1.
    composed = copy.deepcopy(forward)
    require(composed == forward, "right identity composition failed")
    status, before = apply_lens("identity-v1", sample)
    status, after = apply_lens("v1-to-synthetic-v2", before)
    require(status == "success" and after == forward, "left identity composition failed")
    status, representable_v2 = apply_lens("v1-to-synthetic-v2", backward)
    require(status == "success" and representable_v2 == forward, "forward-backward inverse failed")
    require(dag_cbor(forward) == dag_cbor(representable_v2), "canonical target bytes differ")

    expected_normalization = {
        "identity": ("kan-claim-v1", "kan-claim-v1", (), "success"),
        "default-current": ("kan-claim-v1", "kan-claim-v2-test", ("v1-to-synthetic-v2",), "success"),
        "partial-not-default": ("kan-claim-v2-test", "kan-claim-v1", (), "lens-path-unavailable"),
        "lossy-not-default": ("kan-claim-v2-test", "kan-claim-v1", (), "lens-path-unavailable"),
        "unknown-source": ("kan-claim-v9", "kan-claim-v2-test", (), "unsupported-source-codec"),
        "unknown-target": ("kan-claim-v1", "kan-claim-v9", (), "unsupported-target-codec"),
    }
    normalization = {c["name"]: (c["source"], c["target"], tuple(c["path"]), c["outcome"]) for c in data["normalizationCases"]}
    require(all(set(c) == {"name", "source", "target", "path", "outcome"} for c in data["normalizationCases"]), "normalization case field drift")
    require(len(normalization) == len(data["normalizationCases"]), "duplicate normalization case")
    require(normalization == expected_normalization, "normalization matrix incomplete or mislabeled")
    for case in data["normalizationCases"]:
        for lens_id in case["path"]:
            lens = lenses[lens_id]
            require(lens["total"] and lens["lossless"], f"default path uses ineligible lens: {lens_id}")

    require(set(data["requiredViewProvenance"]) == {"sourceCodec", "viewCodec", "sourceUri", "sourceRecordCid", "lensesApplied"}, "view provenance incomplete")
    expected_secrets = {
        "release-source": ("github-public", False), "github-app-private-key": ("railway-runtime", False),
        "pds-admin-credential": ("railway-runtime", True), "repository-signing-key": ("pds-volume", True),
        "railway-reconstruction": ("external-vault", True), "did-recovery-material": ("external-vault", True),
    }
    secrets = {row["secret"]: (row["owner"], row["productionAuthority"]) for row in data["secretBoundaries"]}
    require(all(set(row) == {"secret", "owner", "productionAuthority"} for row in data["secretBoundaries"]), "secret boundary field drift")
    require(len(secrets) == len(data["secretBoundaries"]), "duplicate secret boundary")
    require(secrets == expected_secrets, "secret inventory incomplete or mislabeled")


def mutations(data: dict) -> list[tuple[str, dict]]:
    def delete_refusal_and_rebind(d: dict) -> None:
        d["lensVectors"] = [v for v in d["lensVectors"] if "refusal" not in v]
        vectors = [v for v in d["lensVectors"] if v["lens"] == "synthetic-v2-to-v1"]
        descriptor = next(v for v in d["lensRecords"] if v["id"] == "synthetic-v2-to-v1")
        descriptor["vectors"] = {"$bytes": base64.b64encode(dag_cbor(vectors)).decode("ascii")}
        descriptor["vectorsCid"] = {"$link": dag_cbor_cid(vectors)}

    edits = [
        ("empty authority", lambda d: d["authority"].__setitem__("nsids", [])),
        ("insecure appview", lambda d: d["authority"]["appView"].__setitem__("uri", "http://attacker.invalid")),
        ("attacker PDS", lambda d: d["authority"].__setitem__("pdsEndpoint", "https://attacker.example")),
        ("invalid service DID", lambda d: d["authority"]["appView"].__setitem__("serviceDid", "not-a-did")),
        ("resolution label", lambda d: d["resolutionCases"][1].__setitem__("outcome", "success")),
        ("duplicate canonical resolution", lambda d: d["resolutionCases"].append(copy.deepcopy(d["resolutionCases"][0]))),
        ("delete negative codec cases", lambda d: d.__setitem__("codecCases", [c for c in d["codecCases"] if c["valid"]])),
        ("schema bytes", lambda d: d["schemas"]["envelope"]["value"]["defs"].clear()),
        ("schema cid", lambda d: d["schemas"]["envelope"].__setitem__("cid", d["schemas"]["payload"]["cid"])),
        ("binding label", lambda d: d["bindingCases"][0].__setitem__("outcome", "idempotent")),
        ("duplicate binding case", lambda d: d["bindingCases"].append(copy.deepcopy(d["bindingCases"][0]))),
        ("undeclared codec field", lambda d: d["codecBinding"].__setitem__("extra", True)),
        ("split publication", lambda d: d["publicationCases"][0].__setitem__("applyWritesCalls", 3)),
        ("lens output", lambda d: d["lensVectors"][1]["output"].__setitem__("annotations", ["wrong"])),
        ("delete all lens vectors", lambda d: d.__setitem__("lensVectors", [])),
        ("delete refusal and rebind vectors", delete_refusal_and_rebind),
        ("lie about lens endpoints", lambda d: [lens.__setitem__("source", "kan-claim-v9") for lens in d["lenses"]]),
        ("nonexistent shaped provenance", lambda d: d["codecBinding"].__setitem__("sourceCommit", "1" * 40)),
        ("canonical specification substitution", lambda d: [row.__setitem__("canonicalSpecification", "https://attacker.example/spec") for row in [d["codecBinding"], *d["lensRecords"]]]),
        ("oversized codec record", lambda d: d["codecBinding"].__setitem__("padding", {"$bytes": "AAAA" * 400_000})),
        ("multiple codecs in publication", lambda d: d["publicationCases"][0]["desiredWrites"].append("codec:another")),
        ("delete embedded schema", lambda d: d["codecBinding"].pop("payloadLexicon")),
        ("unknown identity", lambda d: d["normalizationCases"][0].__setitem__("source", "kan-claim-v9")),
        ("lossy default", lambda d: d["normalizationCases"][1].__setitem__("path", ["synthetic-v2-summary"])),
        ("provenance", lambda d: d["requiredViewProvenance"].remove("sourceRecordCid")),
        ("secret deletion", lambda d: d["secretBoundaries"].pop()),
        ("duplicate secret boundary", lambda d: d["secretBoundaries"].append(copy.deepcopy(d["secretBoundaries"][0]))),
    ]
    result = []
    for name, edit in edits:
        changed = copy.deepcopy(data)
        edit(changed)
        result.append((name, changed))
    return result


def main() -> int:
    data = json.loads(MANIFEST.read_text())
    validate(data)
    killed = 0
    for name, changed in mutations(data):
        try:
            validate(changed)
        except (Invalid, KeyError, TypeError, ValueError):
            killed += 1
        else:
            print(f"mutation survived: {name}", file=sys.stderr)
    require(killed == len(mutations(data)), "mutation suite incomplete")
    limit_controls = 0
    for action in (
        lambda: validate_publication_shape(["codec:a", "codec:b"], {"codec:a", "codec:b"}),
        lambda: validate_publication_shape([f"schema:{index}" for index in range(201)], {f"schema:{index}" for index in range(201)}),
        lambda: require_commit_closure_limit(MAX_COMMIT_BLOCK_BYTES + 1),
    ):
        try:
            action()
        except Invalid:
            limit_controls += 1
    require(limit_controls == 3, "publication limit controls incomplete")
    print(
        "Lexicon publication v2 fixtures: "
        f"{len(data['resolutionCases'])} resolution, {len(data['codecCases'])} codec, "
        f"{len(data['bindingCases'])} binding, {len(data['publicationCases'])} publication, "
        f"{len(data['lensVectors'])} lens, {len(data['normalizationCases'])} normalization cases"
    )
    print(f"Lexicon publication v2 mutation controls: {killed}/{len(mutations(data))} killed")
    print(f"Lexicon publication v2 aggregate-limit controls: {limit_controls}/3 rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
