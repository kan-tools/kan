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


def validate(data: dict) -> None:
    require(data.get("version") == 2, "version must be 2")

    authority = data["authority"]
    expected_nsids = {
        "tools.kan.claim", "tools.kan.codec", "tools.kan.defs",
        "tools.kan.getClaim", "tools.kan.getIdentity", "tools.kan.getSubject",
    }
    require(set(authority["nsids"]) == expected_nsids, "authoritative NSID set drift")
    require(len(authority["nsids"]) == len(expected_nsids), "duplicate authoritative NSID")
    require(authority["dnsName"] == "_lexicon.kan.tools", "wrong DNS name")
    require(authority["dnsValue"] == "did=did:web:kan.tools", "wrong DNS value")
    require(authority["did"] == "did:web:kan.tools", "wrong authority DID")
    require(authority["didUrl"] == "https://kan.tools/.well-known/did.json", "wrong did:web URL")
    require(https_origin(authority["pdsEndpoint"]), "PDS endpoint is not HTTPS")
    appview = authority["appView"]
    require(appview["serviceDid"] != authority["did"], "service DID must be separate")
    require(appview["serviceId"] == authority["did"] + "#kan_appview", "wrong service id")
    require(appview["serviceType"] == "KanAppView", "wrong service type")
    require(https_origin(appview["uri"]), "AppView endpoint is not an HTTPS origin")
    for nsid in authority["nsids"]:
        parts = nsid.split(".")
        require(len(parts) >= 3, f"invalid NSID: {nsid}")
        require("_lexicon." + ".".join(reversed(parts[:-1])) == authority["dnsName"], f"authority drift: {nsid}")

    expected_resolution = {
        "canonical": "success", "wrong-did": "authority-mismatch",
        "wrong-group": "authority-mismatch", "missing-txt": "authority-unavailable",
        "multiple-dids": "ambiguous-authority", "did-unavailable": "authority-unavailable",
        "pds-mismatch": "service-mismatch",
    }
    resolution = {case["name"]: case["outcome"] for case in data["resolutionCases"]}
    require(resolution == expected_resolution, "resolution matrix incomplete or mislabeled")

    grammar = re.compile(rf"^(?:{data['codecGrammar']})$")
    require(data["codecMaxBytes"] == 32, "codec maximum drift")
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
    envelope_record = schema_value(schemas["envelope"])["defs"]["main"]["record"]
    require(envelope_record["properties"]["content"] == {"type": "unknown"}, "payload boundary is not open")
    require(set(envelope_record["required"]) == {"codec", "claimCid", "signature", "rev", "content"}, "envelope requirements drift")
    payload_ref = schemas["payload"]["ref"].split("#", 1)
    payload_value = schema_value(schemas["payload"])
    require(payload_ref[0] == payload_value["id"], "payload NSID mismatch")
    require(payload_ref[1] in payload_value["defs"], "payload fragment missing")

    binding = data["codecBinding"]
    require(binding["$type"] == "tools.kan.codec", "wrong codec record type")
    require(binding["codec"] == binding["rkey"] == "kan-claim-v1", "codec/rkey mismatch")
    require(binding["claimLexicon"] == "tools.kan.claim", "wrong claim Lexicon")
    require(binding["envelopeSchema"] == "envelope", "wrong embedded envelope")
    require(binding["payloadSchema"] == schemas["payload"]["ref"], "wrong payload schema")
    require(binding["payloadSchemaRecord"] == "payload", "wrong embedded payload")
    require(https_origin(binding["sourceRepository"]), "source repository is not HTTPS")
    require(re.fullmatch(r"[0-9a-f]{40}", binding["sourceCommit"]) is not None, "bad source commit")
    require(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", binding["sourceTag"]) is not None, "bad source tag")
    require(https_origin(binding["canonicalSpecification"]), "canonical specification is not HTTPS")

    expected_binding = {
        "create-new": "create", "repeat-identical": "idempotent",
        "reject-rebind": "codec-binding-conflict", "reject-rkey-mismatch": "codec-binding-conflict",
    }
    require({c["name"]: c["outcome"] for c in data["bindingCases"]} == expected_binding, "binding matrix incomplete or mislabeled")

    expected_publication = {
        "two-schema-one-codec": (2, 1, 1, "verified"),
        "precommit-injected-failure": (0, 0, 0, "unchanged"),
        "write-ok-readback-fails": (2, 1, 1, "published-unverified"),
        "retry-public-verification": (0, 0, 0, "verified"),
    }
    publication = {c["name"]: (c["schemaWrites"], c["codecCreates"], c["commits"], c["outcome"]) for c in data["publicationCases"]}
    require(publication == expected_publication, "publication matrix incomplete or mislabeled")

    lenses = {lens["id"]: lens for lens in data["lenses"]}
    require(set(lenses) == {"identity-v1", "v1-to-synthetic-v2", "synthetic-v2-to-v1", "synthetic-v2-summary"}, "lens set drift")
    require(set(binding["fromLenses"]) == {"identity-v1", "v1-to-synthetic-v2"}, "binding lens set drift")
    require(lenses["identity-v1"]["total"] and lenses["identity-v1"]["lossless"], "identity lens invalid")
    require(not lenses["synthetic-v2-to-v1"]["total"] and lenses["synthetic-v2-to-v1"]["lossless"], "partial lens classification drift")
    require(lenses["synthetic-v2-summary"]["total"] and not lenses["synthetic-v2-summary"]["lossless"], "lossy lens classification drift")
    for vector in data["lensVectors"]:
        status, result = apply_lens(vector["lens"], vector["input"])
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

    expected_normalization = {
        "identity": ("kan-claim-v1", "kan-claim-v1", (), "success"),
        "default-current": ("kan-claim-v1", "kan-claim-v2-test", ("v1-to-synthetic-v2",), "success"),
        "partial-not-default": ("kan-claim-v2-test", "kan-claim-v1", (), "lens-path-unavailable"),
        "lossy-not-default": ("kan-claim-v2-test", "kan-claim-v1", (), "lens-path-unavailable"),
        "unknown-source": ("kan-claim-v9", "kan-claim-v2-test", (), "unsupported-source-codec"),
        "unknown-target": ("kan-claim-v1", "kan-claim-v9", (), "unsupported-target-codec"),
    }
    normalization = {c["name"]: (c["source"], c["target"], tuple(c["path"]), c["outcome"]) for c in data["normalizationCases"]}
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
    require(secrets == expected_secrets, "secret inventory incomplete or mislabeled")


def mutations(data: dict) -> list[tuple[str, dict]]:
    edits = [
        ("empty authority", lambda d: d["authority"].__setitem__("nsids", [])),
        ("insecure appview", lambda d: d["authority"]["appView"].__setitem__("uri", "http://attacker.invalid")),
        ("resolution label", lambda d: d["resolutionCases"][1].__setitem__("outcome", "success")),
        ("schema bytes", lambda d: d["schemas"]["envelope"]["value"]["defs"].clear()),
        ("schema cid", lambda d: d["schemas"]["envelope"].__setitem__("cid", d["schemas"]["payload"]["cid"])),
        ("binding label", lambda d: d["bindingCases"][0].__setitem__("outcome", "idempotent")),
        ("zero schema publication", lambda d: d["publicationCases"][0].__setitem__("schemaWrites", 0)),
        ("lens output", lambda d: d["lensVectors"][1]["output"].__setitem__("annotations", ["wrong"])),
        ("unknown identity", lambda d: d["normalizationCases"][0].__setitem__("source", "kan-claim-v9")),
        ("lossy default", lambda d: d["normalizationCases"][1].__setitem__("path", ["synthetic-v2-summary"])),
        ("provenance", lambda d: d["requiredViewProvenance"].remove("sourceRecordCid")),
        ("secret deletion", lambda d: d["secretBoundaries"].pop()),
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
    print(
        "Lexicon publication v2 fixtures: "
        f"{len(data['resolutionCases'])} resolution, {len(data['codecCases'])} codec, "
        f"{len(data['bindingCases'])} binding, {len(data['publicationCases'])} publication, "
        f"{len(data['lensVectors'])} lens, {len(data['normalizationCases'])} normalization cases"
    )
    print(f"Lexicon publication v2 mutation controls: {killed}/{len(mutations(data))} killed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
