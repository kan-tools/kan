#!/usr/bin/env python3
"""Structural, implementation-independent checks for RFC 2's URI v1 vectors."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from uri_v1_reference import discover_appview, parse_uri, resolve_uri


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path(os.environ.get("KAN_URI_V1_MANIFEST", ROOT / "tests/fixtures/uri-v1/manifest.json"))


def fail(message: str) -> None:
    raise SystemExit(f"URI v1 fixture check failed: {message}")


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {path.relative_to(ROOT)}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain one JSON object")
    return value


def contains(actual: object, expected: object) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(key in actual and contains(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return actual == expected
    return actual == expected


manifest = load(MANIFEST)
if manifest.get("v") != 1:
    fail("manifest v must be 1")

if manifest.get("lexiconSource") != {
    "repository": "https://github.com/kan-tools/kan-lexicon",
    "revision": "21223656d9954f93d4dc5b0a16c144b6bce1902c",
    "root": "lexicons/tools/kan",
    "snapshots": ".design/rfc-2-lexicons",
}:
    fail("lexiconSource must name the canonical kan-tools/kan-lexicon boundary")

spec = ROOT / manifest.get("spec", "")
if not spec.is_file():
    fail("spec path does not exist")

sources_path = ROOT / manifest.get("sources", "")
sources = load(sources_path).get("fixtures")
if not isinstance(sources, dict) or not sources:
    fail("sources file must contain a non-empty fixtures object")

expected_lexicons = {
    "tools.kan.claim",
    "tools.kan.defs",
    "tools.kan.getClaim",
    "tools.kan.getSubject",
    "tools.kan.getIdentity",
}
seen_lexicons: set[str] = set()
for relative in manifest.get("lexicons", []):
    path = ROOT / relative
    schema = load(path)
    nsid = schema.get("id")
    if nsid in seen_lexicons:
        fail(f"duplicate Lexicon id {nsid}")
    seen_lexicons.add(nsid)
if seen_lexicons != expected_lexicons:
    fail(f"Lexicon ids differ: {sorted(seen_lexicons ^ expected_lexicons)}")

families = manifest.get("mandatoryFamilies")
if not isinstance(families, list) or len(families) != 22 or len(set(families)) != 22:
    fail("mandatoryFamilies must contain 22 unique values")

vectors = manifest.get("vectors")
if not isinstance(vectors, list) or not vectors:
    fail("vectors must be a non-empty array")

ids: set[str] = set()
covered: set[str] = set()
failures: set[str] = set()
resolution_successes = 0
for index, vector in enumerate(vectors):
    if not isinstance(vector, dict):
        fail(f"vector {index} is not an object")
    vector_id = vector.get("id")
    if not isinstance(vector_id, str) or not vector_id:
        fail(f"vector {index} has no id")
    if vector_id in ids:
        fail(f"duplicate vector id {vector_id}")
    ids.add(vector_id)

    vector_families = vector.get("covers")
    if not isinstance(vector_families, list) or not vector_families:
        fail(f"{vector_id} covers no mandatory family")
    unknown = set(vector_families) - set(families)
    if unknown:
        fail(f"{vector_id} covers unknown families {sorted(unknown)}")
    covered.update(vector_families)

    phase = vector.get("phase")
    if phase not in {"parse", "resolution", "safety"}:
        fail(f"{vector_id} has invalid phase {phase!r}")
    if not isinstance(vector.get("input"), str) or not vector["input"]:
        fail(f"{vector_id} has no input URI")

    expected = vector.get("expect")
    if not isinstance(expected, dict):
        fail(f"{vector_id} has no expected object")
    outcome = expected.get("outcome")
    if phase == "parse":
        actual = parse_uri(vector["input"])
        if not contains(actual, expected):
            fail(
                f"{vector_id} executable parse mismatch:\n"
                f"  expected {json.dumps(expected, ensure_ascii=False, sort_keys=True)}\n"
                f"  actual   {json.dumps(actual, ensure_ascii=False, sort_keys=True)}"
            )
    elif phase == "resolution":
        source_fixture = vector.get("sourceFixture")
        request, actual = resolve_uri(vector["input"], sources.get(source_fixture) if source_fixture else None)
        if not contains(actual, expected):
            fail(
                f"{vector_id} executable resolution mismatch:\n"
                f"  expected {json.dumps(expected, ensure_ascii=False, sort_keys=True)}\n"
                f"  actual   {json.dumps(actual, ensure_ascii=False, sort_keys=True)}"
            )
        if request != vector.get("request"):
            fail(
                f"{vector_id} transport request mismatch:\n"
                f"  expected {json.dumps(vector.get('request'), ensure_ascii=False, sort_keys=True)}\n"
                f"  actual   {json.dumps(request, ensure_ascii=False, sort_keys=True)}"
            )
    elif phase == "safety":
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "sentinel"
            sentinel.write_text("unchanged", encoding="utf-8")
            before_files = {path.name: path.read_bytes() for path in Path(directory).iterdir()}
            before_environment = dict(os.environ)
            before_cwd = Path.cwd()
            actual = parse_uri(vector["input"])
            _, resolved = resolve_uri(
                "kan+at://alice.example/kan-tools:day/subject/x",
                sources["at-current-equivalent"],
            )
            discovered = discover_appview(
                "did:web:kan.tools",
                {
                    "id": "did:web:kan.tools",
                    "service": [{
                        "id": "#kan_appview",
                        "type": "KanAppView",
                        "serviceEndpoint": "https://appview.kan.tools",
                    }],
                },
            )
            after_files = {path.name: path.read_bytes() for path in Path(directory).iterdir()}
            if any(result.get("outcome") != "success" for result in (actual, resolved, discovered)):
                fail(f"{vector_id} safety probe did not parse, resolve, and discover successfully")
            if before_files != after_files or before_environment != dict(os.environ) or before_cwd != Path.cwd():
                fail(f"{vector_id} parser caused a filesystem, environment, or working-directory side effect")
    if outcome == "failure":
        failure = expected.get("failure")
        if not isinstance(failure, str) or not failure:
            fail(f"{vector_id} has no exact failure")
        failures.add(failure)
    elif outcome == "success":
        if phase == "parse":
            for field in ("canonical", "scheme", "authority", "resource", "evidence", "evaluation"):
                if field not in expected:
                    fail(f"{vector_id} parse success lacks {field}")
        elif phase == "resolution":
            resolution_successes += 1
            if "sourceFixture" not in vector:
                fail(f"{vector_id} resolution success lacks sourceFixture")
            if "request" not in vector:
                fail(f"{vector_id} resolution success lacks exact transport request")
            for field in ("canonical", "commit", "immutableReplay", "claimCids"):
                if field not in expected:
                    fail(f"{vector_id} resolution success lacks {field}")
        else:
            effects = expected.get("forbiddenEffects")
            if not isinstance(effects, list) or len(effects) != 6:
                fail(f"{vector_id} safety result must name six forbidden effects")
    else:
        fail(f"{vector_id} has invalid outcome {outcome!r}")

    source_fixture = vector.get("sourceFixture")
    if source_fixture is not None and source_fixture not in sources:
        fail(f"{vector_id} names unknown source fixture {source_fixture}")

missing_families = set(families) - covered
if missing_families:
    fail(f"mandatory families uncovered: {sorted(missing_families)}")

stable_failures = {
    "malformed-uri",
    "unsupported-scheme",
    "userinfo-forbidden",
    "credential-in-userinfo",
    "fragment-not-supported",
    "invalid-percent-encoding",
    "invalid-utf8",
    "invalid-path-segment",
    "encoded-separator",
    "non-canonical-identifier",
    "unsupported-parameter",
    "duplicate-parameter",
    "inapplicable-parameter",
    "conflicting-snapshot-selectors",
    "evaluation-time-required",
    "authority-not-found",
    "authority-identity-unknown",
    "authority-identity-unsupported",
    "scope-not-found",
    "ambiguous-scope-locator",
    "source-not-found",
    "access-denied",
    "snapshot-unavailable",
    "resource-not-found-at-snapshot",
}
missing_failures = stable_failures - failures
if missing_failures:
    fail(f"stable failures uncovered: {sorted(missing_failures)}")

equivalent = sources.get("at-current-equivalent", {})
appview_claims = equivalent.get("appview", {}).get("claimCids")
pds_claims = equivalent.get("pds", {}).get("claimCids")
if not appview_claims or appview_claims != pds_claims:
    fail("AT AppView/PDS equivalence fixture does not carry identical claim evidence")
if equivalent.get("appview", {}).get("completeness") == equivalent.get("pds", {}).get("completeness"):
    fail("AT AppView/PDS fixture does not distinguish source provenance")

if resolution_successes < 3:
    fail("expected at least three complete resolution successes")

discovery_vectors = manifest.get("serviceDiscoveryVectors")
if not isinstance(discovery_vectors, list) or len(discovery_vectors) < 7:
    fail("serviceDiscoveryVectors must contain at least seven hostile/positive cases")
discovery_ids: set[str] = set()
for vector in discovery_vectors:
    vector_id = vector.get("id")
    if not isinstance(vector_id, str) or not vector_id or vector_id in discovery_ids:
        fail(f"invalid or duplicate service-discovery id {vector_id!r}")
    discovery_ids.add(vector_id)
    actual = discover_appview(vector.get("namespaceDid"), vector.get("document"))
    expected = vector.get("expect")
    if actual != expected:
        fail(
            f"{vector_id} service-discovery mismatch:\n"
            f"  expected {json.dumps(expected, ensure_ascii=False, sort_keys=True)}\n"
            f"  actual   {json.dumps(actual, ensure_ascii=False, sort_keys=True)}"
        )

print(
    f"URI v1 fixtures: {len(vectors)} URI vectors, {len(discovery_vectors)} service-discovery vectors, {len(covered)}/22 families, "
    f"{len(stable_failures)}/{len(stable_failures)} stable failures"
)

if "--self-test" in sys.argv:
    mutations = []

    changed = json.loads(json.dumps(manifest))
    changed["vectors"][0]["expect"]["canonical"] += "-corrupt"
    mutations.append(("canonical output", changed))

    changed = json.loads(json.dumps(manifest))
    resolution = next(vector for vector in changed["vectors"] if vector.get("request"))
    resolution["request"]["nsid"] = "tools.kan.wrongMethod"
    mutations.append(("transport request", changed))

    changed = json.loads(json.dumps(manifest))
    changed["mandatoryFamilies"].pop()
    mutations.append(("mandatory family", changed))

    changed = json.loads(json.dumps(manifest))
    changed["serviceDiscoveryVectors"][0]["expect"]["endpoint"] = "https://attacker.example"
    mutations.append(("service discovery", changed))

    with tempfile.TemporaryDirectory() as directory:
        for name, changed in mutations:
            path = Path(directory) / f"{name.replace(' ', '-')}.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            environment = dict(os.environ)
            environment["KAN_URI_V1_MANIFEST"] = str(path)
            result = subprocess.run(
                [sys.executable, str(Path(__file__).resolve())],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode == 0:
                fail(f"negative control survived {name} mutation")
    print(f"URI v1 fixture negative controls: {len(mutations)}/{len(mutations)} mutations killed")
