#!/usr/bin/env python3
"""Structural and mutation checks for RFC 3 publication vectors."""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/fixtures/lexicon-publication-v1/manifest.json"


class Invalid(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def validate(data: dict) -> None:
    require(data.get("version") == 1, "version must be 1")

    authority = data["authority"]
    require(authority["dnsName"] == "_lexicon.kan.tools", "wrong DNS name")
    require(authority["dnsValue"] == "did=did:web:kan.tools", "wrong DNS value")
    require(authority["did"] == "did:web:kan.tools", "wrong authority DID")
    require(
        authority["didUrl"] == "https://kan.tools/.well-known/did.json",
        "wrong did:web URL",
    )
    require(authority["appView"]["serviceDid"] != authority["did"], "service DID must be separate")
    for nsid in authority["nsids"]:
        parts = nsid.split(".")
        require(len(parts) >= 3, f"invalid NSID: {nsid}")
        derived = "_lexicon." + ".".join(reversed(parts[:-1]))
        require(derived == authority["dnsName"], f"authority drift: {nsid}")

    grammar = re.compile(rf"^(?:{data['codecGrammar']})$")
    require(data["codecMaxBytes"] == 32, "codec maximum drift")
    for case in data["codecCases"]:
        actual = len(case["input"].encode("ascii", errors="ignore")) <= 32 and bool(
            grammar.fullmatch(case["input"])
        )
        require(actual == case["valid"], f"codec case mismatch: {case['input']}")

    binding = data["codecBinding"]
    require(binding["$type"] == "tools.kan.codec", "wrong codec record type")
    require(binding["codec"] == binding["rkey"], "codec/rkey mismatch")
    require(binding["claimLexicon"] == "tools.kan.claim", "wrong claim Lexicon")
    require(
        binding["payloadSchema"] == "tools.kan.defs#claimContent",
        "wrong v1 payload schema",
    )
    require(
        binding["envelopeLexiconRecordCid"] != binding["payloadLexiconRecordCid"],
        "envelope and payload CIDs unexpectedly alias",
    )
    require(re.fullmatch(r"[0-9a-f]{40}", binding["sourceCommit"]) is not None, "bad source commit")
    require(binding["sourceTag"].startswith("v"), "source tag must be a release tag")

    expected_binding_outcomes = {
        "create",
        "idempotent",
        "codec-binding-conflict",
    }
    binding_names = {case["name"] for case in data["bindingCases"]}
    require(
        binding_names == {"create-new", "repeat-identical", "reject-rebind", "reject-rkey-mismatch"},
        "binding matrix incomplete",
    )
    require(
        all(case["outcome"] in expected_binding_outcomes for case in data["bindingCases"]),
        "unknown binding outcome",
    )

    publication = {case["name"]: case for case in data["publicationCases"]}
    require(
        publication["staged-schema-atomic-activation"]["commits"] == 2
        and publication["staged-schema-atomic-activation"]["activationCommits"] == 1,
        "publication does not stage then activate",
    )
    require(
        publication["activation-injected-failure"]["commits"] == 1
        and publication["activation-injected-failure"]["activationCommits"] == 0
        and publication["activation-injected-failure"]["codecCreates"] == 0,
        "failed activation made a codec resolvable",
    )
    require(
        publication["write-ok-readback-fails"]["outcome"] == "published-unverified",
        "read-back failure declared deployed",
    )
    require(
        publication["retry-public-verification"]["schemaWrites"] == 0
        and publication["retry-public-verification"]["commits"] == 0,
        "verification retry rewrites records",
    )

    lenses = {lens["id"]: lens for lens in data["lenses"]}
    require(lenses["identity-v1"]["total"] and lenses["identity-v1"]["lossless"], "identity lens invalid")
    require(
        not lenses["synthetic-v2-to-v1"]["total"]
        and lenses["synthetic-v2-to-v1"]["lossless"],
        "partial lens classification drift",
    )
    require(
        lenses["synthetic-v2-summary"]["total"]
        and not lenses["synthetic-v2-summary"]["lossless"],
        "lossy lens classification drift",
    )
    for case in data["normalizationCases"]:
        for lens_id in case["path"]:
            lens = lenses[lens_id]
            require(lens["total"] and lens["lossless"], f"default path uses ineligible lens: {lens_id}")

    require(
        set(data["requiredViewProvenance"])
        == {"sourceCodec", "viewCodec", "sourceUri", "sourceRecordCid", "lensesApplied"},
        "view provenance incomplete",
    )

    secrets = data["secretBoundaries"]
    require(
        not any(row["owner"] == "github-public" and row["productionAuthority"] for row in secrets),
        "public GitHub owns a production secret",
    )
    require(
        {row["owner"] for row in secrets if row["productionAuthority"]}
        == {"railway-runtime", "pds-volume", "external-vault"},
        "production secret ownership drift",
    )


def mutations(data: dict) -> list[tuple[str, dict]]:
    result: list[tuple[str, dict]] = []
    for name, edit in [
        ("authority", lambda d: d["authority"].__setitem__("dnsName", "_lexicon.tools.kan")),
        ("codec binding", lambda d: d["codecBinding"].__setitem__("payloadSchema", "tools.kan.defs#claimContentV2")),
        ("atomic activation", lambda d: d["publicationCases"][1].__setitem__("codecCreates", 1)),
        ("lens eligibility", lambda d: d["normalizationCases"][1].__setitem__("path", ["synthetic-v2-summary"])),
        ("provenance", lambda d: d["requiredViewProvenance"].remove("sourceRecordCid")),
        ("secret boundary", lambda d: d["secretBoundaries"][0].__setitem__("productionAuthority", True)),
    ]:
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
        except Invalid:
            killed += 1
        else:
            raise Invalid(f"mutation accepted: {name}")
    print(
        "Lexicon publication v1 fixtures: "
        f"{len(data['codecCases'])} codec cases, "
        f"{len(data['bindingCases'])} binding cases, "
        f"{len(data['publicationCases'])} publication cases, "
        f"{len(data['normalizationCases'])} normalization cases"
    )
    print(f"Lexicon publication v1 mutation controls: {killed}/{len(mutations(data))} killed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Invalid, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"LEXICON PUBLICATION FIXTURE CHECK FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
