#!/usr/bin/env python3
"""Clean-room executable reference semantics for RFC 2 URI-v1 fixtures."""

from __future__ import annotations

import re
import base64
import json
import math
from urllib.parse import quote, unquote_to_bytes, urlsplit


FAILURE = "failure"
SUCCESS = "success"
SCHEMES = {"kan", "kan+git", "kan+at"}
QUERY_NAMES = {"source", "service", "commit", "ref", "snapshot", "version", "trust", "at"}
QUERY_ORDER = {"source": 0, "service": 1, "commit": 2, "ref": 2, "snapshot": 2, "version": 3, "trust": 4, "at": 5}
SEGMENT_SAFE = "-._~!$&'()*+,;=:@"
QUERY_SAFE = "-._~!$'()*+,;=:@/?"


def failure(name: str) -> dict:
    return {"outcome": FAILURE, "failure": name}


def decode_component(raw: str, *, segment: bool) -> tuple[str | None, str | None]:
    for match in re.finditer("%", raw):
        if not re.fullmatch(r"[0-9A-Fa-f]{2}", raw[match.start() + 1 : match.start() + 3]):
            return None, "invalid-percent-encoding"
    try:
        value = unquote_to_bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        return None, "invalid-utf8"
    if "\x00" in value:
        return None, "invalid-path-segment" if segment else "malformed-uri"
    if segment and "/" in value:
        return None, "encoded-separator"
    if segment and value in {"", ".", ".."}:
        return None, "invalid-path-segment"
    return value, None


def canonical_segment(value: str) -> str:
    return quote(value, safe=SEGMENT_SAFE, encoding="utf-8", errors="strict")


def canonical_query(value: str) -> str:
    return quote(value, safe=QUERY_SAFE, encoding="utf-8", errors="strict")


def canonical_trust_selector(value: str) -> tuple[str | None, str | None]:
    value = value.strip()
    if not value or value.startswith("@") or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None, "invalid-selector"
    name, separator, raw_weight = value.partition("=")
    name = name.strip()
    if separator:
        try:
            weight = float(raw_weight.strip())
        except ValueError:
            return None, "invalid-selector"
        if not math.isfinite(weight) or not 0 <= weight <= 1:
            return None, "invalid-selector"
        canonical_weight = "0" if weight == 0 else "1" if weight == 1 else repr(weight)
    else:
        canonical_weight = "1"

    weighted = name == "me" or name.startswith("role:") or name.startswith("did:")
    if name.startswith("role:") and not name.removeprefix("role:"):
        return None, "invalid-selector"
    if name.startswith("did:"):
        parts = name.split(":", 2)
        if len(parts) != 3 or not re.fullmatch(r"[a-z]+", parts[1]) or not parts[2]:
            return None, "non-canonical-identifier"
    if not weighted and separator:
        return None, "invalid-selector"
    if canonical_weight == "1":
        return name, None
    return f"{name}={canonical_weight}", None


def canonical_trust(value: str) -> tuple[str | None, str | None]:
    if not value.startswith("@set:"):
        return canonical_trust_selector(value)
    try:
        members = json.loads(value.removeprefix("@set:"))
    except json.JSONDecodeError:
        return None, "invalid-selector"
    if not isinstance(members, list) or len(members) < 2 or not all(isinstance(member, str) for member in members):
        return None, "invalid-selector"
    canonical: list[str] = []
    for member in members:
        selector, error = canonical_trust_selector(member)
        if error:
            return None, error
        if selector in canonical:
            return None, "duplicate-parameter"
        canonical.append(selector or "")
    return "@set:" + json.dumps(canonical, ensure_ascii=False, separators=(",", ":")), None


def canonical_base32_bytes(value: str) -> bytes | None:
    if not re.fullmatch(r"b[a-z2-7]+", value):
        return None
    encoded = value[1:]
    padding = "=" * ((8 - len(encoded) % 8) % 8)
    try:
        decoded = base64.b32decode((encoded.upper() + padding), casefold=False)
    except ValueError:
        return None
    canonical = base64.b32encode(decoded).decode("ascii").lower().rstrip("=")
    return decoded if canonical == encoded else None


def canonical_scope_id(value: str) -> bool:
    decoded = canonical_base32_bytes(value)
    return decoded is not None and len(decoded) == 34 and decoded[:2] == b"\x12\x20"


def canonical_cid(value: str) -> bool:
    decoded = canonical_base32_bytes(value)
    return decoded is not None and len(decoded) > 4


def parse_query(raw: str, scheme: str, resource: str) -> tuple[dict | None, dict | None, str | None, str | None]:
    if not raw:
        return {}, {}, "", None
    seen: dict[str, list[str]] = {}
    for pair in raw.split("&"):
        if "=" not in pair:
            return None, None, None, "malformed-uri"
        raw_name, raw_value = pair.split("=", 1)
        name, error = decode_component(raw_name, segment=False)
        if error:
            return None, None, None, error
        value, error = decode_component(raw_value, segment=False)
        if error:
            return None, None, None, error
        if name not in QUERY_NAMES:
            return None, None, None, "unsupported-parameter"
        if value == "":
            return None, None, None, "malformed-uri"
        values = seen.setdefault(name, [])
        if name != "source" and values:
            return None, None, None, "duplicate-parameter"
        if value in values:
            return None, None, None, "duplicate-parameter"
        values.append(value)

    if sum(name in seen for name in ("commit", "ref", "snapshot")) > 1:
        return None, None, None, "conflicting-snapshot-selectors"
    if "ref" in seen and scheme != "kan+git":
        return None, None, None, "inapplicable-parameter"
    if "snapshot" in seen and scheme != "kan":
        return None, None, None, "inapplicable-parameter"
    if "commit" in seen and scheme not in {"kan+git", "kan+at"}:
        return None, None, None, "inapplicable-parameter"
    if "service" in seen and not (scheme == "kan+at" and "source" in seen and "appview" in seen["source"]):
        return None, None, None, "inapplicable-parameter"
    if "version" in seen and resource != "principal-identity":
        return None, None, None, "inapplicable-parameter"
    if ("trust" in seen or "at" in seen) and resource in {"authority-identity"}:
        return None, None, None, "inapplicable-parameter"

    if scheme == "kan+git" and "commit" in seen:
        value = seen["commit"][0]
        if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
            return None, None, None, "non-canonical-identifier"
    if scheme == "kan+git" and "ref" in seen and not seen["ref"][0].startswith("refs/"):
        return None, None, None, "non-canonical-identifier"
    if "at" in seen:
        value = seen["at"][0]
        if not re.fullmatch(r"0|[1-9][0-9]*", value):
            return None, None, None, "non-canonical-identifier"
    if "trust" in seen:
        value, error = canonical_trust(seen["trust"][0])
        if error:
            return None, None, None, error
        seen["trust"] = [value or ""]

    evidence: dict = {}
    evaluation: dict = {}
    for name, values in seen.items():
        target = evaluation if name in {"trust", "at"} else evidence
        if name == "source":
            target["sources"] = sorted(values)
        elif name == "at":
            target[name] = int(values[0])
        else:
            target[name] = values[0]

    pairs: list[tuple[int, str, str]] = []
    for name, values in seen.items():
        for value in sorted(values) if name == "source" else values:
            pairs.append((QUERY_ORDER[name], name, value))
    pairs.sort(key=lambda item: (item[0], item[1], item[2]))
    canonical = "&".join(f"{name}={canonical_query(value)}" for _, name, value in pairs)
    return evidence, evaluation, canonical, None


def parse_resource(parts: list[str]) -> tuple[str | None, str | None, str | None]:
    if parts == ["identity"]:
        return "authority-identity", None, None
    if len(parts) == 2 and parts[0] == "claim" and re.fullmatch(r"[a-z0-9]+", parts[1]):
        return "claim", parts[1], None
    if len(parts) >= 2 and parts[0] == "subject":
        if parts[1].startswith("@"):
            if len(parts) != 2:
                return None, None, "invalid-selector"
            cid = parts[1].removeprefix("@cid:")
            if cid == parts[1]:
                return None, None, "unsupported-selector"
            if not canonical_cid(cid):
                return None, None, "non-canonical-identifier"
            return "subject", parts[1], None
        if any(part.startswith("@") for part in parts[1:]):
            return None, None, "invalid-selector"
        return "subject", "/".join(parts[1:]), None
    if parts == ["identity", "scope"]:
        return "scope-identity", None, None
    if parts == ["identity", "authority"]:
        return "authority-identity", None, None
    if len(parts) == 5 and parts[:3] == ["identity", "principal", "did"]:
        return "principal-identity", f"did:{parts[3]}:{parts[4]}", None
    return None, None, "invalid-path-segment"


def parse_uri(uri: str) -> dict:
    match = re.match(r"^([^:]+):", uri)
    if not match or match.group(1).lower() not in SCHEMES:
        return failure("unsupported-scheme")
    scheme = match.group(1).lower()
    if "#" in uri:
        return failure("fragment-not-supported")
    try:
        split = urlsplit(uri)
        port = split.port
    except ValueError:
        return failure("malformed-uri")
    if not split.netloc or split.scheme.lower() != scheme:
        return failure("malformed-uri")

    username = split.username
    password = split.password
    if scheme != "kan+git" and (username is not None or password is not None):
        return failure("userinfo-forbidden")
    if scheme == "kan+git" and password is not None:
        return failure("credential-in-userinfo")
    host = (split.hostname or "").lower()
    if not host:
        return failure("malformed-uri")

    raw_parts = split.path.split("/")[1:]
    if not raw_parts or any(part == "" for part in raw_parts):
        return failure("invalid-path-segment")
    parts: list[str] = []
    for raw in raw_parts:
        value, error = decode_component(raw, segment=True)
        if error:
            return failure(error)
        parts.append(value or "")

    authority = host
    scope_locator = None
    requested_scope = None
    resource_parts: list[str]
    if host == "did" and scheme in {"kan", "kan+at"}:
        if len(parts) < 3:
            return failure("invalid-path-segment")
        authority = f"did:{parts[0]}:{parts[1]}"
        if parts[2:] == ["identity"]:
            resource_parts = ["identity", "principal", "did", parts[0], parts[1]]
        else:
            if len(parts) < 4:
                return failure("invalid-path-segment")
            scope_locator = parts[2]
            resource_parts = parts[3:]
    elif parts == ["identity"]:
        resource_parts = parts
    else:
        scope_locator = parts[0]
        resource_parts = parts[1:]

    if scope_locator is not None:
        if scope_locator.startswith("@"):
            scope_id = scope_locator.removeprefix("@id:")
            if scope_id == scope_locator:
                return failure("unsupported-selector")
            if not canonical_scope_id(scope_id):
                return failure("non-canonical-identifier")
            requested_scope = scope_id
        elif not re.fullmatch(r"[a-z0-9_~.-]+(?::[a-z0-9_~.-]+)*", scope_locator):
            return failure("non-canonical-identifier")

    resource, resource_key, error = parse_resource(resource_parts)
    if error:
        if scheme == "kan+git" and resource_parts == ["identity"]:
            resource = "authority-identity"
            resource_key = None
        else:
            return failure(error)

    evidence, evaluation, canonical_query_string, error = parse_query(split.query, scheme, resource or "")
    if error:
        return failure(error)

    canonical_authority = host
    transport = None
    repository_path = None
    if scheme == "kan+git":
        if username:
            canonical_authority = f"{canonical_segment(username)}@{host}"
            transport = "ssh"
        elif host == "local":
            transport = "local"
        else:
            transport = "https"
        if scope_locator is not None:
            repository_path = "/".join(scope_locator.split(":"))
    if port is not None:
        canonical_authority += f":{port}"

    if host == "did" and scheme in {"kan", "kan+at"}:
        canonical_parts = [canonical_segment(p) for p in parts]
    else:
        canonical_parts = ([canonical_segment(scope_locator)] if scope_locator is not None else []) + [canonical_segment(p) for p in resource_parts]
    canonical = f"{scheme}://{canonical_authority}/{'/'.join(canonical_parts)}"
    if canonical_query_string:
        canonical += f"?{canonical_query_string}"

    result = {
        "outcome": SUCCESS,
        "canonical": canonical,
        "scheme": scheme,
        "authority": authority,
        "resource": resource,
        "evidence": evidence or {},
        "evaluation": evaluation or {},
    }
    if scope_locator is not None:
        result["scopeLocator"] = scope_locator
    if requested_scope is not None:
        result["requestedScope"] = requested_scope
        result.pop("scopeLocator", None)
    if resource_key is not None:
        result["resourceKey"] = resource_key
    if scheme == "kan+git":
        result["transport"] = transport
        if username:
            result["transportUser"] = username
        if repository_path is not None:
            result["repositoryPath"] = repository_path
    return result


def discover_appview(namespace_did: str, document: dict) -> dict:
    if document.get("id") != namespace_did:
        return failure("authority-not-found")
    candidates = []
    for service in document.get("service", []):
        identifier = service.get("id")
        if identifier in {"#kan_appview", f"{namespace_did}#kan_appview"} and service.get("type") == "KanAppView":
            candidates.append(service)
    if len(candidates) != 1:
        return failure("authority-not-found")
    endpoint = candidates[0].get("serviceEndpoint")
    try:
        split = urlsplit(endpoint)
    except (TypeError, ValueError):
        return failure("authority-not-found")
    if split.scheme != "https" or not split.hostname or split.path not in {"", "/"} or split.query or split.fragment or split.username or split.password:
        return failure("authority-not-found")
    origin = f"https://{split.hostname.lower()}"
    if split.port is not None:
        origin += f":{split.port}"
    return {"outcome": SUCCESS, "service": f"{namespace_did}#kan_appview", "endpoint": origin, "proxy": f"{namespace_did}#kan_appview"}


def immutable_replay(canonical: str, commit: str) -> str:
    if "?" not in canonical:
        return f"{canonical}?commit={commit}"
    base, raw_query = canonical.split("?", 1)
    pairs = raw_query.split("&")
    if any(pair.startswith("commit=") for pair in pairs):
        return canonical
    source_pairs = [pair for pair in pairs if pair.startswith("source=")]
    other_pairs = [pair for pair in pairs if not pair.startswith("source=")]
    return f"{base}?{'&'.join(source_pairs + [f'commit={commit}'] + other_pairs)}"


def resolve_uri(uri: str, fixture: dict | None) -> tuple[dict | list | None, dict]:
    parsed = parse_uri(uri)
    if parsed["outcome"] == FAILURE:
        return None, parsed
    scheme = parsed["scheme"]
    resource = parsed["resource"]
    scope = parsed.get("scopeLocator") or parsed.get("requestedScope")
    evidence = parsed.get("evidence", {})

    if scheme == "kan+git" and resource == "authority-identity":
        return None, failure("authority-identity-unsupported")
    if scheme == "kan" and parsed["authority"] == "local" and resource == "authority-identity":
        return None, failure("authority-identity-unknown")
    if parsed.get("resourceKey") == "time-bound" and "at" not in parsed.get("evaluation", {}):
        return None, failure("evaluation-time-required")

    fixture = fixture or {}
    if "knownLocators" in fixture and scope not in fixture["knownLocators"]:
        return None, failure("scope-not-found")
    if "verifiedScopes" in fixture and len(set(fixture["verifiedScopes"])) > 1:
        return None, failure("ambiguous-scope-locator")
    if fixture.get("locator") is not None and scope != fixture["locator"]:
        return None, failure("scope-not-found")
    if fixture.get("exists") is False:
        return None, failure("source-not-found")
    if fixture.get("accessible") is False:
        return None, failure("access-denied")
    if fixture.get("snapshotExists") is True and fixture.get("resourceExists") is False:
        return None, failure("resource-not-found-at-snapshot")
    if fixture.get("retained") is False:
        return None, failure("snapshot-unavailable")
    if scheme == "kan+at" and "handles" in fixture and parsed["authority"].startswith("did:") is False:
        if parsed["authority"] not in fixture["handles"]:
            return None, failure("authority-not-found")

    if scheme != "kan+at" or "accountDid" not in fixture:
        return None, failure("resource-not-found-at-snapshot")

    repo = fixture["accountDid"]
    commit = evidence.get("commit") or fixture["commit"]
    sources = evidence.get("sources") or ["appview"]
    requests: list[dict] = []
    for source in sources:
        if source == "pds":
            request = {"kind": "xrpc", "nsid": "com.atproto.sync.getRepo", "params": {"did": repo}}
            if "commit" in evidence:
                request["requireRoot"] = evidence["commit"]
            requests.append(request)
            continue
        method = {"claim": "tools.kan.getClaim", "subject": "tools.kan.getSubject", "scope-identity": "tools.kan.getIdentity", "authority-identity": "tools.kan.getIdentity", "principal-identity": "tools.kan.getIdentity"}[resource]
        params: dict = {"repo": repo}
        if scope is not None:
            params["scope"] = scope
        if resource == "claim":
            params["cid"] = parsed["resourceKey"]
        elif resource == "subject":
            params["subject"] = parsed["resourceKey"]
        else:
            params["kind"] = resource.removesuffix("-identity")
            if resource == "principal-identity":
                params["did"] = parsed["resourceKey"]
                if "version" in evidence:
                    params["version"] = evidence["version"]
        if "commit" in evidence:
            params["commit"] = evidence["commit"]
        requests.append({"kind": "xrpc", "nsid": method, "params": params})

    result = {
        "outcome": SUCCESS,
        "canonical": parsed["canonical"],
        "commit": commit,
        "immutableReplay": immutable_replay(parsed["canonical"], commit),
        "claimCids": fixture["appview"]["claimCids"],
    }
    if len(sources) == 1:
        result["source"] = sources[0]
    else:
        result["sources"] = sources
    return requests[0] if len(requests) == 1 else requests, result
