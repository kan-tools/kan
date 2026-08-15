#!/usr/bin/env bash
set -euo pipefail

repo_root=${KAN_RFC_ADR_ROOT:-$(git rev-parse --show-toplevel)}
cd "$repo_root"

fail() {
  echo "RFC/ADR CHECK FAILED: $*" >&2
  exit 1
}

hash_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

if [[ "${1:-}" == "--self-test" ]]; then
  fixture=$(mktemp -d "${TMPDIR:-/tmp}/kan-rfc-adr-check.XXXXXX")
  trap 'rm -rf "$fixture"' EXIT
  mkdir -p "$fixture/scripts"
  cp -R adrs rfcs docs "$fixture/"
  cp "$0" "$fixture/scripts/check-rfcs-adrs.sh"
  perl -pi -e 's/Bus-factor/Bus factor/' "$fixture/adrs/1-repo-mst-cid-signing-crate-family-atrium-rs-not-atproto-repo.md"
  if KAN_RFC_ADR_ROOT="$fixture" "$fixture/scripts/check-rfcs-adrs.sh" >"$fixture/output" 2>&1; then
    fail "self-test mutation was accepted"
  fi
  if ! grep -Fq 'historical prose changed' "$fixture/output"; then
    cat "$fixture/output" >&2
    fail "self-test failed for the wrong reason"
  fi
  echo "RFC/ADR self-test: historical-prose mutation rejected"
  exit 0
fi

manifest=adrs/migration-manifest.tsv
[[ -f "$manifest" ]] || fail "missing $manifest"

count=0
duplicates=$(tail -n +2 "$manifest" | cut -f2 | sort | uniq -d)
[[ -z "$duplicates" ]] || fail "duplicate ADR files in manifest: $duplicates"
while IFS=$'\t' read -r number file title expected_hash; do
  [[ "$number" == "number" ]] && continue
  count=$((count + 1))
  expected_number=$count
  [[ "$number" == "$expected_number" ]] || fail "expected ADR $expected_number, found $number"
  path="adrs/$file"
  [[ -f "$path" ]] || fail "missing $path"
  grep -Fqx "# ADR $number: $title" "$path" || fail "$path title differs from manifest"
  grep -Fq -- '- Reconstruction: Reconstructed from the historical' "$path" || fail "$path lacks reconstruction metadata"
  for section in Context Decision Rationale Consequences Evidence 'Alternatives considered' Supersession 'Historical record'; do
    grep -Fqx "## $section" "$path" || fail "$path lacks section: $section"
  done
  for section in Context Decision Rationale Consequences Evidence 'Alternatives considered' Supersession; do
    SECTION="$section" perl -0777 -ne 'my $s = quotemeta($ENV{SECTION}); exit(/## $s\n\nNot recorded contemporaneously\.\n/ ? 0 : 1)' "$path" \
      || fail "$path must mark empty $section as not recorded contemporaneously"
  done
  actual_hash=$(perl -0777 -ne 'if (/## Historical record\n\n(.*)\n\z/s) { print $1 } else { exit 2 }' "$path" | hash_stdin)
  [[ "$actual_hash" == "$expected_hash" ]] || fail "$path historical prose changed"
  links=$(grep -Fxc -- "- [ADR $number: $title]($file)" adrs/README.md || true)
  [[ "$links" -eq 1 ]] || fail "$path must have exactly one index entry"
done < "$manifest"

[[ "$count" -eq 91 ]] || fail "expected 91 reconstructed ADRs, found $count"
[[ $(find adrs -maxdepth 1 -type f -name '[0-9]*-*.md' | wc -l | tr -d ' ') -eq 91 ]] || fail "ADR file count differs from manifest"
! find adrs -maxdepth 1 -type f -name '0[0-9]*-*.md' | grep -q . || fail "ADR filenames must not have leading zeroes"
! grep -Eq '^## ADR-[0-9]+' docs/DECISIONS.md || fail "docs/DECISIONS.md still contains live ADR records"

for file in rfcs/0-rfc-and-adr-process.md rfcs/1-identity-system.md rfcs/template.md; do
  [[ -f "$file" ]] || fail "missing $file"
  for section in Summary Motivation Terminology 'Detailed design' 'Canonicalization and equivalence' 'Resolution or processing algorithm' 'Authority and trust model' 'Security considerations' Compatibility 'Alternatives considered' 'Reference test vectors' 'Unresolved questions' 'Implementation status'; do
    grep -Fqx "## $section" "$file" || fail "$file lacks section: $section"
  done
done

[[ -f adrs/template.md ]] || fail "missing adrs/template.md"
for section in Context Decision Rationale Consequences Evidence 'Alternatives considered' Supersession; do
  grep -Fqx "## $section" adrs/template.md || fail "adrs/template.md lacks section: $section"
done

status=$(sed -n 's/^- Status: //p' rfcs/0-rfc-and-adr-process.md)
case "$status" in
  Draft|Review|Accepted|Implemented|Rejected|Withdrawn|Superseded) ;;
  *) fail "RFC 0 has unrecognized status: $status" ;;
esac

identity_status=$(sed -n 's/^- Status: //p' rfcs/1-identity-system.md)
case "$identity_status" in
  Draft|Review|Accepted|Implemented|Rejected|Withdrawn|Superseded) ;;
  *) fail "RFC 1 has unrecognized status: $identity_status" ;;
esac
grep -Fq 'kan.did.genesis.v1' rfcs/1-identity-system.md || fail "RFC 1 lacks identity domain separation"
grep -Fq 'kan.repository.inception.v1' rfcs/1-identity-system.md || fail "RFC 1 lacks repository domain separation"
grep -Fq 'kan.repository.governance.v1' rfcs/1-identity-system.md || fail "RFC 1 lacks governance domain separation"
grep -Fq 'kan.capability.delegation.v1' rfcs/1-identity-system.md || fail "RFC 1 lacks delegation domain separation"
grep -Fq 'kan.capability.revocation.v1' rfcs/1-identity-system.md || fail "RFC 1 lacks revocation domain separation"
grep -Fq 'Event validity is intrinsic' rfcs/1-identity-system.md || fail "RFC 1 makes event validity view-relative"
grep -Fq 'cryptographicValidity = valid | invalid | unsupported | unknown' rfcs/1-identity-system.md || fail "RFC 1 does not separate cryptographic validity"
grep -Fq 'identityStateStanding = active | superseded | contested | unknown | static' rfcs/1-identity-system.md || fail "RFC 1 does not disclose identity-state standing"
grep -Fq 'repositoryAdmission   = admitted | unadmitted | contested | unknown | not-applicable' rfcs/1-identity-system.md || fail "RFC 1 does not separate repository admission"
grep -Fq 'viewTrust              = included | excluded | weighted' rfcs/1-identity-system.md || fail "RFC 1 does not separate view trust"

perl -0777 -ne 'exit(/72 continuous\s+hours/ ? 0 : 1)' rfcs/0-rfc-and-adr-process.md || fail "RFC 0 lacks the 72-hour review rule"
grep -Fq 'every current maintainer reacts' rfcs/0-rfc-and-adr-process.md || fail "RFC 0 lacks unanimous rocket override semantics"
grep -Fq 'after the latest substantive commit' rfcs/0-rfc-and-adr-process.md || fail "RFC 0 does not invalidate stale override approvals"
grep -Fq 'does not waive unresolved blocking questions, required evidence, or CI' rfcs/0-rfc-and-adr-process.md || fail "RFC 0 review override waives more than time"
perl -0777 -ne 'exit(/allocated when the proposal pull\s+request opens/ ? 0 : 1)' rfcs/0-rfc-and-adr-process.md || fail "RFC 0 lacks allocation-at-PR-open"
grep -Fq 'permanent gaps are valid' rfcs/0-rfc-and-adr-process.md || fail "RFC 0 lacks permanent-gap semantics"
grep -Fq 'RFC 1, the kan identity architecture' rfcs/0-rfc-and-adr-process.md || fail "RFC 0 does not reserve identity as the expected next proposal"
grep -Fq 'RFC 2 is' rfcs/0-rfc-and-adr-process.md || fail "RFC 0 does not sequence the URI proposal after identity"

echo "RFC/ADR check: 91 reconstructed ADRs, RFC 0, and RFC 1 are structurally valid"
