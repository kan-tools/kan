# Security Policy

kan handles private signing keys and makes claims about who said what. Reports
about that surface are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.**

Report it through GitHub's private vulnerability reporting:

> [**Report a vulnerability**](https://github.com/kan-tools/kan/security/advisories/new)

(Repository → *Security* → *Advisories* → *Report a vulnerability*.)

That channel is private to you and the maintainer until an advisory is
published.

### What to include

Whatever you have — a report that only describes the shape of a problem is still
worth sending. If you can, include the version (`kan --version`), the platform,
a reproduction, and what an attacker gets out of it.

### What to expect

kan is maintained by one person. You should get an acknowledgement within about
a week. If a report is valid, the fix and an advisory will follow, and you will
be credited unless you ask otherwise. If a report is declined you will be told
why, rather than left waiting.

## Supported versions

kan is **pre-1.0 and beta**. Only the most recent release gets fixes; there are
no backports to earlier `0.x` lines. Check [releases] for the current version.

[releases]: https://github.com/kan-tools/kan/releases

## Scope

In scope — anything that lets someone:

- forge a claim, or make a claim verify under an author who did not sign it;
- read or exfiltrate a private signing key, or induce kan to write one somewhere
  it should not be;
- silently drop, alter, or hide claims from a fold — a wrong answer at exit 0 is
  treated as severe here, not cosmetic;
- cause a published `.claims/` tree to be accepted when it has been tampered
  with, or rejected when it has not.

Out of scope:

- Anything requiring an attacker who already has read/write access to `.kan/`.
  That directory holds the key and the log; kan's threat model does not defend
  against someone who is already inside it.
- Vulnerabilities in dependencies with no kan-specific exploit path. Report
  those upstream — though telling us is appreciated.
- Missing hardening that is already tracked and public, listed below.

## Known limitations, deliberately public

These are real and already recorded in the issue tracker. They do not need a
private report:

- **kan's binaries are not code-signed or notarized.** On macOS this is the root
  cause of the keychain access problems — "Always Allow" binds a grant to a
  binary's code identity, so an unsigned binary loses it on every rebuild or
  upgrade ([#96](https://github.com/kan-tools/kan/issues/96)). Fixing it is a
  distribution commitment, not a code change.
- **Identity handling is still being hardened**, and its history is public:
  see [#90](https://github.com/kan-tools/kan/issues/90),
  [#149](https://github.com/kan-tools/kan/issues/149) and
  [#190](https://github.com/kan-tools/kan/issues/190). The target architecture
  is recorded as ADR-55 in `docs/DECISIONS.md`.
- **There is no sync layer yet.** Claims travel only through a tracked
  `.claims/` directory in a repo you already trust. The threat model for an
  untrusted relay is designed but not built, and end-to-end encryption is not
  shipped ([#7](https://github.com/kan-tools/kan/issues/7),
  [#29](https://github.com/kan-tools/kan/issues/29)).

If you find something that makes one of these *worse* than documented, that is
worth a private report.
