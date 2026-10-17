# Feature: Recipient-encrypted opaque archive chunks

## Summary

Implement a bounded HPKE archive-chunk profile using explicit recipient keys. Collectors need only a public key to encrypt; the existing storage service receives no decryption key. This is a cryptographic primitive and interoperability build point, independent of the still-open production key custody and erasure-unit decision.

## Requirements

- REQ-1: Use RFC 9180 base-mode DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20Poly1305 through the maintained `hpke` library. Never implement a new cipher, KDF or nonce scheme.
- REQ-2: Authenticate the versioned header, recipient key identifier and routing scope. Wrong keys, scopes, suite versions, truncations and modified bytes must return no plaintext.
- REQ-3: Bound ciphertext to the service's 1 MiB payload limit and allocate only bounded buffers. Each seal uses a fresh HPKE context; repeated plaintext produces distinct ciphertext. A sender's signing identity remains separate from recipient encryption keys.
- REQ-4: Verify the primitive against published RFC 9180 vectors and a separate implementation. Demonstrate encrypted append/read/backup recovery while the service has no private recipient key and plaintext canaries do not occur in its archive.
- REQ-5: Do not create keys, choose production custody, decrypt on the server, or claim secure erasure/forward secrecy from this primitive. Caller-supplied keys and the future spool retain original ciphertext on retries.

## Acceptance Criteria

- [ ] AC-1: Published X25519/ChaCha20Poly1305 HPKE known-answer vector decrypts to exact expected bytes; independent interoperability check agrees. (REQ-1, REQ-4)
- [ ] AC-2: Wrong scope/recipient, edited header/tag/payload, truncation, unsupported version/suite and boundary-size fixtures reject without plaintext; maximum valid input works. (REQ-2, REQ-3)
- [ ] AC-3: Two seals of identical bytes differ; encrypt with a public key, append through the service, restore from backup and decrypt exact original bytes with the private key. A byte scan of service storage finds no plaintext canary. (REQ-3, REQ-4, REQ-5)

## Architecture

`src/evidence_crypto.rs` provides `seal` and `open` pure byte APIs. The existing `src/evidence_service.rs` remains blind and continues to store the signed outer request. The caller owns key storage, plaintext lifetime and its explicit grant to decrypt. HPKE base mode supplies recipient confidentiality, not sender authentication; the existing signed request supplies the observer's outer attribution.

The fixed header is magic KANE, version 1, big-endian KEM/KDF/AEAD identifiers 0x0020/0x0001/0x0003, SHA-256 of the 32-byte recipient public key, the 32-byte HPKE encapsulated key, and a big-endian u32 ciphertext length. The whole header is AEAD associated data. HPKE info is `tools.kan.archive.hpke.v1` plus NUL and the 32-byte routing scope. The ciphertext includes the 16-byte authentication tag. Maximum plaintext is the service limit minus header and tag; the size bound is per chunk, never a lifetime archive cap.

The dependency is optional behind `v2-crypto`, with only alloc/getrandom/x25519/chacha features. No post-quantum or alternate-suite negotiation is claimed. RFC vectors come from the HPKE authors' published test vectors; independent verification must not use the Rust library under test. The existing `src/persistence.rs` surface catalog records authority ownership. Any newly introduced persistence representation is declared as an opaque object subformat in the surface catalog; this module itself does not write files.

References: [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and [hpke crate API](https://docs.rs/hpke/0.14.1/hpke/). Key compromise permits decryption of retained ciphertext for that recipient; this is intended owner recovery, not forward secrecy. Per-record cryptographic erasure would require separately managed recipient/DEK units and key destruction across backups. No such erasure policy is inferred here.

## Open Questions

Production custody/recovery packaging and erasure-unit selection remain pending. The APIs accept explicit keys and do not settle those deployment decisions. The existing day partial-trust limitation still requires later log backfill.

## Out of Scope

- Live key installation, user-data import, production gateway transport or a secure-erasure claim.
- Managing backups of private keys or silently choosing a global identity.
