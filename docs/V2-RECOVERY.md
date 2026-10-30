# Recipient-key recovery setup

`kan recovery setup` backs up **one existing archive decryption key**. It leaves
that operational key, active epoch history, credentials and routing unchanged.
It uses the existing signed `kan-key-recovery/1` package format and HPKE wrapping.
The new random recovery secret is a raw 32-byte key in a mode-0600 file, not a
password-encrypted file. The package contains encrypted key material and signed
public metadata, never the unwrapped operational key.

This is not a whole-instance backup. Retain archive data, signed checkpoints,
configuration, signing credentials, workspace encryption keys and any other key
epochs separately. For an existing multi-epoch history, use the
[key-history export/transfer workflow](V2-LIBRARY.md#encryption-epoch-rotation-and-wrapped-key-recovery).
A package from setup represents only the selected key; it does not extend or
replace an active epoch history. It can be restored into a separate empty history
through the existing owner package workflow.

## Set up

Use `kan` with its default `v2-crypto` feature. Provision two **existing private
(0700) directories**: one for the encrypted package and a separate, non-nested
one for the recovery secret. Use absolute canonical paths without symlink
ancestors. The command creates files with mode 0600 and never overwrites existing
paths, including partial files. It does not chmod existing directories.

Prepare a public proof binding copied from the selected archive configuration:

```json
{
  "profile": "admitted",
  "archive": "<64 lowercase hex>",
  "scope": "<64 lowercase hex>",
  "issuer": "<storage issuer did:key>"
}
```

Use `copied` for a copied proof archive. The signer is the owner of this recovery
package; signing it does not grant archive access or establish current scope
admission. Independently check the binding and public recipient against the
archive configuration. Setup validates the selected key's public recipient but
cannot prove the binding against an archive it has not read.

```sh
kan recovery setup \
  --binding /absolute/config/proof-binding.json \
  --signing-key /absolute/operational/owner-signing.key \
  --recipient-key /absolute/operational/archive-recipient.key \
  --expected-recipient <64-hex-public-recipient-from-archive-config> \
  --package /absolute/private-backup/recipient-recovery.json \
  --recovery-key /absolute/private-secret/recovery.key
```

Successful JSON output includes `package_sha256`, the public recipients and
`key_recovery_verified: true`. Retain that SHA-256 pin independently, for example
in your recovery inventory. It authenticates the exact package; reading the pin
only from a possibly replaced package provides no independent protection.
Private keys are never printed or accepted as inline CLI values.

The command writes and synchronizes the secret first, then the package. A failed
or interrupted invocation can leave a secret or partial package. It retains these
files and refuses a retry using the same output paths. Inspect the retained files;
if the package completed, use its independently recorded digest to verify it.
Otherwise choose fresh paths for a new setup. Do not mistake file existence for
successful setup. An output-channel error can occur after both files were written.

## Retain and verify the copies

Copy the encrypted package and its signed metadata to independent backup storage.
Store the recovery secret separately; a different directory on the same disk is
not an independent failure domain. Both files together permit decryption of the
selected key, so protect the secret from readers of the package. The file-based
reader does not integrate with macOS Keychain. Disk encryption, account isolation
and an independently protected recovery copy are deployment decisions, not
properties inferred by this command.

After copying, restrict each directory to 0700 and each file to 0600. Then:

```sh
kan recovery verify \
  --package /absolute/restored-backup/recipient-recovery.json \
  --recovery-key /absolute/restored-secret/recovery.key \
  --expected-sha256 <independently-retained-package-sha256>
```

Verification is read-only. It checks the exact package digest, signed record chain,
archive binding, recovery recipient and recovered private/public correspondence.
Missing/wrong secrets, changed signatures, malformed or oversized packages,
symlinks, multiply linked files and permissive file permissions refuse recovery.
A successful result does not prove independent storage or archive restoration;
those fields remain explicitly false.

## Recover and test the archive

With the original operational key unavailable, recover to a **new** owner-only
file in an existing private directory:

```sh
kan recovery restore \
  --package /absolute/restored-backup/recipient-recovery.json \
  --recovery-key /absolute/restored-secret/recovery.key \
  --expected-sha256 <independently-retained-package-sha256> \
  --output /absolute/private-reader/recovered-recipient.key
```

Restore verifies the package before writing, synchronizes the new file and checks
its bytes on readback. It refuses an existing output and prints only public
metadata and the output path. If writing fails, preserve the partial output and
choose a new path after diagnosis. It never installs the key into a reader,
starts a service or changes routing.

Use this recovered key for an isolated `kan restore-import` test against the
independent archive backup, with its original proof/binding/plan/writer pins.
Compare selected files to the retained inventory. The key round trip alone cannot
prove archive completeness, semantic migration readiness or current authority.
Missing/wrong-key failure controls and a successful archive restore should both
pass before live migration is approved.
