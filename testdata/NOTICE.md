# Test vectors

## Vendored gitsign golden vectors

`gitsign-oid-commit.txt` and `gitsign-oid-tlog.json` are copied verbatim
from github.com/sigstore/gitsign v0.16.0 `internal/rekor/oid/testdata/`
(`commit.txt`, `tlog.json`).

Copyright The Sigstore Authors. Licensed under the Apache License,
Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).

Used as golden vectors to prove `rekoroid.go` — a faithful port of that
un-importable gitsign internal package — reconstructs the Rekor
HashedRekord byte-identically to upstream. Re-vendor on any gitsign
bump.

## Recorded real-bytes fixtures

Real, contemporaneously captured gitsign artifacts, verified offline
forever against these frozen bytes (a synthetic VirtualSigstore cannot
produce a real embedded Rekor proof). Captured 2026-05-18 by the author
(interactive Google OIDC, gitsign v0.16.0); not third-party material —
throwaway empty commits created solely as test vectors. The embedded
Fulcio leaf binds the author's public OIDC identity; the Rekor entry is
already public in the transparency log. No secret material.

- **Positive:** `gitsign-fixture-commit.txt` +
  `gitsign-fixture-trusted-root.json` — a real
  `gitsign.rekorMode=offline` commit (empty tree) and its
  contemporaneous trusted root (`root.FetchTrustedRoot()` at signing
  time, so the pinned Fulcio/Rekor keys are valid for the signing
  time). The `gpgsig` CMS signature embeds the Rekor
  `TransparencyLogEntry` (OID 1.3.6.1.4.1.57264.3.1) in its unsigned
  attributes — offline-verifiable from the commit alone.
- **Negative (fail-closed):** `gitsign-online-fixture-commit.txt` — a
  real **default-online-mode** gitsign commit carrying **no** embedded
  proof. `gitsign verify` (online) confirmed the identity and that the
  commit IS in Rekor (tlog index 1566725997) — proving the
  transparency-required rejection is the offline-only architecture's
  deliberate stance, not a broken signature.

Expected verified identity of the positive fixture (frozen in
`fixture_test.go`):

- `Subject`             = `nikolas.sepos@gmail.com`
- `Issuer`              = `https://accounts.google.com`
- `CertFingerprint`     = `sha256:ba3d1238f87b7ed76b429476a21c3bc69176a52612ee6519ff4bdccf4ec4d0d4`
- `RekorLogIndex`       = `1566540772`
- `RekorIntegratedTime` = `1779093580`
- `TrustedRootDigest`   = `sha256:0ba58f6c09c271f664f0f8c1fa62e2065844ca89a0397c0178ed5188f6096724`
  (= sha256 of `gitsign-fixture-trusted-root.json` raw bytes)

Re-capture (re-sign + re-fetch root, `rekorMode=offline`) if a
gitsign/sigstore-go bump requires it, and update the expected values.

## Captured cosign vectors

Real carriers cosign v3.1.3+dirty (a distribution build) wrote and
ghcr.io served, captured
2026-09-24 by the author with scripts/capture-cosign.sh (interactive
Google OIDC): a throwaway one-layer OCI image, digest
`sha256:facb5564762d06aa0d30bba81be04b6d078cd289cb861e864dafd36a85322f28`,
signed keyless twice — the default bundle referrer under the TUF
signing configuration, and the legacy simple-signing layer under the
signature tag against the default Rekor v1 log. The Fulcio leaves
bind the author's public OIDC identity; the entries are public in
the transparency log. No secret material, no third-party material.
`cosign verify` reports both good under the identity below.

- `cosign-fixture-bundle.json`: the bundle referrer's one layer, a
  version 0.3 bundle: a DSSE envelope over an in-toto v1 statement
  naming the digest under the cosign sign predicate, the leaf
  certificate, one Rekor v1 `dsse` entry (log index 2940469140,
  integrated time 1790262766, a signed entry timestamp and an
  inclusion proof under a checkpoint whose origin is
  `rekor.sigstore.dev - 1193050959916656506`) and one RFC 3161
  timestamp from `timestamp.sigstore.dev`.
- `cosign-fixture-envelope-manifest.json`: the manifest under the
  tag `sha256-facb…f28.sig`, its one simple-signing layer carrying
  the signature, the certificate, an empty chain and the Rekor v1
  `hashedrekord` bundle (log index 2940477984, integrated time
  1790262794) as annotations, and no timestamp annotation.
- `cosign-fixture-envelope-payload.json`: that layer's content, the
  simple-signing document naming the digest.
- `cosign-fixture-trusted-root.json`: the trusted root sigstore's
  TUF served at signing (`sha256:6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`),
  naming the v1 log and the Rekor v2 log `log2025-1.rekor.sigstore.dev`.

A second image, digest
`sha256:4818f02852957cd2e54cd1f6d6303e96792add0a0694049202551205d439a03d`,
signed the same day the same way, its bundle signed under TUF's
other signing configuration target `signing_config_rekor_v2.v0.2.json`
(`SIGNING_CONFIG`), which names the v2 log with v1 as fallback — the
default target of the day named the v1 log alone; `cosign verify`
reports both of its carriers good under the identity below:

- `cosign-fixture-v2-bundle.json`: the bundle referrer's layer, its
  one entry in the Rekor v2 log: a `hashedrekord` 0.0.2 entry (log
  index 123822350), no integrated time and no signed entry
  timestamp, an inclusion proof under a checkpoint whose origin is
  `log2025-1.rekor.sigstore.dev`, the checkpoint cosigned by three
  witnesses beside the log; and one RFC 3161 timestamp from
  `timestamp.sigstore.dev` at 2026-09-24T15:53:44Z, the signed time.
- `cosign-fixture-v2-envelope-manifest.json` and
  `cosign-fixture-v2-envelope-payload.json`: the legacy carrier, as
  the first image's — a v1 `hashedrekord` bundle (log index
  2941115595, integrated time 1790265244).

Expected verified identity of all four (frozen in `image_test.go`):
`Subject` = `nikolas@greatlion.tech`, `Issuer` =
`https://accounts.google.com`; the leaf fingerprints
`sha256:40c28d9006125604ab5a21be1231899c454653877418fc66a721ff21358bdd5c`
(v1 bundle),
`sha256:9196a33ad6d2f0e231a3a3449c981bb18170e24b5b48ad78e7107a2f265313a3`
(v1 envelope),
`sha256:35f1107ff0a1ea1cad4ad7bba2c26bfebdc3d1177266663d4f2f35c3bd2e1f8e`
(v2 bundle),
`sha256:08f2e4da0d888cd9149514c6915b23bbccaa4103a1a4b364d82d64b4c14a0f64`
(the second image's envelope).

## SSH-signed fixtures

Real objects git 2.55 wrote and OpenSSH signed (`gpg.format=ssh`),
made 2026-09-23 by the author in a throwaway repository with keys
made for the purpose and discarded; no secret material, no
third-party material. `git verify-commit` and `git verify-tag`
report a good signature on each under the matching key.

- `ssh-fixture-commit.txt`: an empty commit signed by the Ed25519
  key `ssh-fixture-key.pub` (fingerprint
  `SHA256:cuQ/ZG8mqAef7X0GZ19RH5baTiwTVg76NePyXAKPBfM`).
- `ssh-fixture-tag.txt`: the annotated tag `v1.0.0` of that commit,
  signed by the same key.
- `ssh-fixture-rsa-tag.txt`: the annotated tag `v1.0.1` of that
  commit, signed by the 2048-bit RSA key `ssh-fixture-rsa-key.pub`
  (fingerprint `SHA256:qJf90eocttnD82cEmd3HjozFS3VFv2VfFEZPKsGOxRc`)
  in the rsa-sha2-512 form ssh-keygen writes.

## Verbatim SSH-signed fixtures

Real objects git 2.55 wrote with `--cleanup=verbatim` and OpenSSH
signed (`gpg.format=ssh`), made 2026-09-24 by the author in a
throwaway repository with a key made for the purpose and discarded;
no secret material, no third-party material. Each carries bytes a
line-reading split loses, and `git verify-commit` and `git
verify-tag` report a good signature on each under the key
`ssh-verbatim-key.pub` (Ed25519, fingerprint
`SHA256:AenzIvrZ1V5M482aTO59gPD791VpGO5R7l2MmGDEg9U`).

- `ssh-verbatim-return-commit.txt`: an empty commit whose message
  lines end in a carriage return before the newline.
- `ssh-verbatim-unterminated-commit.txt`: an empty commit whose
  final message line has no newline.
- `ssh-verbatim-return-tag.txt`: the annotated tag `v1.0.0` of the
  first commit, its message lines ending in a carriage return.

## OpenPGP-signed fixtures

Real objects git 2.55 wrote and GnuPG 2.4.9 signed, made 2026-09-23
by the author in a throwaway repository and keyring with keys made
for the purpose and discarded; no secret material, no third-party
material. `git verify-commit` and `git verify-tag` report a good
signature on each under the matching key.

- `openpgp-fixture-commit.txt`: an empty commit signed by the
  EdDSA key `openpgp-fixture-key.asc` (fingerprint
  `91EDFEA1C6643EA64EC693516EA5914F2DADE816`), whose primary key
  signs.
- `openpgp-fixture-tag.txt`: the annotated tag `v1.0.0` of that
  commit, signed by the same key.
- `openpgp-fixture-subkey-tag.txt`: the annotated tag `v1.0.1` of
  that commit, signed by the signing subkey (fingerprint
  `9167A78376D46BA35072403CCFFBD328B260CD77`) of the certify-only
  key `openpgp-fixture-subkey-key.asc` (primary fingerprint
  `225F3F5BE4F54F0A97C90D557D51FFB6BCF54190`).
- `openpgp-fixture-sha1-tag.txt`: the annotated tag `v1.0.2` of that
  commit, signed by the first key with `digest-algo SHA1` set for
  gpg, which git still reports as a good signature; the verifier
  refuses SHA-1 message digests.
