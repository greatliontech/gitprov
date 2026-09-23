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
