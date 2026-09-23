// Package gitprov verifies the provenance of git objects and OCI
// images, fully offline (docs/specs/verification.md): for a git
// object, a gitsign (sigstore keyless) CMS signature over the raw
// commit or annotated-tag bytes with — when the caller requires
// transparency — a Rekor inclusion proof embedded in the signature
// itself; for an image, a cosign sigstore bundle or simple-signing
// envelope over the manifest digest with its transparency entry
// carried (VerifyImage); in both a Fulcio short-lived certificate
// carrying the signer's OIDC identity matched against caller policy
// and judged at a signed time, all verified against a caller-pinned
// trusted root. No service is ever queried.
//
// The label of a git signature's armor header line states its kind —
// gitsign's CMS, OpenPGP, SSH — and the kind selects the verifier
// (SignatureKindOf, REQ-verify-signature-kind): Verify takes a
// sigstore signature and fails on any other kind with
// ErrSignatureKind; VerifyPinned takes an OpenPGP or an SSH signature
// and verifies it against exactly the keys the caller pins
// (ParsePinnedKey), offline and without transparency, the outcome
// naming the key's kind and fingerprint, a signature the keys do not
// vouch for ErrUnpinnedKey (REQ-verify-pinned-key). A caller routing
// by kind reads it first.
//
// Only signatures made in gitsign's offline Rekor mode
// (`gitsign.rekorMode=offline`) carry the embedded proof. A signature
// from gitsign's default online mode is unverifiable with transparency
// required — its legacy Rekor entry is not an offline-verifiable
// binding of the CMS signature, a dead end established empirically
// (gitsign's own source plus real-bytes captures) before this library's
// extraction — and there is deliberately no network fallback.
//
// Mechanism notes:
//
//   - Certificate-chain verification uses gitsign's public pkg/git:
//     SplitCommit/SplitTag for raw-byte splitting (never a library
//     object re-encode), trusted only where their join reproduces the
//     raw bytes — their line reading drops a carriage return,
//     normalizes an indented signature line and completes a final
//     line, and an object so rebuilt is refused (object.go) — and
//     CertVerifier over Fulcio pools built from the pinned trusted
//     root.
//   - The offline Rekor inclusion check cannot use gitsign's own
//     verifier: pkg/rekor.Client.VerifyInclusion is hard-wired to
//     cosign's TUF/network trusted-root global, and its reconstruction
//     helpers live under gitsign/internal. rekoroid.go is a faithful,
//     attributed port of gitsign v0.16.0 internal/rekor/oid; the
//     proof+SET check is cosign/v3's VerifyTLogEntryOffline with the
//     pinned root as trusted material.
//   - CMS structural access uses the upstream
//     github.com/github/smimesign/ietf-cms/protocol; sigstore-go
//     supplies the trusted-root material and, for images and for the
//     leaf's judgement at a signed time on both paths, its bundle
//     verifier and its certificate-timestamp verb (its verify API
//     cannot consume CMS, so the git path's chain and Rekor binding
//     stay gitsign's and the port's).
//
// Dependency floor: gitsign v0.16.0 — CVE-2026-44310 (empty-cert PKCS7)
// was fixed in v0.15.0, and v0.16.0 carries the raw-bytes
// SplitCommit/SplitTag path (CVE-2026-44309) this package's raw-bytes
// contract requires. Re-audit rekoroid.go against upstream on any
// gitsign bump.
package gitprov
