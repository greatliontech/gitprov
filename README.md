# gitprov

Offline provenance verification of git objects: sigstore-keyless
(gitsign) CMS signatures over raw commit and annotated-tag bytes, Fulcio
identity extraction and policy matching, and embedded-Rekor transparency
proofs — all verified against a caller-pinned trusted root, with no
network access ever.

The contract lives in `docs/specs/verification.md`.

The offline Rekor reconstruction is an attributed port of gitsign
internals that upstream does not export; see the package documentation
for the fidelity and re-audit discipline it carries.
