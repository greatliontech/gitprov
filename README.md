# gitprov

Offline provenance verification of git objects and OCI images:
sigstore-keyless signatures — gitsign's CMS over raw commit and
annotated-tag bytes, cosign's bundle or simple-signing envelope over a
manifest digest — Fulcio identity extraction and policy matching, and
transparency proofs, embedded or carried, with the leaf judged at a
signed time — all verified against a caller-pinned trusted root, with
no network access ever.

The contract lives in `docs/specs/verification.md`.

The offline Rekor reconstruction is an attributed port of gitsign
internals that upstream does not export; see the package documentation
for the fidelity and re-audit discipline it carries.
