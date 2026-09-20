# The git contract states no time source and no CT check

Lands: the image-signatures plan's chunk 2 (the verifier's shared
core, where the git path is reconciled with the image path)

The image contract judges a leaf at a signed time (REQ-image-time-
source) and verifies its signed certificate timestamp against the
pinned root's certificate-transparency log keys. The git contract
states neither: REQ-verify-cert-chain says the chain verifies against
the Fulcio authorities, and the implementation delegates to gitsign's
certificate verifier, which judges the leaf at its own not-before
plus one minute — a time the certificate asserts of itself, so the
validity window holds for every leaf and the check is vacuous — and
consults no certificate-transparency log. With transparency required
the signed entry timestamp binds an integrated time the leaf could be
judged at; without it no signed time exists, and the certificate-only
mode verifies a chain at a time nothing binds.

The resolution is the image contract's applied to git objects: the
leaf judged at the entry's integrated time when transparency is
required, and the certificate-only mode stated as what it is, or
withdrawn; the signed certificate timestamp verified where the root
carries log keys. Stated here so the git section is not silently
weaker than its sibling; the verifier chunk lands it in one core.
