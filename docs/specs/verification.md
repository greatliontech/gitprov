# gitprov — offline provenance verification of git objects

gitprov verifies that a git commit or annotated tag was signed by an
identity a caller's policy accepts, fully offline. The signature model is
sigstore keyless as produced by gitsign: a CMS signature over the raw
object bytes, a short-lived Fulcio certificate carrying the signer's OIDC
identity, and a Rekor transparency-log inclusion proof embedded in the
signature itself. Trust is anchored solely in a pinned trusted-root file
supplied by the caller. What a verified identity is *for* — which
subjects a consumer requires, what gets recorded where — is the
consumer's contract, not this library's.

**raw object bytes** (term): The git-core content of a commit or
annotated tag object — the bytes after the `<type> <len>\0` header, as
git hashes and transports them. A re-encode through any library's object
structs is not raw: signatures are computed over exact bytes, and only
exact bytes can verify.

**trusted root** (term): A sigstore TUF trusted-root JSON document — the
Fulcio certificate authorities and Rekor transparency-log keys — loaded
from bytes the caller pins. It is the sole trust anchor; nothing else is
consulted.

**embedded transparency proof** (term): The Rekor
`TransparencyLogEntry`, carried as an unsigned attribute
(OID 1.3.6.1.4.1.57264.3.1) of the CMS signature — the shape gitsign
produces in its offline Rekor mode. Signatures made in gitsign's default
online mode carry no such attribute; their log entries are a legacy
construct that cannot be re-verified offline, so such signatures are
unverifiable to this library by design, not by omission.

**identity policy** (term): The caller's statement of who may sign: an
OIDC issuer (exact string or full-match regex, exactly one of the two)
and a certificate SAN (exact string or full-match regex, exactly one of
the two).

**verified identity** (term): The proven outcome of a successful
verification: the certificate SAN that matched policy, the OIDC issuer,
the leaf certificate's SHA-256 fingerprint, the digest of the trusted
root verified against, and — when transparency was required — the Rekor
log index and integration time.

## Verification

**REQ-verify-offline** (invariant): Verification MUST complete without
network access: certificate chains verify against the pinned trusted
root's Fulcio authorities, the embedded transparency proof verifies
against the pinned root's log keys, and no service — Rekor, TUF, or any
other — is ever queried.

**REQ-verify-raw-bytes** (invariant): Verification MUST consume raw
object bytes and split them with git-core-faithful parsing; a payload
reconstructed from a decoded object structure is rejected territory —
any normalization would verify bytes the origin never signed.

**REQ-verify-signature-extraction** (behavior): The signature MUST be
taken from the location that signs the form of the bytes in hand, per
git's hash-function-transition rules: for a commit, the header matching
the caller-stated object format (`gpgsig` signs the SHA-1 form,
`gpgsig-sha256` the SHA-256 form); for a tag, the in-body trailer in
either format — a tag's `gpgsig`/`gpgsig-sha256` headers carry
signatures over the *alternate*-form bytes and are never selected. An
object carrying no signature at its form's location fails verification:
selecting a cross-form signature would verify bytes other than the ones
in hand.

**REQ-verify-object-formats** (behavior): Both git object formats,
SHA-1 and SHA-256, MUST verify through the same contract; the object
format is caller-stated input, never inferred from the bytes.

**REQ-verify-cert-chain** (behavior): The CMS signature MUST verify as a
detached signature over the split payload against a certificate chain
ending in the pinned trusted root's Fulcio authorities; an invalid
chain, an invalid signature, or a signer certificate mismatch each fail
verification.

**REQ-verify-embedded-rekor** (behavior): When the caller requires
transparency, the proof MUST be decoded from the signature's embedded
unsigned attribute, bound to this signature — the reconstructed
log-entry body commits to the signed message digest, the signature
bytes, and the leaf certificate — and its inclusion proof and signed
entry timestamp verified against the pinned root's log keys, with a
signature carrying no embedded proof unverifiable and failing. Whether
transparency is required is the caller's policy, stated per call;
without it, verification is certificate-only and the verified identity
carries no log entry.

**REQ-verify-identity-match** (behavior): The verified identity MUST
match policy on both axes: the OIDC issuer from the Fulcio certificate
extension matches the policy's issuer, and at least one certificate SAN
— URI, email, DNS, IP, or the Fulcio OtherName — matches the policy's
subject; regex matching spans the entire value, since a substring match
on an identity is a policy bypass.

**REQ-verify-policy-shape** (invariant): An identity policy naming
neither or both members of an exact/regex pair, or carrying a regex that
does not compile, MUST be rejected before any verification: an unusable
policy never silently passes a subject.

**REQ-verify-fail-closed** (invariant): Every failure — unsigned object,
malformed signature, invalid chain, missing or unverifiable transparency
proof, identity mismatch, unusable policy or trusted root — MUST yield
an error and no verified identity; there is no partial success.

## Trusted root

**REQ-root-pinned-bytes** (behavior): The trusted root MUST be loaded
from caller-supplied bytes with no refresh, and its digest computed over
those exact raw bytes before parsing — a parse round-trip is not
canonical, so only the raw bytes are a stable identity — with the digest
carried into every verified identity produced against it.

## Detection

**REQ-detect-embedded** (behavior): The library MUST expose a detection
predicate reporting whether a signed object carries an embedded
transparency proof, without establishing any trust — consumers route on
it to produce precise unverifiable-versus-invalid diagnostics — and the
predicate fails on unsigned or structurally malformed objects rather
than answering false.
