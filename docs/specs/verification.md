# gitprov — offline provenance verification of git objects and images

gitprov verifies that a git commit or annotated tag, or an OCI image
manifest, was signed by an identity a caller's policy accepts, fully
offline. The signature model is sigstore keyless: for git objects as
gitsign produces it — a CMS signature over the raw object bytes, a
short-lived Fulcio certificate carrying the signer's OIDC identity,
and a Rekor transparency-log inclusion proof embedded in the
signature itself; for images as cosign produces it — the same
certificate and proof carried beside a signature over a payload
naming the manifest digest (see Image signatures). Trust is anchored
solely in a pinned trusted-root file supplied by the caller. What a
verified identity is *for* — which subjects a consumer requires, what
gets recorded where — is the
consumer's contract, not this library's.

**raw object bytes** (term): The git-core content of a commit or
annotated tag object — the bytes after the `<type> <len>\0` header, as
git hashes and transports them. A re-encode through any library's object
structs is not raw: signatures are computed over exact bytes, and only
exact bytes can verify.

**trusted root** (term): A sigstore TUF trusted-root JSON document —
the Fulcio certificate authorities, the Rekor transparency-log keys,
the certificate-transparency log keys, and the timestamp authorities —
loaded from bytes the caller pins. It is the sole trust anchor; nothing
else is consulted. Git-object verification consults the authorities
and the log keys; image verification consults all four (Image
signatures).

**embedded transparency proof** (term): The Rekor
`TransparencyLogEntry`, carried as an unsigned attribute
(OID 1.3.6.1.4.1.57264.3.1) of the CMS signature — the shape gitsign
produces in its offline Rekor mode. Signatures made in gitsign's default
online mode carry no such attribute; their log entries are a legacy
construct that cannot be re-verified offline, so such signatures are
unverifiable to this library by design, not by omission.

**identity policy** (term): The caller's statement of who may sign: an
OIDC issuer and a certificate SAN, each given as exactly one of an
exact string, a full-match regular expression, or a full-input glob
pattern (`/`-separated component semantics: `*` and `?` within a
component, `**` written as a complete component matching zero or more
components, character classes and alternatives, backslash quoting).

**verified identity** (term): The proven outcome of a successful
verification: the certificate SAN that matched policy, the OIDC issuer,
the leaf certificate's SHA-256 fingerprint, the digest of the trusted
root verified against, and — when transparency was required — the Rekor
log index and integration time; for an image, the digest verified as
well.

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

**REQ-verify-signed-time** (invariant): With transparency required, the
leaf MUST be judged at the entry's integrated time, which the signed
entry timestamp binds to this signature: its chain valid at that time
and its signed certificate timestamp verified against the pinned root's
certificate-transparency log keys — never at the time of verification,
and never at a time the certificate asserts of itself. Without
transparency required, verification is certificate-only: the chain is
verified at a time the certificate asserts of itself, which proves
nothing about when its key was live, and the identity read — no
signed time exists at which the short-lived leaf could be judged,
which is what a caller accepts by not requiring transparency.

**REQ-verify-embedded-rekor** (behavior): When the caller requires
transparency, the proof MUST be decoded from the signature's embedded
unsigned attribute, bound to this signature — the reconstructed
log-entry body commits to the signed message digest, the signature
bytes, and the leaf certificate — its signed entry timestamp verified
against the pinned root's log keys, and its inclusion proof walked to
the root hash the entry states; the checkpoint the entry carries is
not judged, so the signed entry timestamp is what binds the entry to
the log — deliberately unlike an image bundle's entry, whose
checkpoint its verifier judges (REQ-image-offline-verification): the
git path runs cosign's offline entry verification, the bundle path
sigstore-go's bundle verifier. A signature carrying no embedded proof
is unverifiable and fails. Whether
transparency is required is the caller's policy, stated per call;
without it, verification is certificate-only and the verified identity
carries no log entry.

**REQ-verify-identity-match** (behavior): The verified identity MUST
match policy on both axes: the OIDC issuer from the Fulcio certificate
extension matches the policy's issuer, and at least one certificate SAN
— URI, email, DNS, IP, or the Fulcio OtherName — matches the policy's
subject; regex and glob matching span the entire value, since a
substring match on an identity is a policy bypass.

**REQ-verify-policy-shape** (invariant): An identity policy naming
none or more than one of an axis's pattern kinds, or carrying a regex
or glob that does not compile, MUST be rejected before any
verification: an unusable policy never silently passes a subject.

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

## Image signatures

**image signature** (term): A sigstore keyless signature over an OCI
manifest or index digest, in one of the two carriers cosign produces,
taken as bytes the caller fetched: where a carrier is found for a
digest — the manifest's referrers, cosign's tag convention — and how
many of them the caller judges are the consumer's contract, not this
library's; each call verifies one carrier.

**sigstore bundle** (term): A sigstore bundle of media type
`application/vnd.dev.sigstore.bundle.v0.3+json` — the version the
library reads — whose content is a DSSE envelope carrying exactly one
signature over an in-toto v1 Statement, the digest signed in a
subject's `digest` map under its algorithm, the predicate type
`https://sigstore.dev/cosign/sign/v1`, and as verification material the
Fulcio leaf certificate, exactly one transparency-log entry — a bundle
without one, or with several, is not this carrier — and any RFC 3161
timestamps; the
shape cosign's default `sign` writes, attached to the manifest as an
OCI referrer whose artifact type is the bundle's media type.

**simple-signing envelope** (term): A payload of media type
`application/vnd.dev.cosign.simplesigning.v1+json` — the layer's, which
the library cannot see; its in-band marker, `critical.type` being
`cosign container image signature`, is what the library checks —
naming the digest signed at `critical.image.docker-manifest-digest`,
with the signature
over the payload bytes, the Fulcio leaf certificate, and the Rekor
bundle — the signed entry timestamp with the entry's body, log index,
log identifier, and integrated time — as cosign's legacy carrier
annotates a signature layer, a certificate chain and an RFC 3161
timestamp annotated or not; the shape cosign stores under the image
repository's `sha256-<hex>.sig` tag, or as a referrer whose manifest
names the configuration media type
`application/vnd.dev.cosign.artifact.sig.v1+json`.

**signed time** (term): A time bound to a signature by a key in the
trusted root: a transparency entry's integrated time, which its signed
entry timestamp binds, or an RFC 3161 timestamp over the signature from
a pinned timestamp authority. A Rekor v2 entry carries an inclusion
proof under a signed checkpoint and no entry timestamp; its time is a
timestamp's.

**REQ-image-carriers** (wire): The library MUST accept exactly the two
carriers, a sigstore bundle and a simple-signing envelope; any other
carrier, or one missing a part its term names as required, fails
verification.

**REQ-image-digest-binding** (invariant): The digest in hand MUST be
the digest the signed content names — one of the statement's subjects
for a bundle, the payload's manifest digest for a simple-signing
envelope — the algorithm compared exactly and the digest as decoded
bytes, after the signature has verified over the carried bytes: the
DSSE pre-authentication encoding of the carried statement for a bundle,
the carried payload for an envelope. The payload is never regenerated
from the digest in hand — a regenerated payload would verify bytes the
signer never signed, as REQ-verify-raw-bytes holds for git objects —
and a signature whose content names another digest, or none, fails.

**REQ-image-offline-verification** (behavior): An image signature MUST
verify as a git object does (REQ-verify-offline), fully offline
against the pinned trusted root. The leaf's chain verifies against
the root's Fulcio authorities, and its signed certificate timestamp
against the root's certificate-transparency log keys. The
transparency entry verifies against the root's log keys, the key
selected by the entry's log identifier and valid at the signed time
as the root states its validity: for a bundle, the inclusion proof
under its checkpoint — a Rekor v1 checkpoint carrying its own origin,
a Rekor v2 checkpoint's origin being the host of the pinned log's
base URL, so a root naming that log without one admits no v2 entry —
and, where carried, the signed entry timestamp; for a simple-signing
envelope, the signed entry timestamp over an entry body reconstructed
from the payload digest, the signature bytes, and the leaf, as
REQ-verify-embedded-rekor binds a git object's proof. Every RFC 3161
timestamp carried verifies against a pinned authority — every one,
deliberately: a timestamp no pinned authority verifies fails the
carrier even where the entry alone would supply the signed time. The
leaf's identity matches the caller's policy on both axes
(REQ-verify-identity-match). Every failure yields an error and no
verified identity (REQ-verify-fail-closed).

**REQ-image-time-source** (invariant): A Fulcio leaf is short-lived, so
its validity MUST be judged at a signed time — never at the time of
verification, and never at a time the carrier asserts unsigned. A
carrier with no signed time has no time at which its certificate can
be judged, is unverifiable, and fails. A timestamp supplies the time
an entry without an entry timestamp cannot; it never stands in for
the entry: transparency is not a per-call choice for an image
signature as it is for a git object, and a carrier with a timestamp
and no entry is not a carrier at all (REQ-image-carriers).

**REQ-image-verified-identity** (behavior): A verified image signature
MUST yield the verified identity with the digest verified and, as its
integration time, the signed time the leaf was judged at — an
integrated time nothing signs is never recorded as proven — so a
consumer records exactly what was proven and against what.

## Detection

**REQ-detect-embedded** (behavior): The library MUST expose a detection
predicate reporting whether a signed object carries an embedded
transparency proof, without establishing any trust — consumers route on
it to produce precise unverifiable-versus-invalid diagnostics — and the
predicate fails on unsigned or structurally malformed objects rather
than answering false.

**REQ-detect-image-time** (behavior): The library MUST expose the same
predicate for an image carrier: whether it carries the material a
signed time would come from — an entry with an entry timestamp, or an
RFC 3161 timestamp — without verifying any of it, so a consumer
distinguishes an unverifiable carrier from an invalid one; the
predicate fails on a carrier that is neither shape rather than
answering false.
