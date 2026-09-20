package gitprov

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

// ImageCarrier is one of the two carriers cosign produces for a
// signature over an OCI manifest or index digest (verification.md,
// Image signatures): a SigstoreBundle or a SimpleSigningEnvelope, as
// bytes the caller fetched. Where a carrier is found for a digest and
// how many are judged is the caller's; each VerifyImage call verifies
// one.
type ImageCarrier interface {
	// hasSignedTimeMaterial reports whether the carrier holds the
	// material a signed time would come from, without verifying any
	// of it (REQ-detect-image-time).
	hasSignedTimeMaterial() (bool, error)
}

// SigstoreBundle is the carrier cosign's default sign writes: a
// sigstore bundle of version 0.3 — a DSSE envelope with one signature
// over an in-toto v1 statement naming the digest as a subject under
// the cosign sign predicate type, with the leaf certificate, a
// transparency-log entry and any RFC 3161 timestamps as verification
// material — attached to the manifest as an OCI referrer whose
// artifact type is the bundle's media type.
type SigstoreBundle struct {
	JSON []byte // the bundle as serialized
}

// SimpleSigningEnvelope is cosign's legacy carrier, a signature layer
// under the repository's sha256-<hex>.sig tag or a referrer whose
// configuration media type is application/vnd.dev.cosign.artifact.sig
// .v1+json: the layer's payload and its annotations, each as cosign
// wrote it.
type SimpleSigningEnvelope struct {
	// Payload is the layer's content, a simple-signing document
	// (application/vnd.dev.cosign.simplesigning.v1+json) naming the
	// digest at critical.image.docker-manifest-digest.
	Payload []byte
	// Signature is the dev.cosignproject.cosign/signature annotation:
	// the signature over the payload bytes, base64.
	Signature string
	// Certificate is the dev.sigstore.cosign/certificate annotation:
	// the Fulcio leaf, PEM.
	Certificate string
	// Chain is the dev.sigstore.cosign/chain annotation, PEM, or empty.
	Chain string
	// RekorBundle is the dev.sigstore.cosign/bundle annotation: the
	// signed entry timestamp with the entry's body, log index, log
	// identifier and integrated time, JSON.
	RekorBundle string
	// RFC3161Timestamp is the dev.sigstore.cosign/rfc3161timestamp
	// annotation, JSON holding the DER timestamp response base64, or
	// empty.
	RFC3161Timestamp string
}

// cosignSignPredicateType is the predicate type cosign's sign writes
// into the statement a bundle carries.
const cosignSignPredicateType = "https://sigstore.dev/cosign/sign/v1"

// bundleVersion is the one bundle version the library reads.
const bundleVersion = "0.3"

// simpleSigningType is the in-band marker of a simple-signing
// payload, at critical.type.
const simpleSigningType = "cosign container image signature"

// VerifyImage verifies an image signature over digest ("<algorithm>:
// <hex>") against the policy and the pinned trusted root, fully
// offline (REQ-image-offline-verification): the carrier is one of the
// two shapes (REQ-image-carriers); the digest in hand is the digest
// the signed content names, the signature verified over the carried
// bytes (REQ-image-digest-binding); the leaf's chain verifies against
// the root's Fulcio authorities and its signed certificate timestamp
// against the root's certificate-transparency logs; the transparency
// entry verifies against the root's log keys; every carried RFC 3161
// timestamp verifies against a pinned authority; the leaf is judged
// at a signed time, a carrier with none failing
// (REQ-image-time-source); and the identity matches policy on both
// axes (REQ-verify-identity-match). Every failure returns an error and
// no VerifiedIdentity (REQ-verify-fail-closed); success carries the
// digest and the signed time the leaf was judged at
// (REQ-image-verified-identity).
func VerifyImage(ctx context.Context, digest string, carrier ImageCarrier, id Identity, tr *TrustedRoot) (*VerifiedIdentity, error) {
	alg, sum, err := parseDigest(digest)
	if err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	if tr == nil || tr.root == nil {
		return nil, fmt.Errorf("gitprov: nil or uninitialized trusted root")
	}
	carrier, err = carrierValue(carrier)
	if err != nil {
		return nil, err
	}
	var leaf *x509.Certificate
	var signedTime time.Time
	var logIndex int64
	switch c := carrier.(type) {
	case SigstoreBundle:
		leaf, signedTime, logIndex, err = verifyBundle(c, alg, sum, tr)
	case SimpleSigningEnvelope:
		leaf, signedTime, logIndex, err = verifyEnvelope(ctx, c, alg, sum, tr)
	default:
		return nil, fmt.Errorf("gitprov: image carrier %T is neither a sigstore bundle nor a simple-signing envelope", carrier)
	}
	if err != nil {
		return nil, err
	}
	subject, issuer, err := id.match(leaf)
	if err != nil {
		return nil, err
	}
	return &VerifiedIdentity{
		Subject:             subject,
		Issuer:              issuer,
		CertFingerprint:     certFingerprint(leaf),
		RekorLogIndex:       logIndex,
		RekorIntegratedTime: signedTime.Unix(),
		TrustedRootDigest:   tr.digest,
		Digest:              alg + ":" + hex.EncodeToString(sum),
	}, nil
}

// HasImageTime reports whether an image carrier holds the material a
// signed time would come from — a transparency entry with a signed
// entry timestamp, or an RFC 3161 timestamp — verifying none of it
// (REQ-detect-image-time): present means VerifyImage can judge the
// leaf at a time; absent means the carrier is unverifiable by design,
// which a consumer tells apart from an invalid one. A carrier that is
// neither shape returns an error rather than answering false.
func HasImageTime(carrier ImageCarrier) (bool, error) {
	carrier, err := carrierValue(carrier)
	if err != nil {
		return false, err
	}
	return carrier.hasSignedTimeMaterial()
}

// carrierValue is the carrier as a value: a nil interface or a nil
// pointer to either shape is an error, never a dereference.
func carrierValue(carrier ImageCarrier) (ImageCarrier, error) {
	switch c := carrier.(type) {
	case SigstoreBundle, SimpleSigningEnvelope:
		return c, nil
	case *SigstoreBundle:
		if c == nil {
			return nil, errors.New("gitprov: nil image carrier")
		}
		return *c, nil
	case *SimpleSigningEnvelope:
		if c == nil {
			return nil, errors.New("gitprov: nil image carrier")
		}
		return *c, nil
	case nil:
		return nil, errors.New("gitprov: nil image carrier")
	}
	return nil, fmt.Errorf("gitprov: image carrier %T is neither a sigstore bundle nor a simple-signing envelope", carrier)
}

func (b SigstoreBundle) hasSignedTimeMaterial() (bool, error) {
	sb, err := parseBundle(b.JSON)
	if err != nil {
		return false, err
	}
	entries, err := sb.TlogEntries()
	if err != nil {
		return false, fmt.Errorf("gitprov: bundle log entries: %w", err)
	}
	for _, e := range entries {
		if e.HasInclusionPromise() {
			return true, nil
		}
	}
	ts, err := sb.Timestamps()
	if err != nil {
		return false, fmt.Errorf("gitprov: bundle timestamps: %w", err)
	}
	return len(ts) > 0, nil
}

func (e SimpleSigningEnvelope) hasSignedTimeMaterial() (bool, error) {
	if len(e.Payload) == 0 || e.Signature == "" || e.Certificate == "" {
		return false, errors.New("gitprov: simple-signing envelope without a payload, a signature and a certificate is not a carrier")
	}
	return e.RekorBundle != "" || e.RFC3161Timestamp != "", nil
}

// parseDigest splits "<algorithm>:<hex>" into the algorithm, compared
// exactly, and the digest as decoded bytes (REQ-image-digest-binding).
func parseDigest(digest string) (alg string, sum []byte, err error) {
	alg, h, ok := strings.Cut(digest, ":")
	if !ok || alg == "" || h == "" {
		return "", nil, fmt.Errorf("gitprov: digest %q is not <algorithm>:<hex>", digest)
	}
	sum, err = hex.DecodeString(h)
	if err != nil || len(sum) == 0 {
		return "", nil, fmt.Errorf("gitprov: digest %q: not hex", digest)
	}
	return alg, sum, nil
}

// parseBundle reads a bundle of the one version the library reads.
func parseBundle(raw []byte) (*bundle.Bundle, error) {
	var sb bundle.Bundle
	if err := sb.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("gitprov: bundle: %w", err)
	}
	want, err := bundle.MediaTypeString(bundleVersion)
	if err != nil {
		return nil, fmt.Errorf("gitprov: bundle: %w", err)
	}
	if sb.MediaType != want {
		return nil, fmt.Errorf("gitprov: bundle media type %q is not %q", sb.MediaType, want)
	}
	return &sb, nil
}

// verifyBundle verifies a sigstore bundle carrier through the bundle
// verifier of the sigstore client library, configured to the contract:
// a transparency entry required, a signed time required from the
// entry's signed entry timestamp or a pinned timestamp authority, the
// leaf's signed certificate timestamp required, the digest bound to a
// statement subject; the identity is left to this library's own
// match. Every carried timestamp then verifies on its own, the
// verifier's threshold being one: a timestamp no pinned authority
// verifies fails the carrier.
func verifyBundle(b SigstoreBundle, alg string, sum []byte, tr *TrustedRoot) (leaf *x509.Certificate, signedTime time.Time, logIndex int64, err error) {
	sb, err := parseBundle(b.JSON)
	if err != nil {
		return nil, time.Time{}, 0, err
	}
	if _, err := sb.Envelope(); err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle content is not a DSSE envelope: %w", err)
	}
	// The envelope's one signature is the client library's own rule:
	// its verifier refuses any other count before the policy runs.
	entries, err := sb.TlogEntries()
	if err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle log entries: %w", err)
	}
	if len(entries) != 1 {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle carries %d transparency-log entries, not one: not this carrier", len(entries))
	}
	verifier, err := verify.NewVerifier(tr.root,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
		verify.WithSignedCertificateTimestamps(1),
	)
	if err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle verifier: %w", err)
	}
	policy := verify.NewPolicy(verify.WithArtifactDigest(alg, sum), verify.WithoutIdentitiesUnsafe())
	res, err := verifier.Verify(sb, policy)
	if err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle: %w", err)
	}
	if res.Statement == nil || res.Statement.PredicateType != cosignSignPredicateType {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle statement predicate is not %s", cosignSignPredicateType)
	}
	// Every carried timestamp, on its own: the verifier's threshold of
	// one would tolerate a timestamp no pinned authority verifies.
	ts, err := sb.Timestamps()
	if err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle timestamps: %w", err)
	}
	sc, err := sb.SignatureContent()
	if err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle signature: %w", err)
	}
	if err := verifyTimestamps(ts, sc.Signature(), tr); err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle: %w", err)
	}
	vc, err := sb.VerificationContent()
	if err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle verification content: %w", err)
	}
	leaf = vc.Certificate()
	if leaf == nil {
		return nil, time.Time{}, 0, errors.New("gitprov: bundle carries no leaf certificate")
	}
	// The signed time the leaf was judged at: the entry's integrated
	// time where its signed entry timestamp binds it, else the
	// earliest verified timestamp; an unsigned integrated time is
	// never recorded (REQ-image-verified-identity).
	for _, t := range res.VerifiedTimestamps {
		if t.Type == "Tlog" && (signedTime.IsZero() || t.Timestamp.Before(signedTime)) {
			signedTime = t.Timestamp
		}
	}
	if signedTime.IsZero() {
		for _, t := range res.VerifiedTimestamps {
			if t.Type == "TimestampAuthority" && (signedTime.IsZero() || t.Timestamp.Before(signedTime)) {
				signedTime = t.Timestamp
			}
		}
	}
	if signedTime.IsZero() {
		return nil, time.Time{}, 0, errors.New("gitprov: bundle verified at no signed time")
	}
	// The log key valid at the signed time as the root states it: the
	// verifier judges that for an entry with a signed entry timestamp
	// and not for one without, and its rule is this one — a start the
	// root does not state is refused, an end it does not state is
	// open.
	log, ok := tr.root.RekorLogs()[hex.EncodeToString([]byte(entries[0].LogKeyID()))]
	if !ok {
		return nil, time.Time{}, 0, errors.New("gitprov: bundle entry names a log the root does not")
	}
	if log.ValidityPeriodStart.IsZero() {
		return nil, time.Time{}, 0, errors.New("gitprov: the root states no validity start for the bundle entry's log key")
	}
	if signedTime.Before(log.ValidityPeriodStart) || (!log.ValidityPeriodEnd.IsZero() && signedTime.After(log.ValidityPeriodEnd)) {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: bundle entry's log key is not valid at the signed time %s", signedTime.UTC().Format(time.RFC3339))
	}
	return leaf, signedTime, entries[0].LogIndex(), nil
}

// verifyTimestamps verifies every RFC 3161 timestamp over sig against
// a pinned authority — every one, deliberately: a timestamp no pinned
// authority verifies fails the carrier even where the entry alone
// would supply the signed time (REQ-image-offline-verification).
func verifyTimestamps(ts [][]byte, sig []byte, tr *TrustedRoot) error {
	for i, raw := range ts {
		var errs []error
		verified := false
		for _, ta := range tr.root.TimestampingAuthorities() {
			if _, err := ta.Verify(raw, sig); err == nil {
				verified = true
				break
			} else {
				errs = append(errs, err)
			}
		}
		if !verified {
			return fmt.Errorf("timestamp %d of %d verifies against no pinned authority: %w", i+1, len(ts), errors.Join(errs...))
		}
	}
	return nil
}

// verifyEnvelope verifies a simple-signing envelope carrier piece by
// piece: the payload names the digest; the signature verifies over the
// payload bytes with the leaf's key; the Rekor bundle's signed entry
// timestamp verifies, over an entry body reconstructed from the
// payload digest, the signature and the leaf, with the log key the
// entry's log identifier selects, valid at the integrated time; the
// leaf's chain verifies at that time against the root's Fulcio
// authorities and its signed certificate timestamp against the root's
// certificate-transparency logs; a carried RFC 3161 timestamp
// verifies against a pinned authority.
func verifyEnvelope(ctx context.Context, e SimpleSigningEnvelope, alg string, sum []byte, tr *TrustedRoot) (leaf *x509.Certificate, signedTime time.Time, logIndex int64, err error) {
	fail := func(format string, a ...any) (*x509.Certificate, time.Time, int64, error) {
		return nil, time.Time{}, 0, fmt.Errorf("gitprov: simple-signing envelope: "+format, a...)
	}
	if len(e.Payload) == 0 || e.Signature == "" || e.Certificate == "" || e.RekorBundle == "" {
		return fail("a payload, a signature, a certificate and a Rekor bundle are required: not this carrier")
	}
	var doc payload.SimpleContainerImage
	if err := json.Unmarshal(e.Payload, &doc); err != nil {
		return fail("payload: %w", err)
	}
	if doc.Critical.Type != simpleSigningType {
		return fail("payload type %q is not %q", doc.Critical.Type, simpleSigningType)
	}
	named := doc.Critical.Image.DockerManifestDigest
	nalg, nsum, err := parseDigest(named)
	if err != nil {
		return fail("payload names no digest: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return fail("signature: %w", err)
	}
	leaf, err = parseOnePEMCert(e.Certificate)
	if err != nil {
		return fail("certificate: %w", err)
	}
	verifier, err := signature.LoadVerifier(leaf.PublicKey, crypto.SHA256)
	if err != nil {
		return fail("leaf key: %w", err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(e.Payload)); err != nil {
		return fail("signature over the payload: %w", err)
	}
	// The binding after the signature has verified over the carried
	// bytes (REQ-image-digest-binding).
	if nalg != alg || !bytes.Equal(nsum, sum) {
		return fail("payload names %s, not the digest in hand", named)
	}
	var rb cbundle.RekorBundle
	if err := json.Unmarshal([]byte(e.RekorBundle), &rb); err != nil {
		return fail("Rekor bundle: %w", err)
	}
	body, err := HashedRekordBody(ctx, e.Payload, sig, leaf)
	if err != nil {
		return fail("entry body: %w", err)
	}
	logID, err := hex.DecodeString(rb.Payload.LogID)
	if err != nil {
		return fail("Rekor bundle log identifier: %w", err)
	}
	entry, err := tlog.NewEntry(body, rb.Payload.IntegratedTime, rb.Payload.LogIndex, logID, rb.SignedEntryTimestamp, nil)
	if err != nil {
		return fail("entry: %w", err)
	}
	if err := tlog.VerifySET(entry, tr.root.RekorLogs()); err != nil {
		return fail("signed entry timestamp: %w", err)
	}
	signedTime = entry.IntegratedTime()
	chain, err := parsePEMCerts(e.Chain)
	if err != nil {
		return fail("chain: %w", err)
	}
	if err := judgeLeafAt(leaf, chain, signedTime, tr); err != nil {
		return fail("%w", err)
	}
	if e.RFC3161Timestamp != "" {
		var ts cbundle.RFC3161Timestamp
		if err := json.Unmarshal([]byte(e.RFC3161Timestamp), &ts); err != nil {
			return fail("RFC 3161 timestamp: %w", err)
		}
		if err := verifyTimestamps([][]byte{ts.SignedRFC3161Timestamp}, sig, tr); err != nil {
			return fail("%w", err)
		}
	}
	return leaf, signedTime, rb.Payload.LogIndex, nil
}

// judgeLeafAt judges a Fulcio leaf at a signed time (REQ-verify-
// signed-time, REQ-image-time-source): its chain, through the
// intermediates the carrier attached and the pinned root's own,
// verifies at that time against the root's Fulcio authorities, and its
// signed certificate timestamp verifies against the root's
// certificate-transparency log keys.
func judgeLeafAt(leaf *x509.Certificate, extra []*x509.Certificate, at time.Time, tr *TrustedRoot) error {
	roots, intermediates, err := tr.fulcioPools()
	if err != nil {
		return err
	}
	for _, c := range extra {
		if !c.Equal(leaf) {
			intermediates.AddCert(c)
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return fmt.Errorf("gitprov: certificate chain at the signed time %s: %w", at.UTC().Format(time.RFC3339), err)
	}
	if err := verify.VerifySignedCertificateTimestamp(chains, 1, tr.root); err != nil {
		return fmt.Errorf("gitprov: signed certificate timestamp: %w", err)
	}
	return nil
}

// parseOnePEMCert reads exactly one certificate from PEM.
func parseOnePEMCert(pemStr string) (*x509.Certificate, error) {
	certs, err := parsePEMCerts(pemStr)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("%d certificates in PEM, want one", len(certs))
	}
	return certs[0], nil
}

// parsePEMCerts reads every certificate block in PEM; a block that is
// not a certificate, or bytes that are not PEM, fail.
func parsePEMCerts(pemStr string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(pemStr)
	for len(bytes.TrimSpace(rest)) > 0 {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("not PEM")
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}
