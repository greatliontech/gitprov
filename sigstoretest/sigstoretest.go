// Package sigstoretest is a synthetic sigstore for tests, this
// library's own and its consumers': a virtual Rekor log and
// timestamp authority (sigstore-go's), and a Fulcio of its own that
// issues short-lived leaves carrying a signed certificate timestamp
// from its own certificate-transparency log — the part the virtual
// one does not model, and the part every verification judged at a
// signed time needs. Its trusted root is pinned through the same
// bytes path a real one takes, so what the fixtures verify against
// is what a caller pins.
//
// Nothing here is a fixture of real bytes: the shapes are cosign's
// and gitsign's, their markers spelled here on their own so a test of
// the verifier's checks does not share the verifier's constants. The
// real captures live with the tests that record them.
//
// A Sigstore is safe for concurrent use once built: a leaf's serial
// is drawn at random, and nothing else is written after New.
package sigstoretest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/greatliontech/gitprov"
)

// Sigstore is one synthetic sigstore: the virtual log and timestamp
// authority, the Fulcio with its transparency log, and the trusted
// root pinning them.
type Sigstore struct {
	vs           *ca.VirtualSigstore
	rootCert     *x509.Certificate
	intermediate *x509.Certificate
	interKey     *ecdsa.PrivateKey
	ctKey        *ecdsa.PrivateKey
	root         *gitprov.TrustedRoot
	rootJSON     []byte
}

// New builds a sigstore whose root pins its own authorities and
// logs, valid from an hour ago for a day; a leaf it issues is valid
// from a minute before its issue to ten minutes after (Leaf), so a
// signed time a fixture states must fall in that window.
func New(t testing.TB) *Sigstore {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	s := &Sigstore{vs: vs}
	rootKey := ecdsaKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sigstoretest-fulcio-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	s.rootCert = issue(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	s.interKey = ecdsaKey(t)
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "sigstoretest-fulcio-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	s.intermediate = issue(t, interTemplate, s.rootCert, &s.interKey.PublicKey, rootKey)
	s.ctKey = ecdsaKey(t)
	s.rootJSON, s.root = s.buildRoot(t, s.RekorLogs(t))
	return s
}

// TrustedRootWithRekorLogs is a root of this sigstore — the same
// Fulcio, transparency log and timestamp authority — naming the given
// Rekor logs in place of the virtual log's own entry. A test that
// judges an entry under another validity window takes RekorLogs,
// changes the window and pins the result here, rather than moving
// the signed time out of the leaf's own window.
func (s *Sigstore) TrustedRootWithRekorLogs(t testing.TB, rekor map[string]*root.TransparencyLog) *gitprov.TrustedRoot {
	t.Helper()
	_, tr := s.buildRoot(t, rekor)
	return tr
}

func (s *Sigstore) buildRoot(t testing.TB, rekor map[string]*root.TransparencyLog) ([]byte, *gitprov.TrustedRoot) {
	t.Helper()
	logID := s.ctLogID(t)
	ctlogs := map[string]*root.TransparencyLog{hex.EncodeToString(logID[:]): {
		ID:                  logID[:],
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(24 * time.Hour),
		HashFunc:            crypto.SHA256,
		PublicKey:           &s.ctKey.PublicKey,
		SignatureHashFunc:   crypto.SHA256,
	}}
	fulcio := &root.FulcioCertificateAuthority{
		Root:                s.rootCert,
		Intermediates:       []*x509.Certificate{s.intermediate},
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(24 * time.Hour),
		URI:                 "https://fulcio.sigstoretest.invalid",
	}
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{fulcio}, ctlogs, s.vs.TimestampingAuthorities(), rekor)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := gitprov.ParseTrustedRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, pinned
}

// TrustedRoot is the pinned root.
func (s *Sigstore) TrustedRoot() *gitprov.TrustedRoot { return s.root }

// RootJSON is a copy of the root's bytes, as pinned.
func (s *Sigstore) RootJSON() []byte { return append([]byte(nil), s.rootJSON...) }

// Virtual is the underlying virtual sigstore, for its Rekor log —
// RekorSignPayload, GetInclusionProof — and its timestamp authority,
// TimestampResponse. Its own Fulcio is not this sigstore's: a leaf
// from GenerateLeafCert carries no certificate timestamp and chains
// to no authority the pinned root names, so such a leaf never
// verifies here.
func (s *Sigstore) Virtual() *ca.VirtualSigstore { return s.vs }

// Intermediate is the Fulcio intermediate every leaf chains to.
func (s *Sigstore) Intermediate() *x509.Certificate { return s.intermediate }

// RekorLogs is the virtual Rekor log as a real root keys it: the
// virtual sigstore holds the log's identifier as the bytes of its
// hex spelling, which a root's JSON form would hex-encode again.
func (s *Sigstore) RekorLogs(t testing.TB) map[string]*root.TransparencyLog {
	t.Helper()
	out := map[string]*root.TransparencyLog{}
	for k, l := range s.vs.RekorLogs() {
		id, err := hex.DecodeString(string(l.ID))
		if err != nil {
			t.Fatal(err)
		}
		c := *l
		c.ID = id
		out[k] = &c
	}
	return out
}

// RekorLogID is the virtual log's identifier, hex, as an entry names
// it.
func (s *Sigstore) RekorLogID(t testing.TB) string {
	t.Helper()
	id, err := s.vs.RekorLogID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (s *Sigstore) ctLogID(t testing.TB) [32]byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&s.ctKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(spki)
}

// The window a leaf is valid in, around its issue.
const (
	leafBefore = time.Minute
	leafAfter  = 10 * time.Minute
)

// Leaf issues a short-lived Fulcio leaf for subject and issuer, as
// Fulcio does: the email as a SAN, the issuer in the Fulcio
// extension, code signing, valid from a minute before now to ten
// minutes after, and an embedded signed certificate timestamp over
// the pre-certificate — the base leaf without the timestamp
// extension — signed by the log key, as a verifier reconstructs it
// from the final leaf and the issuing intermediate. The serial is
// drawn at random.
func (s *Sigstore) Leaf(t testing.TB, subject, issuer string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	key := ecdsaKey(t)
	template := &x509.Certificate{
		SerialNumber:   serial,
		EmailAddresses: []string{subject},
		NotBefore:      time.Now().Add(-leafBefore),
		NotAfter:       time.Now().Add(leafAfter),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Value: []byte(issuer),
		}},
	}
	base := issue(t, template, s.intermediate, &key.PublicKey, s.interKey)
	logID := s.ctLogID(t)
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logID},
		Timestamp:  uint64(time.Now().UnixMilli()),
	}
	entry := ct.LogEntry{Leaf: ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: sct.Timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(s.intermediate.RawSubjectPublicKeyInfo),
				TBSCertificate: base.RawTBSCertificate,
			},
		},
	}}
	input, err := ct.SerializeSCTSignatureInput(sct, entry)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(input)
	sig, err := s.ctKey.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sct.Signature = ct.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA256, Signature: tls.ECDSA},
		Signature: sig,
	}
	list, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		t.Fatal(err)
	}
	listBytes, err := tls.Marshal(*list)
	if err != nil {
		t.Fatal(err)
	}
	asnList, err := asn1.Marshal(listBytes)
	if err != nil {
		t.Fatal(err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT), Value: asnList})
	return issue(t, template, s.intermediate, &key.PublicKey, s.interKey), key
}

// PEM renders a certificate as cosign annotates one.
func PEM(t testing.TB, c *x509.Certificate) string {
	t.Helper()
	b, err := cryptoutils.MarshalCertificateToPEM(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// RefuseNetwork installs a transport on the process's default that
// fails the test on any round trip, restored when the test ends: the
// witness that a verification is offline.
func RefuseNetwork(t testing.TB) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = refuseNetwork{t: t}
	t.Cleanup(func() { http.DefaultTransport = prev })
}

type refuseNetwork struct{ t testing.TB }

func (g refuseNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	g.t.Errorf("network attempt during offline verification: %s %s", r.Method, r.URL)
	return nil, fmt.Errorf("network disabled: %s", r.URL)
}

// signedTimeFor is the signed time a fixture states: now, or the
// option's, which must fall in the issued leaf's own validity — a
// time outside it would build a fixture that fails for the leaf's
// validity, not for what the test means to state. The leaf is the
// one source of the window: its NotBefore and NotAfter, not a clock
// read again.
func signedTimeFor(t testing.TB, at time.Time, leaf *x509.Certificate) time.Time {
	t.Helper()
	if at.IsZero() {
		return time.Now()
	}
	if at.Before(leaf.NotBefore) || at.After(leaf.NotAfter) {
		t.Fatalf("sigstoretest: a signed time of %s is outside the leaf's validity (%s to %s); move the root's window instead", at.Format(time.RFC3339), leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	return at
}

// CosignSignPredicateType is the predicate type cosign's sign writes.
const CosignSignPredicateType = "https://sigstore.dev/cosign/sign/v1"

// SimpleSigningType is the in-band marker of a simple-signing payload.
const SimpleSigningType = "cosign container image signature"

// BundleOptions shape a bundle away from the default — a Rekor v1
// entry (an inclusion proof and a signed entry timestamp) with one
// timestamp from the pinned authority.
type BundleOptions struct {
	// Predicate is the statement's predicate type; empty is cosign's.
	Predicate string
	// NoPromise drops the entry's signed entry timestamp, the shape of
	// a Rekor v2 entry.
	NoPromise bool
	// NoTimestamp drops the timestamp; NoEntry the entry.
	NoTimestamp, NoEntry bool
	// TwoSignatures carries the envelope's signature twice; TwoEntries
	// the entry twice.
	TwoSignatures, TwoEntries bool
	// TimestampBy is the authority the timestamp comes from in place
	// of this sigstore's; ExtraTimestampBy adds a second timestamp
	// from that authority beside the first. Both are moot under
	// NoTimestamp.
	TimestampBy, ExtraTimestampBy *Sigstore
	// MediaType replaces the bundle's.
	MediaType string
	// IntegratedAt is the entry's integrated time, now when zero; it
	// must fall in the leaf's window (New), the builder failing the
	// test otherwise.
	IntegratedAt time.Time
}

// Bundle builds a sigstore bundle as cosign's default sign would for
// digest, signed by a leaf for subject and issuer.
func (s *Sigstore) Bundle(t testing.TB, digest, subject, issuer string, o BundleOptions) gitprov.SigstoreBundle {
	t.Helper()
	predicate := o.Predicate
	if predicate == "" {
		predicate = CosignSignPredicateType
	}
	leaf, key := s.Leaf(t, subject, issuer)
	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	es, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer, Pub: leaf.PublicKey.(*ecdsa.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	env, err := es.SignPayload(context.Background(), "application/vnd.in-toto+json", Statement(t, digest, predicate))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	at := signedTimeFor(t, o.IntegratedAt, leaf)
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
		},
	}
	if o.MediaType != "" {
		pb.MediaType = o.MediaType
	}
	if !o.NoEntry {
		entry, err := s.vs.GenerateTlogEntry(leaf, env, sig, at.Unix(), true)
		if err != nil {
			t.Fatal(err)
		}
		tle := entry.TransparencyLogEntry()
		// The projection names no kind and carries no signed entry
		// timestamp; the log signs one over the entry as it records
		// it, and a bundle names it as the promise.
		var kind struct{ Kind, APIVersion string }
		if err := json.Unmarshal(tle.CanonicalizedBody, &kind); err != nil {
			t.Fatal(err)
		}
		tle.KindVersion = &protorekor.KindVersion{Kind: kind.Kind, Version: kind.APIVersion}
		set, err := s.vs.RekorSignPayload(tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(tle.CanonicalizedBody), IntegratedTime: at.Unix(), LogIndex: 0, LogID: s.RekorLogID(t)})
		if err != nil {
			t.Fatal(err)
		}
		tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
		if o.NoPromise {
			tle.InclusionPromise = nil
		}
		pb.VerificationMaterial.TlogEntries = append(pb.VerificationMaterial.TlogEntries, tle)
		if o.TwoEntries {
			pb.VerificationMaterial.TlogEntries = append(pb.VerificationMaterial.TlogEntries, tle)
		}
	}
	if !o.NoTimestamp {
		by := s
		if o.TimestampBy != nil {
			by = o.TimestampBy
		}
		tsr, err := by.vs.TimestampResponse(sig)
		if err != nil {
			t.Fatal(err)
		}
		pb.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: tsr}},
		}
		if o.ExtraTimestampBy != nil {
			extra, err := o.ExtraTimestampBy.vs.TimestampResponse(sig)
			if err != nil {
				t.Fatal(err)
			}
			pb.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps = append(pb.VerificationMaterial.TimestampVerificationData.Rfc3161Timestamps, &protocommon.RFC3161SignedTimestamp{SignedTimestamp: extra})
		}
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	de := &protodsse.Envelope{Payload: payload, PayloadType: env.PayloadType, Signatures: []*protodsse.Signature{{Sig: sig}}}
	if o.TwoSignatures {
		de.Signatures = append(de.Signatures, &protodsse.Signature{Sig: sig})
	}
	pb.Content = &protobundle.Bundle_DsseEnvelope{DsseEnvelope: de}
	raw, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	return gitprov.SigstoreBundle{JSON: raw}
}

// Statement is the in-toto statement cosign's sign writes for a
// digest: the digest as the one subject, under the predicate.
func Statement(t testing.TB, digest, predicate string) []byte {
	t.Helper()
	alg, h, ok := strings.Cut(digest, ":")
	if !ok || alg == "" || h == "" {
		t.Fatalf("sigstoretest: digest %q is not <algorithm>:<hex>", digest)
	}
	st := &intotov1.Statement{
		Type:          intotov1.StatementTypeUri,
		Subject:       []*intotov1.ResourceDescriptor{{Digest: map[string]string{alg: h}}},
		PredicateType: predicate,
		Predicate:     &structpb.Struct{},
	}
	b, err := protojson.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// EnvelopeOptions shape a simple-signing envelope away from the
// default — the payload naming the digest, a Rekor bundle, no chain,
// no timestamp.
type EnvelopeOptions struct {
	// NoRekorBundle drops the Rekor bundle; Timestamp adds one.
	NoRekorBundle, Timestamp bool
	// TimestampBy is the authority the timestamp comes from in place
	// of this sigstore's; moot without Timestamp.
	TimestampBy *Sigstore
	// WithChain annotates the intermediate.
	WithChain bool
	// NamedDigest is the digest the payload names in place of the one
	// signed for; PayloadType the marker in place of cosign's.
	NamedDigest, PayloadType string
	// IntegratedAt is the Rekor bundle's integrated time, now when
	// zero; it must fall in the leaf's window (New), the builder
	// failing the test otherwise; moot under NoRekorBundle.
	IntegratedAt time.Time
}

// Envelope builds a simple-signing envelope as cosign's legacy sign
// would for digest, signed by a leaf for subject and issuer; the
// Rekor bundle's entry body is the one a verifier reconstructs.
func (s *Sigstore) Envelope(t testing.TB, digest, subject, issuer string, o EnvelopeOptions) gitprov.SimpleSigningEnvelope {
	t.Helper()
	named := o.NamedDigest
	if named == "" {
		named = digest
	}
	ptype := o.PayloadType
	if ptype == "" {
		ptype = SimpleSigningType
	}
	doc := map[string]any{"critical": map[string]any{
		"identity": map[string]any{"docker-reference": "registry.example.com/image"},
		"image":    map[string]any{"docker-manifest-digest": named},
		"type":     ptype,
	}, "optional": nil}
	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	leaf, key := s.Leaf(t, subject, issuer)
	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	e := gitprov.SimpleSigningEnvelope{Payload: payload, Signature: base64.StdEncoding.EncodeToString(sig), Certificate: PEM(t, leaf)}
	if o.WithChain {
		e.Chain = PEM(t, s.intermediate)
	}
	if !o.NoRekorBundle {
		body, err := gitprov.HashedRekordBody(context.Background(), payload, sig, leaf)
		if err != nil {
			t.Fatal(err)
		}
		at := signedTimeFor(t, o.IntegratedAt, leaf)
		rp := tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(body), IntegratedTime: at.Unix(), LogIndex: 7, LogID: s.RekorLogID(t)}
		set, err := s.vs.RekorSignPayload(rp)
		if err != nil {
			t.Fatal(err)
		}
		rb, err := json.Marshal(cbundle.RekorBundle{SignedEntryTimestamp: set, Payload: cbundle.RekorPayload(rp)})
		if err != nil {
			t.Fatal(err)
		}
		e.RekorBundle = string(rb)
	}
	if o.Timestamp {
		by := s
		if o.TimestampBy != nil {
			by = o.TimestampBy
		}
		tsr, err := by.vs.TimestampResponse(sig)
		if err != nil {
			t.Fatal(err)
		}
		ts, err := json.Marshal(cbundle.RFC3161Timestamp{SignedRFC3161Timestamp: tsr})
		if err != nil {
			t.Fatal(err)
		}
		e.RFC3161Timestamp = string(ts)
	}
	return e
}

func ecdsaKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t testing.TB, template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
