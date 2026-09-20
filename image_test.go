package gitprov

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	intotov1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	cbundle "github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// The image fixtures are synthetic: a virtual sigstore — its own
// Fulcio, Rekor, certificate-transparency and timestamp authorities —
// signs what the tests ask, and its trusted root is pinned through
// the same bytes path a real one takes. Each carrier's shape is
// cosign's, built from cosign's own constants; the real captured
// vectors under testdata, once present, prove the shapes against
// bytes cosign wrote.

const (
	imageIdentity = "signer@example.com"
	imageIssuer   = "https://accounts.example.com"
	imageDigest   = "sha256:8d1b7cf2f8a1f2a1e1c4b5d0a2f2e8e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5"
)

func imagePolicy() Identity { return Identity{Issuer: imageIssuer, Subject: imageIdentity} }

// sigstoreFixture is one synthetic sigstore: the virtual Rekor and
// timestamp authority, the Fulcio with a transparency log that
// issues leaves, and the trusted root pinning them.
type sigstoreFixture struct {
	vs     *ca.VirtualSigstore
	fulcio *virtualFulcio
	tr     *TrustedRoot
}

func newSigstore(t *testing.T) *sigstoreFixture {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	f := newVirtualFulcio(t)
	return &sigstoreFixture{vs: vs, fulcio: f, tr: f.trustedRoot(t, vs, nil)}
}

// statementFor is the in-toto statement cosign's sign writes for a
// digest: the digest as the one subject, under the sign predicate.
func statementFor(t *testing.T, digest, predicate string) []byte {
	t.Helper()
	alg, hex, _ := strings.Cut(digest, ":")
	st := &intotov1.Statement{
		Type:          intotov1.StatementTypeUri,
		Subject:       []*intotov1.ResourceDescriptor{{Digest: map[string]string{alg: hex}}},
		PredicateType: predicate,
		Predicate:     &structpb.Struct{},
	}
	b, err := protojson.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bundleOpts shape a synthetic bundle away from the default — a Rekor
// v1 entry (an inclusion proof and a signed entry timestamp) with a
// timestamp: a Rekor v2-like entry (the proof, no entry timestamp),
// no timestamp, no entry, a second signature, a foreign timestamp
// authority, a media type of another version.
type bundleOpts struct {
	predicate     string
	noPromise     bool
	noTimestamp   bool
	noEntry       bool
	twoSignatures bool
	foreignTSA    *sigstoreFixture // the timestamp's authority in place of the pinned one
	extraTSA      *sigstoreFixture // a second timestamp, from this authority, beside the pinned one
	mediaType     string
	twoEntries    bool // the entry carried twice
	integratedAt  time.Time
}

// bundleFor builds a sigstore bundle as cosign's sign would, from the
// virtual sigstore's leaf, log and timestamp authority.
func bundleFor(t *testing.T, s *sigstoreFixture, digest string, o bundleOpts) SigstoreBundle {
	t.Helper()
	vs := s.vs
	predicate := o.predicate
	if predicate == "" {
		predicate = cosignSignPredicateType
	}
	leaf, key := s.fulcio.leaf(t, imageIdentity, imageIssuer)
	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	es, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer, Pub: leaf.PublicKey.(*ecdsa.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	env, err := es.SignPayload(context.Background(), "application/vnd.in-toto+json", statementFor(t, digest, predicate))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	at := o.integratedAt
	if at.IsZero() {
		at = time.Now()
	}
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
		},
	}
	if o.mediaType != "" {
		pb.MediaType = o.mediaType
	}
	if !o.noEntry {
		entry, err := vs.GenerateTlogEntry(leaf, env, sig, at.Unix(), true)
		if err != nil {
			t.Fatal(err)
		}
		tle := entry.TransparencyLogEntry()
		// The entry constructor leaves the kind unnamed; a bundle
		// names it as the body does.
		var kind struct{ Kind, APIVersion string }
		if err := json.Unmarshal(tle.CanonicalizedBody, &kind); err != nil {
			t.Fatal(err)
		}
		tle.KindVersion = &protorekor.KindVersion{Kind: kind.Kind, Version: kind.APIVersion}
		// The projection carries no signed entry timestamp; the log
		// signs one over the entry as it records it, and a bundle
		// names it as the promise.
		logID, err := vs.RekorLogID()
		if err != nil {
			t.Fatal(err)
		}
		set, err := vs.RekorSignPayload(tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(tle.CanonicalizedBody), IntegratedTime: at.Unix(), LogIndex: 0, LogID: logID})
		if err != nil {
			t.Fatal(err)
		}
		tle.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
		if o.noPromise {
			tle.InclusionPromise = nil
		}
		pb.VerificationMaterial.TlogEntries = append(pb.VerificationMaterial.TlogEntries, tle)
		if o.twoEntries {
			pb.VerificationMaterial.TlogEntries = append(pb.VerificationMaterial.TlogEntries, tle)
		}
	}
	if !o.noTimestamp {
		tsa := vs
		if o.foreignTSA != nil {
			tsa = o.foreignTSA.vs
		}
		tsr, err := tsa.TimestampResponse(sig)
		if err != nil {
			t.Fatal(err)
		}
		pb.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: tsr}},
		}
		if o.extraTSA != nil {
			extra, err := o.extraTSA.vs.TimestampResponse(sig)
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
	if o.twoSignatures {
		de.Signatures = append(de.Signatures, &protodsse.Signature{Sig: sig})
	}
	pb.Content = &protobundle.Bundle_DsseEnvelope{DsseEnvelope: de}
	raw, err := protojson.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	return SigstoreBundle{JSON: raw}
}

// envelopeOpts shape a synthetic simple-signing envelope away from the
// default: no Rekor bundle, a timestamp, a foreign timestamp
// authority, a chain annotation, a different named digest.
type envelopeOpts struct {
	noRekorBundle bool
	timestamp     bool
	foreignTSA    *sigstoreFixture
	withChain     bool
	namedDigest   string
	payloadType   string // critical.type in place of the marker
	integratedAt  time.Time
}

// envelopeFor builds a simple-signing envelope as cosign's legacy sign
// would, the Rekor bundle's entry body the one the library must
// reconstruct.
func envelopeFor(t *testing.T, s *sigstoreFixture, digest string, o envelopeOpts) SimpleSigningEnvelope {
	t.Helper()
	vs := s.vs
	named := o.namedDigest
	if named == "" {
		named = digest
	}
	ptype := o.payloadType
	if ptype == "" {
		ptype = simpleSigningType
	}
	doc := map[string]any{"critical": map[string]any{
		"identity": map[string]any{"docker-reference": "registry.example.com/plugin"},
		"image":    map[string]any{"docker-manifest-digest": named},
		"type":     ptype,
	}, "optional": nil}
	payload, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	leaf, key := s.fulcio.leaf(t, imageIdentity, imageIssuer)
	signer, err := signature.LoadECDSASignerVerifier(key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	e := SimpleSigningEnvelope{Payload: payload, Signature: base64.StdEncoding.EncodeToString(sig), Certificate: pemOf(leaf)}
	if o.withChain {
		e.Chain = pemOf(s.fulcio.intermediate)
	}
	if !o.noRekorBundle {
		body, err := hashedRekordBody(context.Background(), payload, sig, leaf)
		if err != nil {
			t.Fatal(err)
		}
		logID, err := vs.RekorLogID()
		if err != nil {
			t.Fatal(err)
		}
		at := o.integratedAt
		if at.IsZero() {
			at = time.Now()
		}
		rp := tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(body), IntegratedTime: at.Unix(), LogIndex: 7, LogID: logID}
		set, err := vs.RekorSignPayload(rp)
		if err != nil {
			t.Fatal(err)
		}
		rb, err := json.Marshal(cbundle.RekorBundle{SignedEntryTimestamp: set, Payload: cbundle.RekorPayload(rp)})
		if err != nil {
			t.Fatal(err)
		}
		e.RekorBundle = string(rb)
	}
	if o.timestamp {
		tsa := vs
		if o.foreignTSA != nil {
			tsa = o.foreignTSA.vs
		}
		tsr, err := tsa.TimestampResponse(sig)
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

// A bundle cosign's default sign writes verifies: the identity, the
// leaf fingerprint, the root's digest, the digest verified, the entry's
// index and its integrated time as the signed time.
func TestVerifyImageBundle(t *testing.T) {
	s := newSigstore(t)
	tr := s.tr
	at := time.Now().Truncate(time.Second)
	b := bundleFor(t, s, imageDigest, bundleOpts{integratedAt: at})
	vi, err := VerifyImage(context.Background(), imageDigest, b, imagePolicy(), tr)
	if err != nil {
		t.Fatalf("VerifyImage: %v", err)
	}
	if vi.Subject != imageIdentity || vi.Issuer != imageIssuer || vi.Digest != imageDigest || vi.TrustedRootDigest != tr.Digest() {
		t.Fatalf("verified identity = %+v", vi)
	}
	if vi.RekorIntegratedTime != at.Unix() || vi.RekorLogIndex != 0 {
		t.Fatalf("signed time %d (want %d), log index %d", vi.RekorIntegratedTime, at.Unix(), vi.RekorLogIndex)
	}
	if !strings.HasPrefix(vi.CertFingerprint, "sha256:") {
		t.Fatalf("fingerprint %q", vi.CertFingerprint)
	}
	// The pointer form is the same carrier.
	if _, err := VerifyImage(context.Background(), imageDigest, &b, imagePolicy(), tr); err != nil {
		t.Fatalf("pointer carrier: %v", err)
	}
}

// A simple-signing envelope cosign's legacy sign writes verifies, with
// or without its chain annotation and its timestamp, the Rekor
// bundle's integrated time being the signed time and its index the
// entry's.
func TestVerifyImageEnvelope(t *testing.T) {
	s := newSigstore(t)
	tr := s.tr
	at := time.Now().Truncate(time.Second)
	for name, o := range map[string]envelopeOpts{
		"bare":            {integratedAt: at},
		"chain":           {integratedAt: at, withChain: true},
		"timestamp":       {integratedAt: at, timestamp: true},
		"chain+timestamp": {integratedAt: at, withChain: true, timestamp: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := envelopeFor(t, s, imageDigest, o)
			vi, err := VerifyImage(context.Background(), imageDigest, e, imagePolicy(), tr)
			if err != nil {
				t.Fatalf("VerifyImage: %v", err)
			}
			if vi.Subject != imageIdentity || vi.Issuer != imageIssuer || vi.Digest != imageDigest || vi.RekorLogIndex != 7 || vi.RekorIntegratedTime != at.Unix() {
				t.Fatalf("verified identity = %+v", vi)
			}
		})
	}
}

// The digest in hand must be the digest the signed content names:
// another digest, or a case-different spelling of the algorithm, fails
// on both carriers, and a differently cased hex of the same digest
// passes as decoded bytes.
func TestVerifyImageDigestBinding(t *testing.T) {
	s := newSigstore(t)
	tr := s.tr
	other := "sha256:" + strings.Repeat("ab", 32)
	b := bundleFor(t, s, imageDigest, bundleOpts{})
	e := envelopeFor(t, s, imageDigest, envelopeOpts{})
	for name, c := range map[string]ImageCarrier{"bundle": b, "envelope": e} {
		if _, err := VerifyImage(context.Background(), other, c, imagePolicy(), tr); err == nil {
			t.Errorf("%s: another digest verified", name)
		}
		if _, err := VerifyImage(context.Background(), "SHA256:"+strings.TrimPrefix(imageDigest, "sha256:"), c, imagePolicy(), tr); err == nil {
			t.Errorf("%s: another algorithm spelling verified", name)
		}
		upper := "sha256:" + strings.ToUpper(strings.TrimPrefix(imageDigest, "sha256:"))
		if vi, err := VerifyImage(context.Background(), upper, c, imagePolicy(), tr); err != nil || vi.Digest != imageDigest {
			t.Errorf("%s: the same digest in upper-case hex: %v %+v", name, err, vi)
		}
	}
	// An envelope naming another digest than the one it is judged for,
	// its own signature intact.
	e2 := envelopeFor(t, s, imageDigest, envelopeOpts{namedDigest: other})
	if _, err := VerifyImage(context.Background(), imageDigest, e2, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "not the digest in hand") {
		t.Errorf("a payload naming another digest: %v", err)
	}
}

// The identity must match on both axes; a mismatch fails after the
// carrier verified.
func TestVerifyImageIdentityMismatch(t *testing.T) {
	s := newSigstore(t)
	tr := s.tr
	b := bundleFor(t, s, imageDigest, bundleOpts{})
	e := envelopeFor(t, s, imageDigest, envelopeOpts{})
	for name, c := range map[string]ImageCarrier{"bundle": b, "envelope": e} {
		if _, err := VerifyImage(context.Background(), imageDigest, c, Identity{Issuer: imageIssuer, Subject: "other@example.com"}, tr); !errors.Is(err, ErrIdentityMismatch) {
			t.Errorf("%s: subject mismatch: %v", name, err)
		}
		if _, err := VerifyImage(context.Background(), imageDigest, c, Identity{Issuer: "https://other.example.com", Subject: imageIdentity}, tr); !errors.Is(err, ErrIdentityMismatch) {
			t.Errorf("%s: issuer mismatch: %v", name, err)
		}
	}
}

// The signed time: a Rekor v1 entry (signed entry timestamp) needs no
// timestamp; a Rekor v2-like entry (inclusion proof, no entry
// timestamp) takes its time from a timestamp and fails without one; a
// timestamp with no entry is not a carrier; a timestamp no pinned
// authority verifies fails the carrier even where the entry alone
// would supply the time.
func TestVerifyImageSignedTime(t *testing.T) {
	s := newSigstore(t)
	tr := s.tr
	foreign := newSigstore(t)
	at := time.Now().Truncate(time.Second)
	cases := []struct {
		name string
		opts bundleOpts
		ok   bool
		want string
	}{
		{"v1 entry, no timestamp", bundleOpts{noTimestamp: true, integratedAt: at}, true, ""},
		{"v2 entry with timestamp", bundleOpts{noPromise: true, integratedAt: at}, true, ""},
		{"v2 entry without timestamp", bundleOpts{noPromise: true, noTimestamp: true}, false, "timestamp"},
		{"timestamp without entry", bundleOpts{noEntry: true}, false, "not one: not this carrier"},
		{"foreign timestamp beside a v1 entry", bundleOpts{foreignTSA: foreign, integratedAt: at}, false, "no pinned authority"},
		{"a foreign timestamp beside a pinned one", bundleOpts{extraTSA: foreign, integratedAt: at}, false, "no pinned authority"},
		{"two timestamps from the pinned authority", bundleOpts{extraTSA: s, integratedAt: at}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := bundleFor(t, s, imageDigest, c.opts)
			vi, err := VerifyImage(context.Background(), imageDigest, b, imagePolicy(), tr)
			if c.ok {
				if err != nil {
					t.Fatalf("VerifyImage: %v", err)
				}
				if c.opts.noPromise {
					// The time is the timestamp's, not the unsigned
					// integrated time the entry asserts.
					if vi.RekorIntegratedTime == at.Unix() && time.Since(at) > 2*time.Second {
						t.Fatalf("the unsigned integrated time %d recorded as the signed time", vi.RekorIntegratedTime)
					}
				} else if vi.RekorIntegratedTime != at.Unix() {
					t.Fatalf("signed time %d, want the entry's %d", vi.RekorIntegratedTime, at.Unix())
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("VerifyImage = %v, want a failure naming %q", err, c.want)
			}
		})
	}
	// The envelope: a Rekor bundle is required; a foreign timestamp
	// beside it fails.
	e := envelopeFor(t, s, imageDigest, envelopeOpts{noRekorBundle: true})
	if _, err := VerifyImage(context.Background(), imageDigest, e, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "not this carrier") {
		t.Errorf("an envelope without a Rekor bundle: %v", err)
	}
	e = envelopeFor(t, s, imageDigest, envelopeOpts{timestamp: true, foreignTSA: foreign})
	if _, err := VerifyImage(context.Background(), imageDigest, e, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "no pinned authority") {
		t.Errorf("an envelope with a foreign timestamp: %v", err)
	}
}

// The carrier's shape is exact: a bundle of another version, one with
// two signatures, one under another predicate, and one signed by a
// leaf the pinned root does not chain fail; an envelope whose Rekor
// bundle names a log the root does not know fails.
func TestVerifyImageCarrierShape(t *testing.T) {
	s := newSigstore(t)
	tr := s.tr
	foreign := newSigstore(t)
	for name, o := range map[string]bundleOpts{
		"another version": {mediaType: "application/vnd.dev.sigstore.bundle.v0.2+json"},
		"two signatures":  {twoSignatures: true},
		"other predicate": {predicate: "https://slsa.dev/provenance/v1"},
	} {
		b := bundleFor(t, s, imageDigest, o)
		if _, err := VerifyImage(context.Background(), imageDigest, b, imagePolicy(), tr); err == nil {
			t.Errorf("%s verified", name)
		}
	}
	if _, err := VerifyImage(context.Background(), imageDigest, bundleFor(t, foreign, imageDigest, bundleOpts{}), imagePolicy(), tr); err == nil {
		t.Error("a bundle from a foreign sigstore verified")
	}
	if _, err := VerifyImage(context.Background(), imageDigest, envelopeFor(t, foreign, imageDigest, envelopeOpts{}), imagePolicy(), tr); err == nil {
		t.Error("an envelope from a foreign sigstore verified")
	}
	if _, err := VerifyImage(context.Background(), imageDigest, SigstoreBundle{JSON: []byte("{")}, imagePolicy(), tr); err == nil {
		t.Error("a malformed bundle verified")
	}
	if _, err := VerifyImage(context.Background(), imageDigest, nil, imagePolicy(), tr); err == nil {
		t.Error("a nil carrier verified")
	}
	// A nil pointer to either shape is an error, never a dereference.
	var nb *SigstoreBundle
	var ne *SimpleSigningEnvelope
	if _, err := VerifyImage(context.Background(), imageDigest, nb, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "nil image carrier") {
		t.Errorf("a nil bundle pointer: %v", err)
	}
	if _, err := VerifyImage(context.Background(), imageDigest, ne, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "nil image carrier") {
		t.Errorf("a nil envelope pointer: %v", err)
	}
	if _, err := HasImageTime(nb); err == nil {
		t.Error("a nil bundle pointer answered")
	}
	// Two entries are not the carrier; a payload without the in-band
	// marker is not one either; a chain that is not PEM fails.
	if _, err := VerifyImage(context.Background(), imageDigest, bundleFor(t, s, imageDigest, bundleOpts{twoEntries: true}), imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "not one") {
		t.Errorf("a bundle with two entries: %v", err)
	}
	unmarked := envelopeFor(t, s, imageDigest, envelopeOpts{payloadType: "something else"})
	if _, err := VerifyImage(context.Background(), imageDigest, unmarked, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "payload type") {
		t.Errorf("a payload without the marker: %v", err)
	}
	badChain := envelopeFor(t, s, imageDigest, envelopeOpts{})
	badChain.Chain = "not pem"
	if _, err := VerifyImage(context.Background(), imageDigest, badChain, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Errorf("a chain that is not PEM: %v", err)
	}
	if _, err := VerifyImage(context.Background(), "sha256", bundleFor(t, s, imageDigest, bundleOpts{}), imagePolicy(), tr); err == nil {
		t.Error("a digest without hex verified")
	}
}

// The envelope's signature and entry body are bound: a signature over
// other bytes, or a Rekor bundle whose entry timestamp signed another
// body, fails.
func TestVerifyImageEnvelopeBinding(t *testing.T) {
	s := newSigstore(t)
	tr := s.tr
	e := envelopeFor(t, s, imageDigest, envelopeOpts{})
	tampered := e
	tampered.Payload = append([]byte{}, e.Payload...)
	tampered.Payload[len(tampered.Payload)-2] ^= 1
	if _, err := VerifyImage(context.Background(), imageDigest, tampered, imagePolicy(), tr); err == nil {
		t.Error("a tampered payload verified")
	}
	other := envelopeFor(t, s, imageDigest, envelopeOpts{})
	swapped := e
	swapped.RekorBundle = other.RekorBundle // an entry timestamp over another signature's body
	if _, err := VerifyImage(context.Background(), imageDigest, swapped, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "signed entry timestamp") {
		t.Errorf("a Rekor bundle over another body: %v", err)
	}
}

// A log key valid only outside the signed time is refused: the root's
// validity window binds the entry's key at its integrated time.
func TestVerifyImageLogKeyValidity(t *testing.T) {
	s := newSigstore(t)
	logs := logsWithDecodedIDs(t, s.vs.RekorLogs())
	for _, l := range logs {
		l.ValidityPeriodStart = time.Now().Add(-48 * time.Hour)
		l.ValidityPeriodEnd = time.Now().Add(-24 * time.Hour)
	}
	pinned := s.fulcio.trustedRoot(t, s.vs, logs)
	e := envelopeFor(t, s, imageDigest, envelopeOpts{})
	if _, err := VerifyImage(context.Background(), imageDigest, e, imagePolicy(), pinned); err == nil {
		t.Error("an envelope whose log key is outside its validity at the signed time verified")
	}
	b := bundleFor(t, s, imageDigest, bundleOpts{noTimestamp: true})
	if _, err := VerifyImage(context.Background(), imageDigest, b, imagePolicy(), pinned); err == nil {
		t.Error("a bundle whose log key is outside its validity at the signed time verified")
	}
	// A promise-less entry, its time a timestamp's: the log key is
	// judged at that time all the same.
	v2 := bundleFor(t, s, imageDigest, bundleOpts{noPromise: true})
	if _, err := VerifyImage(context.Background(), imageDigest, v2, imagePolicy(), pinned); err == nil || !strings.Contains(err.Error(), "not valid at the signed time") {
		t.Errorf("a promise-less entry whose log key is outside its validity at the signed time: %v", err)
	}
	// A root stating no validity start for the log key refuses both
	// entry kinds alike, as the client library's own rule does.
	open := logsWithDecodedIDs(t, s.vs.RekorLogs())
	for _, l := range open {
		l.ValidityPeriodStart = time.Time{}
		l.ValidityPeriodEnd = time.Time{}
	}
	noStart := s.fulcio.trustedRoot(t, s.vs, open)
	for name, c := range map[string]ImageCarrier{"v1": b, "v2": v2} {
		if _, err := VerifyImage(context.Background(), imageDigest, c, imagePolicy(), noStart); err == nil {
			t.Errorf("%s: a log key with no validity start verified", name)
		}
	}
}

// The image path runs with no network: a carrier of either shape
// verifies while every round trip is refused (REQ-verify-offline).
func TestVerifyImageUsesNoNetwork(t *testing.T) {
	s := newSigstore(t)
	prev := http.DefaultTransport
	http.DefaultTransport = networkGuard{t: t}
	defer func() { http.DefaultTransport = prev }()
	if _, err := VerifyImage(context.Background(), imageDigest, bundleFor(t, s, imageDigest, bundleOpts{}), imagePolicy(), s.tr); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if _, err := VerifyImage(context.Background(), imageDigest, envelopeFor(t, s, imageDigest, envelopeOpts{timestamp: true, withChain: true}), imagePolicy(), s.tr); err != nil {
		t.Fatalf("envelope: %v", err)
	}
}

// Detection reports the material a signed time would come from,
// verifying nothing: a foreign sigstore's carrier still reports it,
// a carrier without it reports false, and a non-carrier errors.
func TestHasImageTime(t *testing.T) {
	s := newSigstore(t)
	for name, c := range map[string]struct {
		carrier ImageCarrier
		want    bool
	}{
		"bundle with entry":          {bundleFor(t, s, imageDigest, bundleOpts{noTimestamp: true}), true},
		"bundle with timestamp only": {bundleFor(t, s, imageDigest, bundleOpts{noEntry: true}), true},
		"bundle with v2 entry alone": {bundleFor(t, s, imageDigest, bundleOpts{noPromise: true, noTimestamp: true}), false},
		"envelope with rekor bundle": {envelopeFor(t, s, imageDigest, envelopeOpts{}), true},
		"envelope with timestamp":    {envelopeFor(t, s, imageDigest, envelopeOpts{noRekorBundle: true, timestamp: true}), true},
		"envelope bare":              {envelopeFor(t, s, imageDigest, envelopeOpts{noRekorBundle: true}), false},
	} {
		got, err := HasImageTime(c.carrier)
		if err != nil || got != c.want {
			t.Errorf("%s: HasImageTime = %v, %v; want %v", name, got, err, c.want)
		}
	}
	if _, err := HasImageTime(SigstoreBundle{JSON: []byte("nope")}); err == nil {
		t.Error("a malformed bundle answered")
	}
	if _, err := HasImageTime(SimpleSigningEnvelope{}); err == nil {
		t.Error("an empty envelope answered")
	}
	if _, err := HasImageTime(nil); err == nil {
		t.Error("a nil carrier answered")
	}
}

// The digest is compared as bytes, the algorithm as a string.
func TestParseDigest(t *testing.T) {
	alg, sum, err := parseDigest("sha256:" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if err != nil || alg != "sha256" || len(sum) != 32 {
		t.Fatalf("parseDigest = %q %d %v", alg, len(sum), err)
	}
	for _, bad := range []string{"", "sha256", "sha256:", ":abcd", "sha256:zz"} {
		if _, _, err := parseDigest(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	_ = sha256.Size
	_ = x509.ErrUnsupportedAlgorithm
}
