package gitprov_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gitprov"
	"github.com/greatliontech/gitprov/sigstoretest"
)

// The image fixtures are sigstoretest's synthetic sigstore: cosign's
// shapes built from cosign's constants; the real captured vectors,
// once present, prove the shapes against bytes cosign wrote.

const (
	imageIdentity = "signer@example.com"
	imageIssuer   = "https://accounts.example.com"
	imageDigest   = "sha256:8d1b7cf2f8a1f2a1e1c4b5d0a2f2e8e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5"
)

func imagePolicy() gitprov.Identity {
	return gitprov.Identity{Issuer: imageIssuer, Subject: imageIdentity}
}

// A bundle cosign's default sign writes verifies: the identity, the
// leaf fingerprint, the root's digest, the digest verified, the entry's
// index and its integrated time as the signed time.
func TestVerifyImageBundle(t *testing.T) {
	s := sigstoretest.New(t)
	tr := s.TrustedRoot()
	at := time.Now().Truncate(time.Second)
	b := s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{IntegratedAt: at})
	vi, err := gitprov.VerifyImage(context.Background(), imageDigest, b, imagePolicy(), tr)
	if err != nil {
		t.Fatalf("gitprov.VerifyImage: %v", err)
	}
	if vi.Subject != imageIdentity || vi.Issuer != imageIssuer || vi.Digest != imageDigest || vi.TrustedRootDigest != tr.Digest() {
		t.Fatalf("verified identity = %+v", vi)
	}
	if vi.RekorIntegratedTime != at.Unix() || vi.RekorLogIndex != 1 {
		t.Fatalf("signed time %d (want %d), log index %d", vi.RekorIntegratedTime, at.Unix(), vi.RekorLogIndex)
	}
	if !strings.HasPrefix(vi.CertFingerprint, "sha256:") {
		t.Fatalf("fingerprint %q", vi.CertFingerprint)
	}
	// The pointer form is the same carrier.
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, &b, imagePolicy(), tr); err != nil {
		t.Fatalf("pointer carrier: %v", err)
	}
}

// A bundle's entry is judged under its checkpoint: one another log's
// key signed, over the very same tree, fails, the entry's log being
// the pinned one (REQ-image-offline-verification).
func TestVerifyImageCheckpoint(t *testing.T) {
	s := sigstoretest.New(t)
	b := s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{CheckpointBy: sigstoretest.New(t)})
	_, err := gitprov.VerifyImage(context.Background(), imageDigest, b, imagePolicy(), s.TrustedRoot())
	if err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("a checkpoint another log signed: %v", err)
	}
	// One the log signed over another tree state names a size the
	// proof does not: the verifier's own checks pass it, the rule here
	// does not.
	b = s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{CheckpointSize: 3})
	_, err = gitprov.VerifyImage(context.Background(), imageDigest, b, imagePolicy(), s.TrustedRoot())
	if err == nil || !strings.Contains(err.Error(), "names a tree of 3, the inclusion proof 2") {
		t.Fatalf("a checkpoint over another size: %v", err)
	}
}

// A simple-signing envelope cosign's legacy sign writes verifies, with
// or without its chain annotation and its timestamp, the Rekor
// bundle's integrated time being the signed time and its index the
// entry's.
func TestVerifyImageEnvelope(t *testing.T) {
	s := sigstoretest.New(t)
	tr := s.TrustedRoot()
	at := time.Now().Truncate(time.Second)
	for name, o := range map[string]sigstoretest.EnvelopeOptions{
		"bare":            {IntegratedAt: at},
		"chain":           {IntegratedAt: at, WithChain: true},
		"timestamp":       {IntegratedAt: at, Timestamp: true},
		"chain+timestamp": {IntegratedAt: at, WithChain: true, Timestamp: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, o)
			vi, err := gitprov.VerifyImage(context.Background(), imageDigest, e, imagePolicy(), tr)
			if err != nil {
				t.Fatalf("gitprov.VerifyImage: %v", err)
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
	s := sigstoretest.New(t)
	tr := s.TrustedRoot()
	other := "sha256:" + strings.Repeat("ab", 32)
	b := s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{})
	e := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{})
	for name, c := range map[string]gitprov.ImageCarrier{"bundle": b, "envelope": e} {
		if _, err := gitprov.VerifyImage(context.Background(), other, c, imagePolicy(), tr); err == nil {
			t.Errorf("%s: another digest verified", name)
		}
		if _, err := gitprov.VerifyImage(context.Background(), "SHA256:"+strings.TrimPrefix(imageDigest, "sha256:"), c, imagePolicy(), tr); err == nil {
			t.Errorf("%s: another algorithm spelling verified", name)
		}
		upper := "sha256:" + strings.ToUpper(strings.TrimPrefix(imageDigest, "sha256:"))
		if vi, err := gitprov.VerifyImage(context.Background(), upper, c, imagePolicy(), tr); err != nil || vi.Digest != imageDigest {
			t.Errorf("%s: the same digest in upper-case hex: %v %+v", name, err, vi)
		}
	}
	// An envelope naming another digest than the one it is judged for,
	// its own signature intact.
	e2 := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{NamedDigest: other})
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, e2, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "not the digest in hand") {
		t.Errorf("a payload naming another digest: %v", err)
	}
}

// The identity must match on both axes; a mismatch fails after the
// carrier verified.
func TestVerifyImageIdentityMismatch(t *testing.T) {
	s := sigstoretest.New(t)
	tr := s.TrustedRoot()
	b := s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{})
	e := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{})
	for name, c := range map[string]gitprov.ImageCarrier{"bundle": b, "envelope": e} {
		if _, err := gitprov.VerifyImage(context.Background(), imageDigest, c, gitprov.Identity{Issuer: imageIssuer, Subject: "other@example.com"}, tr); !errors.Is(err, gitprov.ErrIdentityMismatch) {
			t.Errorf("%s: subject mismatch: %v", name, err)
		}
		if _, err := gitprov.VerifyImage(context.Background(), imageDigest, c, gitprov.Identity{Issuer: "https://other.example.com", Subject: imageIdentity}, tr); !errors.Is(err, gitprov.ErrIdentityMismatch) {
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
	s := sigstoretest.New(t)
	tr := s.TrustedRoot()
	foreign := sigstoretest.New(t)
	at := time.Now().Truncate(time.Second)
	cases := []struct {
		name string
		opts sigstoretest.BundleOptions
		ok   bool
		want string
	}{
		{"v1 entry, no timestamp", sigstoretest.BundleOptions{NoTimestamp: true, IntegratedAt: at}, true, ""},
		{"v2 entry with timestamp", sigstoretest.BundleOptions{NoPromise: true, IntegratedAt: at}, true, ""},
		{"v2 entry without timestamp", sigstoretest.BundleOptions{NoPromise: true, NoTimestamp: true}, false, "timestamp"},
		{"timestamp without entry", sigstoretest.BundleOptions{NoEntry: true}, false, "not one: not this carrier"},
		{"foreign timestamp beside a v1 entry", sigstoretest.BundleOptions{TimestampBy: foreign, IntegratedAt: at}, false, "no pinned authority"},
		{"a foreign timestamp beside a pinned one", sigstoretest.BundleOptions{ExtraTimestampBy: foreign, IntegratedAt: at}, false, "no pinned authority"},
		{"two timestamps from the pinned authority", sigstoretest.BundleOptions{ExtraTimestampBy: s, IntegratedAt: at}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := s.Bundle(t, imageDigest, imageIdentity, imageIssuer, c.opts)
			vi, err := gitprov.VerifyImage(context.Background(), imageDigest, b, imagePolicy(), tr)
			if c.ok {
				if err != nil {
					t.Fatalf("gitprov.VerifyImage: %v", err)
				}
				if c.opts.NoPromise {
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
				t.Fatalf("gitprov.VerifyImage = %v, want a failure naming %q", err, c.want)
			}
		})
	}
	// The envelope: a Rekor bundle is required; a foreign timestamp
	// beside it fails.
	e := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{NoRekorBundle: true})
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, e, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "not this carrier") {
		t.Errorf("an envelope without a Rekor bundle: %v", err)
	}
	e = s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{Timestamp: true, TimestampBy: foreign})
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, e, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "no pinned authority") {
		t.Errorf("an envelope with a foreign Timestamp: %v", err)
	}
}

// The carrier's shape is exact: a bundle of another version, one with
// two signatures, one under another predicate, and one signed by a
// leaf the pinned root does not chain fail; an envelope whose Rekor
// bundle names a log the root does not know fails.
func TestVerifyImageCarrierShape(t *testing.T) {
	s := sigstoretest.New(t)
	tr := s.TrustedRoot()
	foreign := sigstoretest.New(t)
	for name, o := range map[string]sigstoretest.BundleOptions{
		"another version": {MediaType: "application/vnd.dev.sigstore.bundle.v0.2+json"},
		"two signatures":  {TwoSignatures: true},
		"other predicate": {Predicate: "https://slsa.dev/provenance/v1"},
	} {
		b := s.Bundle(t, imageDigest, imageIdentity, imageIssuer, o)
		if _, err := gitprov.VerifyImage(context.Background(), imageDigest, b, imagePolicy(), tr); err == nil {
			t.Errorf("%s verified", name)
		}
	}
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, foreign.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{}), imagePolicy(), tr); err == nil {
		t.Error("a bundle from a foreign sigstore verified")
	}
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, foreign.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{}), imagePolicy(), tr); err == nil {
		t.Error("an envelope from a foreign sigstore verified")
	}
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, gitprov.SigstoreBundle{JSON: []byte("{")}, imagePolicy(), tr); err == nil {
		t.Error("a malformed bundle verified")
	}
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, nil, imagePolicy(), tr); err == nil {
		t.Error("a nil carrier verified")
	}
	// A nil pointer to either shape is an error, never a dereference.
	var nb *gitprov.SigstoreBundle
	var ne *gitprov.SimpleSigningEnvelope
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, nb, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "nil image carrier") {
		t.Errorf("a nil bundle pointer: %v", err)
	}
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, ne, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "nil image carrier") {
		t.Errorf("a nil envelope pointer: %v", err)
	}
	if _, err := gitprov.HasImageTime(nb); err == nil {
		t.Error("a nil bundle pointer answered")
	}
	// Two entries are not the carrier; a payload without the in-band
	// marker is not one either; a chain that is not PEM fails.
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{TwoEntries: true}), imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "not one") {
		t.Errorf("a bundle with two entries: %v", err)
	}
	unmarked := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{PayloadType: "something else"})
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, unmarked, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "payload type") {
		t.Errorf("a payload without the marker: %v", err)
	}
	badChain := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{})
	badChain.Chain = "not pem"
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, badChain, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Errorf("a chain that is not PEM: %v", err)
	}
	if _, err := gitprov.VerifyImage(context.Background(), "sha256", s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{}), imagePolicy(), tr); err == nil {
		t.Error("a digest without hex verified")
	}
}

// The envelope's signature and entry body are bound: a signature over
// other bytes, or a Rekor bundle whose entry timestamp signed another
// body, fails.
func TestVerifyImageEnvelopeBinding(t *testing.T) {
	s := sigstoretest.New(t)
	tr := s.TrustedRoot()
	e := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{})
	tampered := e
	tampered.Payload = append([]byte{}, e.Payload...)
	tampered.Payload[len(tampered.Payload)-2] ^= 1
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, tampered, imagePolicy(), tr); err == nil {
		t.Error("a tampered payload verified")
	}
	other := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{})
	swapped := e
	swapped.RekorBundle = other.RekorBundle // an entry timestamp over another signature's body
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, swapped, imagePolicy(), tr); err == nil || !strings.Contains(err.Error(), "signed entry timestamp") {
		t.Errorf("a Rekor bundle over another body: %v", err)
	}
}

// A log key valid only outside the signed time is refused: the root's
// validity window binds the entry's key at its integrated time.
func TestVerifyImageLogKeyValidity(t *testing.T) {
	s := sigstoretest.New(t)
	logs := s.RekorLogs(t)
	for _, l := range logs {
		l.ValidityPeriodStart = time.Now().Add(-48 * time.Hour)
		l.ValidityPeriodEnd = time.Now().Add(-24 * time.Hour)
	}
	pinned := s.TrustedRootWithRekorLogs(t, logs)
	e := s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{})
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, e, imagePolicy(), pinned); err == nil {
		t.Error("an envelope whose log key is outside its validity at the signed time verified")
	}
	b := s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{NoTimestamp: true})
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, b, imagePolicy(), pinned); err == nil {
		t.Error("a bundle whose log key is outside its validity at the signed time verified")
	}
	// A promise-less entry, its time a timestamp's: the log key is
	// judged at that time all the same.
	v2 := s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{NoPromise: true})
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, v2, imagePolicy(), pinned); err == nil || !strings.Contains(err.Error(), "not valid at the signed time") {
		t.Errorf("a promise-less entry whose log key is outside its validity at the signed time: %v", err)
	}
	// A root stating no validity start for the log key refuses both
	// entry kinds alike, as the client library's own rule does.
	open := s.RekorLogs(t)
	for _, l := range open {
		l.ValidityPeriodStart = time.Time{}
		l.ValidityPeriodEnd = time.Time{}
	}
	noStart := s.TrustedRootWithRekorLogs(t, open)
	for name, c := range map[string]gitprov.ImageCarrier{"v1": b, "v2": v2} {
		if _, err := gitprov.VerifyImage(context.Background(), imageDigest, c, imagePolicy(), noStart); err == nil {
			t.Errorf("%s: a log key with no validity start verified", name)
		}
	}
}

// The image path runs with no network: a carrier of either shape
// verifies while every round trip is refused (REQ-verify-offline).
func TestVerifyImageUsesNoNetwork(t *testing.T) {
	s := sigstoretest.New(t)
	sigstoretest.RefuseNetwork(t)
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{}), imagePolicy(), s.TrustedRoot()); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if _, err := gitprov.VerifyImage(context.Background(), imageDigest, s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{Timestamp: true, WithChain: true}), imagePolicy(), s.TrustedRoot()); err != nil {
		t.Fatalf("envelope: %v", err)
	}
}

// Detection reports the material a signed time would come from,
// verifying nothing: a foreign sigstore's carrier still reports it,
// a carrier without it reports false, and a non-carrier errors.
func TestHasImageTime(t *testing.T) {
	s := sigstoretest.New(t)
	for name, c := range map[string]struct {
		carrier gitprov.ImageCarrier
		want    bool
	}{
		"bundle with entry":          {s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{NoTimestamp: true}), true},
		"bundle with timestamp only": {s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{NoEntry: true}), true},
		"bundle with v2 entry alone": {s.Bundle(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.BundleOptions{NoPromise: true, NoTimestamp: true}), false},
		"envelope with rekor bundle": {s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{}), true},
		"envelope with timestamp":    {s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{NoRekorBundle: true, Timestamp: true}), true},
		"envelope bare":              {s.Envelope(t, imageDigest, imageIdentity, imageIssuer, sigstoretest.EnvelopeOptions{NoRekorBundle: true}), false},
	} {
		got, err := gitprov.HasImageTime(c.carrier)
		if err != nil || got != c.want {
			t.Errorf("%s: gitprov.HasImageTime = %v, %v; want %v", name, got, err, c.want)
		}
	}
	if _, err := gitprov.HasImageTime(gitprov.SigstoreBundle{JSON: []byte("nope")}); err == nil {
		t.Error("a malformed bundle answered")
	}
	if _, err := gitprov.HasImageTime(gitprov.SimpleSigningEnvelope{}); err == nil {
		t.Error("an empty envelope answered")
	}
	if _, err := gitprov.HasImageTime(nil); err == nil {
		t.Error("a nil carrier answered")
	}
}
