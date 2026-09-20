package sigstoretest_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greatliontech/gitprov"
	"github.com/greatliontech/gitprov/sigstoretest"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	subject = "signer@example.com"
	issuer  = "https://accounts.example.com"
	digest  = "sha256:8d1b7cf2f8a1f2a1e1c4b5d0a2f2e8e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5"
)

// recorder is a testing.TB that records a failure instead of ending
// the test, so a builder's refusal can be asserted on; a fatal ends
// the builder's goroutine as the real one would, so nothing runs
// past a refusal.
type recorder struct {
	testing.TB
	failed string
}

func (r *recorder) Helper()           {}
func (r *recorder) Fatal(args ...any) { r.failed = fmt.Sprint(args...); runtime.Goexit() }
func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = fmt.Sprintf(format, args...)
	runtime.Goexit()
}
func (r *recorder) Errorf(format string, args ...any) { r.failed = fmt.Sprintf(format, args...) }

// record runs build on its own goroutine under a recorder and returns
// what it recorded.
func record(t *testing.T, build func(*recorder)) string {
	t.Helper()
	r := &recorder{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		build(r)
	}()
	<-done
	return r.failed
}

// A bundle's entry is the log's: its inclusion proof walks the
// Merkle path every entry of this log has (New).
func TestBundleEntryCarriesPath(t *testing.T) {
	s := sigstoretest.New(t)
	var b protobundle.Bundle
	if err := protojson.Unmarshal(s.Bundle(t, digest, subject, issuer, sigstoretest.BundleOptions{}).JSON, &b); err != nil {
		t.Fatal(err)
	}
	entries := b.GetVerificationMaterial().GetTlogEntries()
	if len(entries) != 1 || len(entries[0].GetInclusionProof().GetHashes()) == 0 {
		t.Fatalf("the bundle's entry walks no Merkle path: %v", entries)
	}
}

// Both carriers a sigstore builds verify against its own root, at the
// edge of the leaf's validity as at its issue.
func TestCarriersVerify(t *testing.T) {
	s := sigstoretest.New(t)
	policy := gitprov.Identity{Issuer: issuer, Subject: subject}
	edge := time.Now().Add(-59 * time.Second) // a leaf is valid from a minute before its issue
	for name, c := range map[string]gitprov.ImageCarrier{
		"bundle":           s.Bundle(t, digest, subject, issuer, sigstoretest.BundleOptions{}),
		"bundle at edge":   s.Bundle(t, digest, subject, issuer, sigstoretest.BundleOptions{IntegratedAt: edge}),
		"envelope":         s.Envelope(t, digest, subject, issuer, sigstoretest.EnvelopeOptions{}),
		"envelope at edge": s.Envelope(t, digest, subject, issuer, sigstoretest.EnvelopeOptions{IntegratedAt: edge, Timestamp: true, WithChain: true}),
	} {
		if vi, err := gitprov.VerifyImage(context.Background(), digest, c, policy, s.TrustedRoot()); err != nil || vi.Subject != subject {
			t.Errorf("%s: %v %+v", name, err, vi)
		}
	}
}

// A stated signed time outside the leaf's validity fails the test
// that asked for it, naming the idiom; a colonless digest and a
// certificate that cannot be rendered fail likewise.
func TestBuildersRefuse(t *testing.T) {
	s := sigstoretest.New(t)
	for name, build := range map[string]func(*recorder){
		"bundle past validity": func(r *recorder) {
			s.Bundle(r, digest, subject, issuer, sigstoretest.BundleOptions{IntegratedAt: time.Now().Add(time.Hour)})
		},
		"bundle before validity": func(r *recorder) {
			s.Bundle(r, digest, subject, issuer, sigstoretest.BundleOptions{IntegratedAt: time.Now().Add(-time.Hour)})
		},
		"envelope past validity": func(r *recorder) {
			s.Envelope(r, digest, subject, issuer, sigstoretest.EnvelopeOptions{IntegratedAt: time.Now().Add(time.Hour)})
		},
		"entry past validity": func(r *recorder) {
			leaf, key := s.Leaf(r, subject, issuer)
			s.LogEntry(r, leaf, hashedRekord(r, leaf, key, []byte("late")), time.Now().Add(time.Hour))
		},
	} {
		if failed := record(t, build); !strings.Contains(failed, "outside the leaf's validity") || !strings.Contains(failed, "move the root's window") {
			t.Errorf("%s: %q", name, failed)
		}
	}
	for name, body := range map[string]string{"not JSON": "{", "no kind": "{}", "no version": `{"kind":"hashedrekord"}`} {
		if failed := record(t, func(r *recorder) {
			leaf, _ := s.Leaf(r, subject, issuer)
			s.LogEntry(r, leaf, []byte(body), time.Time{})
		}); !strings.Contains(failed, "entry body") {
			t.Errorf("a body that is not an entry (%s): %q", name, failed)
		}
	}
	if failed := record(t, func(r *recorder) { sigstoretest.Statement(r, "deadbeef", sigstoretest.CosignSignPredicateType) }); !strings.Contains(failed, "is not <algorithm>:<hex>") {
		t.Errorf("a colonless digest: %q", failed)
	}
	if failed := record(t, func(r *recorder) { sigstoretest.PEM(r, nil) }); failed == "" {
		t.Error("a nil certificate rendered")
	}
}

// hashedRekord signs message with the leaf's key and returns the
// HashedRekord body the log records for it.
func hashedRekord(t testing.TB, leaf *x509.Certificate, key *ecdsa.PrivateKey, message []byte) []byte {
	t.Helper()
	h := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	body, err := gitprov.HashedRekordBody(context.Background(), message, sig, leaf)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// An entry the log records verifies as a real one does: its
// inclusion proof walks a Merkle path under the log's checkpoint, its
// signed entry timestamp is the log's over the entry's coordinates,
// and its kind is the body's.
func TestLogEntryVerifies(t *testing.T) {
	s := sigstoretest.New(t)
	leaf, key := s.Leaf(t, subject, issuer)
	tle := s.LogEntry(t, leaf, hashedRekord(t, leaf, key, []byte("signed bytes")), time.Time{})
	if tle.KindVersion.Kind != "hashedrekord" || tle.KindVersion.Version != "0.0.1" {
		t.Fatalf("kind = %v", tle.KindVersion)
	}
	// The kind is the body's, whatever it names.
	if other := s.LogEntry(t, leaf, []byte(`{"kind":"dsse","apiVersion":"0.0.2","spec":{}}`), time.Time{}); other.KindVersion.Kind != "dsse" || other.KindVersion.Version != "0.0.2" {
		t.Fatalf("kind of another body = %v", other.KindVersion)
	}
	if len(tle.InclusionProof.Hashes) == 0 {
		t.Fatal("the inclusion proof walks no Merkle path")
	}
	entry, err := tlog.ParseEntry(tle)
	if err != nil {
		t.Fatal(err)
	}
	logs := s.RekorLogs(t)
	verifier, err := signature.LoadVerifier(logs[s.RekorLogID(t)].PublicKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlog.VerifyInclusion(entry, verifier); err != nil {
		t.Fatalf("inclusion: %v", err)
	}
	if err := tlog.VerifySET(entry, logs); err != nil {
		t.Fatalf("signed entry timestamp: %v", err)
	}
	// The checkpoint is the log's, over the proof's root and size.
	var cp util.SignedCheckpoint
	if err := cp.UnmarshalText([]byte(tle.InclusionProof.Checkpoint.Envelope)); err != nil {
		t.Fatal(err)
	}
	if !cp.SignedNote.Verify(verifier) || !bytes.Equal(cp.Hash, tle.InclusionProof.RootHash) || cp.Size != uint64(tle.InclusionProof.TreeSize) {
		t.Fatalf("the checkpoint is not the log's over the proof: %+v", cp.Checkpoint)
	}
	// Another log's checkpoint over the same tree is not this log's.
	foreign := s.LogEntryWith(t, leaf, hashedRekord(t, leaf, key, []byte("signed bytes")), time.Time{}, sigstoretest.EntryOptions{CheckpointBy: sigstoretest.New(t)})
	if err := cp.UnmarshalText([]byte(foreign.InclusionProof.Checkpoint.Envelope)); err != nil {
		t.Fatal(err)
	}
	if cp.SignedNote.Verify(verifier) {
		t.Fatal("a checkpoint another log signed verified by this log's key")
	}
}

// A sigstore is safe for concurrent use once built (the witness is
// the race detector's, which the suite runs under).
func TestConcurrentUse(t *testing.T) {
	s := sigstoretest.New(t)
	var wg sync.WaitGroup
	recorders := make([]*recorder, 8)
	for i := range recorders {
		r := &recorder{TB: t}
		recorders[i] = r
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				s.Bundle(r, digest, subject, issuer, sigstoretest.BundleOptions{})
			} else {
				s.Envelope(r, digest, subject, issuer, sigstoretest.EnvelopeOptions{Timestamp: true})
			}
			s.RekorLogs(r)
			s.RootJSON()
		}(i)
	}
	wg.Wait()
	for i, r := range recorders {
		if r.failed != "" {
			t.Errorf("goroutine %d: %s", i, r.failed)
		}
	}
}
