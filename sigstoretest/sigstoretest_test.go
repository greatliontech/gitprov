package sigstoretest_test

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greatliontech/gitprov"
	"github.com/greatliontech/gitprov/sigstoretest"
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
	} {
		if failed := record(t, build); !strings.Contains(failed, "outside the leaf's validity") || !strings.Contains(failed, "move the root's window") {
			t.Errorf("%s: %q", name, failed)
		}
	}
	if failed := record(t, func(r *recorder) { sigstoretest.Statement(r, "deadbeef", sigstoretest.CosignSignPredicateType) }); !strings.Contains(failed, "is not <algorithm>:<hex>") {
		t.Errorf("a colonless digest: %q", failed)
	}
	if failed := record(t, func(r *recorder) { sigstoretest.PEM(r, nil) }); failed == "" {
		t.Error("a nil certificate rendered")
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
