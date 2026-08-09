package gitprov

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// virtualTrustedRootBytes marshals an in-memory sigstore trusted root
// built from a VirtualSigstore to its JSON wire form — the exact bytes
// the digest pin is computed over.
func virtualTrustedRootBytes(t *testing.T, vs *ca.VirtualSigstore) []byte {
	t.Helper()
	tr, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		vs.FulcioCertificateAuthorities(),
		vs.CTLogs(),
		vs.TimestampingAuthorities(),
		vs.RekorLogs(),
	)
	if err != nil {
		t.Fatalf("root.NewTrustedRoot: %v", err)
	}
	raw, err := tr.MarshalJSON()
	if err != nil {
		t.Fatalf("TrustedRoot.MarshalJSON: %v", err)
	}
	return raw
}

func TestLoadTrustedRoot(t *testing.T) {
	t.Run("happy: digest pins the exact on-disk bytes", func(t *testing.T) {
		const path = "testdata/gitsign-fixture-trusted-root.json"
		got, err := LoadTrustedRoot(path)
		if err != nil {
			t.Fatalf("LoadTrustedRoot: %v", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		want := "sha256:" + hex.EncodeToString(sum[:])
		if got.Digest() != want {
			t.Fatalf("Digest = %q, want %q (sha256 of raw file bytes)", got.Digest(), want)
		}
		// ParseTrustedRoot over the same bytes pins identically: Load is
		// read + Parse and nothing more.
		parsed, err := ParseTrustedRoot(raw)
		if err != nil {
			t.Fatalf("ParseTrustedRoot: %v", err)
		}
		if parsed.Digest() != want {
			t.Fatalf("ParseTrustedRoot digest = %q, want %q", parsed.Digest(), want)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadTrustedRoot("testdata/does-not-exist.json")
		if err == nil || !strings.Contains(err.Error(), "read trusted root") {
			t.Fatalf("LoadTrustedRoot = %v, want read error", err)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		_, err := LoadTrustedRoot("testdata/malformed-trusted-root.json")
		if err == nil || !strings.Contains(err.Error(), "parse trusted root") {
			t.Fatalf("LoadTrustedRoot = %v, want parse error", err)
		}
	})
}

func TestFulcioPools(t *testing.T) {
	t.Run("happy: pools chain a real Fulcio leaf", func(t *testing.T) {
		vs, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatalf("NewVirtualSigstore: %v", err)
		}
		tr, err := ParseTrustedRoot(virtualTrustedRootBytes(t, vs))
		if err != nil {
			t.Fatalf("ParseTrustedRoot: %v", err)
		}
		roots, intermediates, err := tr.fulcioPools()
		if err != nil {
			t.Fatalf("fulcioPools: %v", err)
		}
		if roots == nil || intermediates == nil {
			t.Fatalf("fulcioPools returned nil pool(s): roots=%v intermediates=%v", roots, intermediates)
		}
		// Structural proof the pools hold the right material: a freshly
		// minted Fulcio leaf must chain to the root through them.
		leaf, _, err := vs.GenerateLeafCert("a@b.com", "https://accounts.google.com")
		if err != nil {
			t.Fatalf("GenerateLeafCert: %v", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			CurrentTime:   leaf.NotBefore.Add(time.Minute),
		}); err != nil {
			t.Fatalf("leaf.Verify via fulcioPools = %v, want valid chain", err)
		}
	})

	t.Run("trusted root with no Fulcio CAs is rejected", func(t *testing.T) {
		empty, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("root.NewTrustedRoot(empty): %v", err)
		}
		tr := &TrustedRoot{root: empty}
		if _, _, err := tr.fulcioPools(); err == nil ||
			!strings.Contains(err.Error(), "no Fulcio certificate authorities") {
			t.Fatalf("fulcioPools = %v, want no-Fulcio-CA error", err)
		}
	})

	t.Run("fulcio CAs carrying no root certificate are rejected", func(t *testing.T) {
		nilRoot, err := root.NewTrustedRoot(root.TrustedRootMediaType01,
			[]root.CertificateAuthority{&root.FulcioCertificateAuthority{}}, nil, nil, nil)
		if err != nil {
			t.Fatalf("root.NewTrustedRoot(nil-root CA): %v", err)
		}
		tr := &TrustedRoot{root: nilRoot}
		if _, _, err := tr.fulcioPools(); err == nil ||
			!strings.Contains(err.Error(), "no usable Fulcio root certificates") {
			t.Fatalf("fulcioPools = %v, want no-usable-roots error", err)
		}
	})

	t.Run("non-fulcio CA implementations are skipped, not fatal", func(t *testing.T) {
		vs, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatalf("NewVirtualSigstore: %v", err)
		}
		mixed := append([]root.CertificateAuthority{stubCA{}}, vs.FulcioCertificateAuthorities()...)
		tr0, err := root.NewTrustedRoot(root.TrustedRootMediaType01, mixed, nil, nil, nil)
		if err != nil {
			t.Fatalf("root.NewTrustedRoot(mixed): %v", err)
		}
		tr := &TrustedRoot{root: tr0}
		roots, _, err := tr.fulcioPools()
		if err != nil {
			t.Fatalf("fulcioPools(mixed) = %v, want nil: a foreign CA type must be skipped", err)
		}
		if roots == nil {
			t.Fatal("fulcioPools(mixed) returned nil roots")
		}
	})
}

// stubCA is a CertificateAuthority that is not a
// *root.FulcioCertificateAuthority — the foreign-implementation case
// fulcioPools must skip.
type stubCA struct{}

func (stubCA) Verify(*x509.Certificate, time.Time) ([][]*x509.Certificate, error) {
	return nil, fmt.Errorf("stub")
}
