package gitprov

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// newVirtualTrustedRoot builds an in-memory sigstore trusted root from a
// VirtualSigstore, marshals it to JSON, and writes it to a temp file. It
// returns the path and the exact on-disk bytes (the digest pin is
// computed over these bytes pre-parse, so tests recompute from the same
// source).
func newVirtualTrustedRoot(t *testing.T, vs *ca.VirtualSigstore) (path string, raw []byte) {
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
	raw, err = tr.MarshalJSON()
	if err != nil {
		t.Fatalf("TrustedRoot.MarshalJSON: %v", err)
	}
	path = filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, raw
}

func TestLoadTrustedRoot(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}

	t.Run("happy: digest pins the exact on-disk bytes", func(t *testing.T) {
		path, raw := newVirtualTrustedRoot(t, vs)
		got, err := LoadTrustedRoot(path)
		if err != nil {
			t.Fatalf("LoadTrustedRoot: %v", err)
		}
		if got.Root == nil {
			t.Fatal("LoadTrustedRoot returned nil Root")
		}
		sum := sha256.Sum256(raw)
		want := "sha256:" + hex.EncodeToString(sum[:])
		if got.Digest != want {
			t.Fatalf("Digest = %q, want %q (sha256 of raw file bytes)", got.Digest, want)
		}
		// ParseTrustedRoot over the same bytes pins identically: Load is
		// read + Parse and nothing more.
		parsed, err := ParseTrustedRoot(raw)
		if err != nil {
			t.Fatalf("ParseTrustedRoot: %v", err)
		}
		if parsed.Digest != want {
			t.Fatalf("ParseTrustedRoot digest = %q, want %q", parsed.Digest, want)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadTrustedRoot(filepath.Join(t.TempDir(), "nope.json"))
		if err == nil || !strings.Contains(err.Error(), "read trusted root") {
			t.Fatalf("LoadTrustedRoot = %v, want read error", err)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadTrustedRoot(p)
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
		path, _ := newVirtualTrustedRoot(t, vs)
		tr, err := LoadTrustedRoot(path)
		if err != nil {
			t.Fatalf("LoadTrustedRoot: %v", err)
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
		tr := &TrustedRoot{Root: empty}
		if _, _, err := tr.fulcioPools(); err == nil ||
			!strings.Contains(err.Error(), "no Fulcio certificate authorities") {
			t.Fatalf("fulcioPools = %v, want no-Fulcio-CA error", err)
		}
	})
}
