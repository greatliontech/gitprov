package gitprov

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

func TestIdentityValidate(t *testing.T) {
	tests := []struct {
		name    string
		id      Identity
		wantErr string // substring; "" means expect nil
	}{
		{"exact/exact ok", Identity{Issuer: "https://accounts.google.com", Subject: "a@b.com"}, ""},
		{"regex/regex ok", Identity{IssuerRegex: `https://.*`, SubjectRegex: `.*@b\.com`}, ""},
		{"exact issuer + regex subject ok", Identity{Issuer: "https://x", SubjectRegex: `.+`}, ""},
		{"no issuer at all", Identity{Subject: "a@b.com"}, "one of Issuer or IssuerRegex is required"},
		{"both issuer forms", Identity{Issuer: "x", IssuerRegex: "y", Subject: "a@b.com"}, "Issuer and IssuerRegex are mutually exclusive"},
		{"no subject at all", Identity{Issuer: "x"}, "one of Subject or SubjectRegex is required"},
		{"both subject forms", Identity{Issuer: "x", Subject: "a", SubjectRegex: "b"}, "Subject and SubjectRegex are mutually exclusive"},
		{"invalid issuerRegex", Identity{IssuerRegex: "(", Subject: "a@b.com"}, "invalid IssuerRegex"},
		{"invalid subjectRegex", Identity{Issuer: "x", SubjectRegex: "["}, "invalid SubjectRegex"},
		// Security regression: a pattern crafted to escape fullMatch's
		// \A(?:…)\z wrapper (close the group early, then `(?:` to
		// rebalance the trailing `)`) has unbalanced parens *bare* and
		// MUST be rejected here. If it passed Validate, fullMatch would
		// compile `\A(?:a)\z|(?:)\z` and match every value (full
		// de-anchor). Bare compilation in Validate is exactly what blocks
		// this — do not "consistency-fix" Validate to compile the
		// anchored form.
		{"subjectRegex wrapper-escape attempt", Identity{Issuer: "x", SubjectRegex: `a)\z|(?:`}, "invalid SubjectRegex"},
		{"issuerRegex wrapper-escape attempt", Identity{IssuerRegex: `a)\z|(?:`, Subject: "a@b.com"}, "invalid IssuerRegex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.id.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestIdentityMatch(t *testing.T) {
	const (
		subject = "nikolas.sepos@gmail.com"
		issuer  = "https://accounts.google.com"
	)
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	leaf, _, err := vs.GenerateLeafCert(subject, issuer)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	t.Run("exact issuer + exact subject", func(t *testing.T) {
		id := Identity{Issuer: issuer, Subject: subject}
		ms, iss, err := id.match(leaf)
		if err != nil {
			t.Fatalf("match() = %v, want nil", err)
		}
		if ms != subject || iss != issuer {
			t.Fatalf("match() = (%q,%q), want (%q,%q)", ms, iss, subject, issuer)
		}
	})

	t.Run("anchored regex full match", func(t *testing.T) {
		id := Identity{IssuerRegex: `https://accounts\.google\.com`, SubjectRegex: `.+@gmail\.com`}
		ms, iss, err := id.match(leaf)
		if err != nil {
			t.Fatalf("match() = %v, want nil", err)
		}
		if ms != subject || iss != issuer {
			t.Fatalf("match() = (%q,%q), want (%q,%q)", ms, iss, subject, issuer)
		}
	})

	t.Run("subject regex must span the value (substring is a bypass)", func(t *testing.T) {
		id := Identity{Issuer: issuer, SubjectRegex: `nikolas\.sepos`}
		if _, _, err := id.match(leaf); err == nil {
			t.Fatal("match() = nil, want error: unanchored substring regex must not match full SAN")
		}
	})

	t.Run("wrong exact issuer", func(t *testing.T) {
		id := Identity{Issuer: "https://evil.example.com", Subject: subject}
		if _, _, err := id.match(leaf); err == nil || !strings.Contains(err.Error(), "issuer") {
			t.Fatalf("match() = %v, want issuer-mismatch error", err)
		}
	})

	t.Run("no SAN matches policy", func(t *testing.T) {
		id := Identity{Issuer: issuer, Subject: "someone-else@example.com"}
		if _, _, err := id.match(leaf); err == nil || !strings.Contains(err.Error(), "SAN") {
			t.Fatalf("match() = %v, want no-SAN-match error", err)
		}
	})

	t.Run("fail-closed: cert with no OIDC issuer extension", func(t *testing.T) {
		bare := selfSignedNoIssuer(t, subject)
		id := Identity{Issuer: issuer, Subject: subject}
		if _, _, err := id.match(bare); err == nil || !strings.Contains(err.Error(), "no OIDC issuer extension") {
			t.Fatalf("match() = %v, want no-issuer-extension error", err)
		}
	})
}

// selfSignedNoIssuer mints a self-signed leaf with an email SAN but no
// Fulcio OIDC-issuer extension, exercising the fail-closed empty-issuer
// rejection.
func selfSignedNoIssuer(t *testing.T, email string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{email},
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		Subject:        pkix.Name{CommonName: "no-issuer-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
