package gitprov

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"pgregory.net/rapid"
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

	t.Run("fail-closed: malformed Fulcio issuer extension", func(t *testing.T) {
		// A cert carrying the Fulcio issuer OID with undecodable DER must
		// surface the extension-parse failure itself — not fall through to
		// a downstream empty-issuer or no-SAN diagnosis.
		bad := testCert(t, &x509.Certificate{
			SerialNumber:   big.NewInt(2),
			EmailAddresses: []string{subject},
			NotBefore:      time.Now().Add(-time.Minute),
			NotAfter:       time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: []byte{0xff}},
			},
		})
		id := Identity{Issuer: issuer, Subject: subject}
		if _, _, err := id.match(bad); err == nil || !strings.Contains(err.Error(), "parse fulcio extensions") {
			t.Fatalf("match() = %v, want extension-parse error", err)
		}
	})

	t.Run("DNS SAN is a subject candidate", func(t *testing.T) {
		// SAN value chosen to also pin the exact non-empty-SAN filter.
		cert := testCert(t, &x509.Certificate{
			SerialNumber:    big.NewInt(3),
			DNSNames:        []string{"mutant"},
			NotBefore:       time.Now().Add(-time.Minute),
			NotAfter:        time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{fulcioIssuerExt(t, issuer)},
		})
		id := Identity{Issuer: issuer, Subject: "mutant"}
		ms, iss, err := id.match(cert)
		if err != nil {
			t.Fatalf("match() = %v, want nil", err)
		}
		if ms != "mutant" || iss != issuer {
			t.Fatalf("match() = (%q,%q), want (mutant,%q)", ms, iss, issuer)
		}
	})

	t.Run("Fulcio OtherName SAN is a subject candidate", func(t *testing.T) {
		on, err := cryptoutils.MarshalOtherNameSAN("mutant", true)
		if err != nil {
			t.Fatalf("MarshalOtherNameSAN: %v", err)
		}
		cert := testCert(t, &x509.Certificate{
			SerialNumber:    big.NewInt(4),
			NotBefore:       time.Now().Add(-time.Minute),
			NotAfter:        time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{fulcioIssuerExt(t, issuer), *on},
		})
		id := Identity{Issuer: issuer, Subject: "mutant"}
		ms, iss, err := id.match(cert)
		if err != nil {
			t.Fatalf("match() = %v, want nil", err)
		}
		if ms != "mutant" || iss != issuer {
			t.Fatalf("match() = (%q,%q), want (mutant,%q)", ms, iss, issuer)
		}
	})
}

// TestFullMatchInvalidPatternFailsClosed pins fullMatch's last-resort
// arm directly: called with a pattern Validate would reject, it answers
// false — never a panic, never a match.
func TestFullMatchInvalidPatternFailsClosed(t *testing.T) {
	if fullMatch("", "(", "anything") {
		t.Fatal("fullMatch(invalid pattern) = true, want false")
	}
}

// TestIdentityValidateAcceptsExactlyWellFormedPolicies proves
// REQ-verify-policy-shape as a for-all property: over every combination
// of empty/exact/valid-regex/invalid-regex on both axes, Validate
// accepts exactly the policies naming one member of each pair with any
// regex compiling — and every accepted regex also compiles in
// fullMatch's anchored `\A(?:…)\z` form, so no accepted pattern can
// escape the wrapper and de-anchor the match.
func TestIdentityValidateAcceptsExactlyWellFormedPolicies(t *testing.T) {
	// Shapes for one exact/regex pair; ok marks the well-formed ones.
	type pairShape struct {
		exact, regex string
		ok           bool
	}
	validRe := rapid.SampledFrom([]string{`.+`, `https://.*`, `[a-z]+@example\.com`, `(a|b)c*`, `\d{3}`, `a{2,4}`})
	invalidRe := rapid.SampledFrom([]string{`(`, `[`, `*`, `(?P<`, `a)\z|(?:`, `a(`, `+x`})
	exact := rapid.SampledFrom([]string{"a@b.com", "https://accounts.google.com", "x"})
	pair := func(rt *rapid.T, label string) pairShape {
		switch rapid.IntRange(0, 4).Draw(rt, label+"Shape") {
		case 0: // neither: malformed
			return pairShape{"", "", false}
		case 1: // exact only: well-formed
			return pairShape{exact.Draw(rt, label+"Exact"), "", true}
		case 2: // valid regex only: well-formed
			return pairShape{"", validRe.Draw(rt, label+"ValidRe"), true}
		case 3: // invalid regex only: malformed
			return pairShape{"", invalidRe.Draw(rt, label+"InvalidRe"), false}
		default: // both: malformed even when each member is individually fine
			return pairShape{exact.Draw(rt, label+"BothExact"), validRe.Draw(rt, label+"BothRe"), false}
		}
	}
	rapid.Check(t, func(rt *rapid.T) {
		iss, sub := pair(rt, "issuer"), pair(rt, "subject")
		id := Identity{Issuer: iss.exact, IssuerRegex: iss.regex, Subject: sub.exact, SubjectRegex: sub.regex}
		err := id.Validate()
		if want := iss.ok && sub.ok; (err == nil) != want {
			t.Fatalf("Validate(%+v) = %v, want ok=%v", id, err, want)
		}
		if err != nil {
			return
		}
		// Wrapper-escape closure: everything Validate accepts must stay a
		// true full match under the anchored compile.
		for _, pat := range []string{id.IssuerRegex, id.SubjectRegex} {
			if pat == "" {
				continue
			}
			if _, aerr := regexp.Compile(`\A(?:` + pat + `)\z`); aerr != nil {
				t.Fatalf("accepted pattern %q does not compile anchored: %v", pat, aerr)
			}
		}
	})
}

// testCert self-signs the template and returns the parsed certificate.
func testCert(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	tmpl.Subject = pkix.Name{CommonName: "gitprov-test"}
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

// fulcioIssuerExt encodes the Fulcio v2 OIDC-issuer extension exactly as
// fulcio does: a DER UTF8String under OID 1.3.6.1.4.1.57264.1.8.
func fulcioIssuerExt(t *testing.T, issuer string) pkix.Extension {
	t.Helper()
	val, err := asn1.MarshalWithParams(issuer, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: val}
}

// selfSignedNoIssuer mints a self-signed leaf with an email SAN but no
// Fulcio OIDC-issuer extension, exercising the fail-closed empty-issuer
// rejection.
func selfSignedNoIssuer(t *testing.T, email string) *x509.Certificate {
	t.Helper()
	return testCert(t, &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{email},
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       time.Now().Add(time.Hour),
	})
}
