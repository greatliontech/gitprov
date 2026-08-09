package gitprov

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
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
		{"glob/glob ok", Identity{IssuerGlob: "https://**", SubjectGlob: "*@b.com"}, ""},
		{"exact issuer + glob subject ok", Identity{Issuer: "https://x", SubjectGlob: "https://github.com/acme/**"}, ""},
		{"no issuer at all", Identity{Subject: "a@b.com"}, "one of Issuer, IssuerRegex, or IssuerGlob is required"},
		{"both issuer forms", Identity{Issuer: "x", IssuerRegex: "y", Subject: "a@b.com"}, "Issuer, IssuerRegex, and IssuerGlob are mutually exclusive"},
		{"regex and glob issuer", Identity{IssuerRegex: "x", IssuerGlob: "y", Subject: "a@b.com"}, "mutually exclusive"},
		{"all three subject forms", Identity{Issuer: "x", Subject: "a", SubjectRegex: "b", SubjectGlob: "c"}, "mutually exclusive"},
		{"no subject at all", Identity{Issuer: "x"}, "one of Subject, SubjectRegex, or SubjectGlob is required"},
		{"both subject forms", Identity{Issuer: "x", Subject: "a", SubjectRegex: "b"}, "Subject, SubjectRegex, and SubjectGlob are mutually exclusive"},
		{"invalid issuerRegex", Identity{IssuerRegex: "(", Subject: "a@b.com"}, "invalid IssuerRegex"},
		{"invalid subjectRegex", Identity{Issuer: "x", SubjectRegex: "["}, "invalid SubjectRegex"},
		{"invalid issuerGlob", Identity{IssuerGlob: "[a", Subject: "a@b.com"}, "invalid IssuerGlob"},
		{"invalid subjectGlob", Identity{Issuer: "x", SubjectGlob: "{a"}, "invalid SubjectGlob"},
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

	t.Run("glob subject matches component-aware", func(t *testing.T) {
		id := Identity{Issuer: issuer, SubjectGlob: "*@gmail.com"}
		ms, iss, err := id.match(leaf)
		if err != nil {
			t.Fatalf("match() = %v, want nil", err)
		}
		if ms != subject || iss != issuer {
			t.Fatalf("match() = (%q,%q), want (%q,%q)", ms, iss, subject, issuer)
		}
	})

	t.Run("glob issuer matches across components with **", func(t *testing.T) {
		id := Identity{IssuerGlob: "https://**", Subject: subject}
		if _, _, err := id.match(leaf); err != nil {
			t.Fatalf("match() = %v, want nil", err)
		}
	})

	t.Run("glob subject spans the value (substring is a bypass)", func(t *testing.T) {
		// "nikolas.sepos" without wildcards must not match the full SAN.
		id := Identity{Issuer: issuer, SubjectGlob: "nikolas.sepos"}
		if _, _, err := id.match(leaf); err == nil {
			t.Fatal("match() = nil, want error: a glob is a full-input match, never a substring")
		}
	})

	t.Run("glob * does not cross a / component boundary", func(t *testing.T) {
		// "https:/*" is two /-separated components; the issuer
		// "https://accounts.google.com" is three. A single * is
		// component-scoped and must not absorb the extra "/" — only **
		// crosses components.
		id := Identity{IssuerGlob: "https:/*", Subject: subject}
		if _, _, err := id.match(leaf); err == nil {
			t.Fatal("match() = nil, want error: * must not cross a component boundary")
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
		} else if !errors.Is(err, ErrIdentityMismatch) {
			t.Fatalf("issuer mismatch = %v, want errors.Is(ErrIdentityMismatch): callers classify non-acceptance on it", err)
		}
	})

	t.Run("no SAN matches policy", func(t *testing.T) {
		id := Identity{Issuer: issuer, Subject: "someone-else@example.com"}
		if _, _, err := id.match(leaf); err == nil || !strings.Contains(err.Error(), "SAN") {
			t.Fatalf("match() = %v, want no-SAN-match error", err)
		} else if !errors.Is(err, ErrIdentityMismatch) {
			t.Fatalf("SAN mismatch = %v, want errors.Is(ErrIdentityMismatch): callers classify non-acceptance on it", err)
		}
	})

	t.Run("fail-closed: cert with no OIDC issuer extension", func(t *testing.T) {
		bare := selfSignedNoIssuer(t, subject)
		id := Identity{Issuer: issuer, Subject: subject}
		if _, _, err := id.match(bare); err == nil || !strings.Contains(err.Error(), "no OIDC issuer extension") {
			t.Fatalf("match() = %v, want no-issuer-extension error", err)
		} else if errors.Is(err, ErrIdentityMismatch) {
			t.Fatalf("missing issuer extension classified as identity mismatch: %v — a malformed certificate is not a mere non-acceptance", err)
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
// arms directly: called with a regex or glob Validate would reject, it
// answers false — never a panic, never a match.
func TestFullMatchInvalidPatternFailsClosed(t *testing.T) {
	if fullMatch("", "(", "", "anything") {
		t.Fatal("fullMatch(invalid regex) = true, want false")
	}
	if fullMatch("", "", "[a", "anything") {
		t.Fatal("fullMatch(invalid glob) = true, want false")
	}
}

// TestIdentityValidateAcceptsExactlyWellFormedPolicies proves
// REQ-verify-policy-shape as a for-all property: over every combination
// of empty/exact/regex/glob (valid and invalid) on both axes, Validate
// accepts exactly the policies naming one valid pattern kind per axis —
// and every accepted regex also compiles in fullMatch's anchored
// `\A(?:…)\z` form, so no accepted pattern can escape the wrapper and
// de-anchor the match.
func TestIdentityValidateAcceptsExactlyWellFormedPolicies(t *testing.T) {
	// Shapes for one axis's pattern kinds; ok marks the well-formed ones.
	type axisShape struct {
		exact, regex, glob string
		ok                 bool
	}
	validRe := rapid.SampledFrom([]string{`.+`, `https://.*`, `[a-z]+@example\.com`, `(a|b)c*`, `\d{3}`, `a{2,4}`})
	invalidRe := rapid.SampledFrom([]string{`(`, `[`, `*`, `(?P<`, `a)\z|(?:`, `a(`, `+x`})
	validGlob := rapid.SampledFrom([]string{`*`, `**`, `a/*`, `{a,b}`, `?x`, `*@example.com`, `https://github.com/acme/**`})
	invalidGlob := rapid.SampledFrom([]string{`[a`, `{a`, `[!`, `{a,{b`})
	exact := rapid.SampledFrom([]string{"a@b.com", "https://accounts.google.com", "x"})
	axis := func(rt *rapid.T, label string) axisShape {
		switch rapid.IntRange(0, 6).Draw(rt, label+"Shape") {
		case 0: // nothing: malformed
			return axisShape{ok: false}
		case 1: // exact only: well-formed
			return axisShape{exact: exact.Draw(rt, label+"Exact"), ok: true}
		case 2: // valid regex only: well-formed
			return axisShape{regex: validRe.Draw(rt, label+"ValidRe"), ok: true}
		case 3: // invalid regex only: malformed
			return axisShape{regex: invalidRe.Draw(rt, label+"InvalidRe"), ok: false}
		case 4: // valid glob only: well-formed
			return axisShape{glob: validGlob.Draw(rt, label+"ValidGlob"), ok: true}
		case 5: // invalid glob only: malformed
			return axisShape{glob: invalidGlob.Draw(rt, label+"InvalidGlob"), ok: false}
		default: // two kinds at once: malformed even when each is fine
			return axisShape{exact: exact.Draw(rt, label+"BothExact"), glob: validGlob.Draw(rt, label+"BothGlob"), ok: false}
		}
	}
	rapid.Check(t, func(rt *rapid.T) {
		iss, sub := axis(rt, "issuer"), axis(rt, "subject")
		id := Identity{
			Issuer: iss.exact, IssuerRegex: iss.regex, IssuerGlob: iss.glob,
			Subject: sub.exact, SubjectRegex: sub.regex, SubjectGlob: sub.glob,
		}
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
