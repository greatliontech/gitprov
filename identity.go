package gitprov

import (
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"

	"github.com/greatliontech/glob"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Identity is the caller's statement of who may sign
// (REQ-verify-identity-match): each axis carries exactly one pattern
// kind — an exact string, a full-match regular expression, or a
// full-input glob (`/`-separated component semantics; the
// greatliontech/glob pattern language).
type Identity struct {
	Issuer       string // exact OIDC issuer   (xor the other Issuer kinds)
	IssuerRegex  string // OIDC issuer regex   (xor)
	IssuerGlob   string // OIDC issuer glob    (xor)
	Subject      string // exact cert SAN      (xor the other Subject kinds)
	SubjectRegex string // cert SAN regex      (xor)
	SubjectGlob  string // cert SAN glob       (xor)
}

// ErrIdentityMismatch marks a certificate whose extracted identity does
// not satisfy the policy on some axis (REQ-verify-identity-match) — a
// cryptographically valid signature by a signer the policy does not
// accept, as opposed to invalid or unverifiable evidence. Callers whose
// own policy tolerates unsigned subjects classify on it: an unaccepted
// signer is a non-acceptance, not proof of tampering.
var ErrIdentityMismatch = errors.New("gitprov: certificate identity does not match policy")

// Validate enforces the policy shape (REQ-verify-policy-shape). A
// policy naming none or several of an axis's pattern kinds is ambiguous
// intent and is rejected up front: an unusable policy must never
// silently pass a subject.
func (id Identity) Validate() error {
	if err := validateAxis("Issuer", id.Issuer, id.IssuerRegex, id.IssuerGlob); err != nil {
		return err
	}
	return validateAxis("Subject", id.Subject, id.SubjectRegex, id.SubjectGlob)
}

func validateAxis(axis, exact, pat, glb string) error {
	n := 0
	for _, s := range []string{exact, pat, glb} {
		if s != "" {
			n++
		}
	}
	switch {
	case n == 0:
		return fmt.Errorf("gitprov: identity policy: one of %s, %[1]sRegex, or %[1]sGlob is required", axis)
	case n > 1:
		return fmt.Errorf("gitprov: identity policy: %s, %[1]sRegex, and %[1]sGlob are mutually exclusive", axis)
	}
	// Compile the BARE pattern. This is deliberately not the anchored
	// form fullMatch uses: bare compilation is precisely what rejects a
	// pattern whose parentheses would escape fullMatch's `\A(?:…)\z`
	// wrapper. Any pattern that could break out of the wrapper group has
	// unbalanced parens and fails to compile bare here; any pattern
	// valid bare has balanced parens, so `(?:P)` encloses exactly P and
	// `\A(?:P)\z` stays a true full match. (The pattern is caller
	// policy, never attacker input — the adversary controls the
	// certificate, not the policy.)
	if pat != "" {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("gitprov: identity policy: invalid %sRegex: %w", axis, err)
		}
	}
	// Globs match full-input by construction; compilation is the whole
	// validity question.
	if glb != "" {
		if _, err := glob.Compile(glb); err != nil {
			return fmt.Errorf("gitprov: identity policy: invalid %sGlob: %w", axis, err)
		}
	}
	return nil
}

// fullMatch reports whether value matches the axis's one set pattern
// kind. Every kind spans the entire value: a substring match on an
// identity is a policy bypass (REQ-verify-identity-match). For regex,
// RE2 (no backtracking) plus the absolute \A…\z anchors make this
// robust even against a SAN containing newlines or metacharacters, and
// Validate's bare compile guarantees pat cannot escape the wrapper
// group; globs are full-input by construction.
func fullMatch(exact, pat, glb, value string) bool {
	if exact != "" {
		return value == exact
	}
	if pat != "" {
		re, err := regexp.Compile(`\A(?:` + pat + `)\z`)
		if err != nil {
			return false // unreachable: Validate rejects any pat invalid here
		}
		return re.MatchString(value)
	}
	p, err := glob.Compile(glb)
	if err != nil {
		return false // unreachable: Validate rejects any glb invalid here
	}
	return p.Match(value)
}

// certIdentity is the (issuer, subjects) extracted from a verified
// Fulcio leaf: the OIDC issuer from the Fulcio extension
// (OID 1.3.6.1.4.1.57264.1.8, with the v1 .1.1 fallback handled by
// fulcio/pkg/certificate.ParseExtensions) and every SAN —
// GetSubjectAlternateNames covers all five kinds: URI, email, DNS, IP,
// and the Fulcio OtherName.
func certIdentity(leaf *x509.Certificate) (issuer string, subjects []string, err error) {
	ext, err := certificate.ParseExtensions(leaf.Extensions)
	if err != nil {
		return "", nil, fmt.Errorf("gitprov: parse fulcio extensions: %w", err)
	}
	return ext.Issuer, cryptoutils.GetSubjectAlternateNames(leaf), nil
}

// match verifies a leaf certificate satisfies the policy. Fail-closed:
// any extraction failure, an empty issuer, or no SAN matching is a
// rejection. The matched subject is returned so consumers can record
// the concrete identity that was verified.
func (id Identity) match(leaf *x509.Certificate) (matchedSubject, issuer string, err error) {
	iss, subjects, err := certIdentity(leaf)
	if err != nil {
		return "", "", err
	}
	if iss == "" {
		return "", "", fmt.Errorf("gitprov: certificate has no OIDC issuer extension")
	}
	if !fullMatch(id.Issuer, id.IssuerRegex, id.IssuerGlob, iss) {
		return "", "", fmt.Errorf("%w: certificate issuer %q", ErrIdentityMismatch, iss)
	}
	for _, s := range subjects {
		if s != "" && fullMatch(id.Subject, id.SubjectRegex, id.SubjectGlob, s) {
			return s, iss, nil
		}
	}
	return "", "", fmt.Errorf("%w: no certificate SAN %v matches", ErrIdentityMismatch, subjects)
}
