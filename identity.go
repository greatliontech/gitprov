package gitprov

import (
	"crypto/x509"
	"fmt"
	"regexp"

	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Identity is the caller's statement of who may sign
// (REQ-verify-identity-match): exactly one of Issuer/IssuerRegex and
// exactly one of Subject/SubjectRegex must be set.
type Identity struct {
	Issuer       string // exact OIDC issuer  (xor IssuerRegex)
	IssuerRegex  string // OIDC issuer regex  (xor Issuer)
	Subject      string // exact cert SAN     (xor SubjectRegex)
	SubjectRegex string // cert SAN regex     (xor Subject)
}

// Validate enforces the policy shape (REQ-verify-policy-shape). A
// policy naming neither or both of a pair is ambiguous intent and is
// rejected up front: an unusable policy must never silently pass a
// subject.
func (id Identity) Validate() error {
	switch {
	case id.Issuer == "" && id.IssuerRegex == "":
		return fmt.Errorf("gitprov: identity policy: one of Issuer or IssuerRegex is required")
	case id.Issuer != "" && id.IssuerRegex != "":
		return fmt.Errorf("gitprov: identity policy: Issuer and IssuerRegex are mutually exclusive")
	case id.Subject == "" && id.SubjectRegex == "":
		return fmt.Errorf("gitprov: identity policy: one of Subject or SubjectRegex is required")
	case id.Subject != "" && id.SubjectRegex != "":
		return fmt.Errorf("gitprov: identity policy: Subject and SubjectRegex are mutually exclusive")
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
	if id.IssuerRegex != "" {
		if _, err := regexp.Compile(id.IssuerRegex); err != nil {
			return fmt.Errorf("gitprov: identity policy: invalid IssuerRegex: %w", err)
		}
	}
	if id.SubjectRegex != "" {
		if _, err := regexp.Compile(id.SubjectRegex); err != nil {
			return fmt.Errorf("gitprov: identity policy: invalid SubjectRegex: %w", err)
		}
	}
	return nil
}

// fullMatch reports whether value equals exact (when set) or is fully
// matched by pat (when set). A regex matches only if it spans the
// entire value: a substring match on an identity is a policy bypass
// (REQ-verify-identity-match). RE2 (no backtracking) plus the absolute
// \A…\z anchors make this robust even against a SAN containing
// newlines or regex metacharacters; Validate's bare compile guarantees
// pat cannot escape the wrapper group.
func fullMatch(exact, pat, value string) bool {
	if exact != "" {
		return value == exact
	}
	re, err := regexp.Compile(`\A(?:` + pat + `)\z`)
	if err != nil {
		return false // unreachable: Validate rejects any pat invalid here
	}
	return re.MatchString(value)
}

// certIdentity is the (issuer, subjects) extracted from a verified
// Fulcio leaf: the OIDC issuer from the Fulcio extension
// (OID 1.3.6.1.4.1.57264.1.8, with the v1 .1.1 fallback handled by
// fulcio/pkg/certificate.ParseExtensions) and every SAN
// (URI/email/DNS/IP plus the Fulcio OtherName).
func certIdentity(leaf *x509.Certificate) (issuer string, subjects []string, err error) {
	ext, err := certificate.ParseExtensions(leaf.Extensions)
	if err != nil {
		return "", nil, fmt.Errorf("gitprov: parse fulcio extensions: %w", err)
	}
	subjects = cryptoutils.GetSubjectAlternateNames(leaf) // URI/email/DNS/IP
	if on, err := cryptoutils.UnmarshalOtherNameSAN(leaf.Extensions); err == nil && on != "" {
		subjects = append(subjects, on)
	}
	return ext.Issuer, subjects, nil
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
	if !fullMatch(id.Issuer, id.IssuerRegex, iss) {
		return "", "", fmt.Errorf("gitprov: certificate issuer %q does not match policy", iss)
	}
	for _, s := range subjects {
		if s != "" && fullMatch(id.Subject, id.SubjectRegex, s) {
			return s, iss, nil
		}
	}
	return "", "", fmt.Errorf("gitprov: no certificate SAN %v matches policy", subjects)
}
