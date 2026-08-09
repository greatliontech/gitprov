package gitprov

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// TrustedRoot is a pinned sigstore TUF trusted root plus the digest of
// the exact bytes it was loaded from. The digest is computed over the
// raw bytes before parsing — a parse round-trip is not canonical, so
// only the raw bytes are a stable identity (REQ-root-pinned-bytes) —
// and rides into every VerifiedIdentity produced against this root.
//
// The fields are unexported so the parsed root and its digest can never
// diverge: ParseTrustedRoot/LoadTrustedRoot are the only producers. The
// zero value is unusable and rejected by Verify.
type TrustedRoot struct {
	root   *root.TrustedRoot
	digest string // "sha256:<hex>" of the raw bytes
}

// Digest returns the "sha256:<hex>" digest of the exact raw bytes this
// root was parsed from (REQ-root-pinned-bytes).
func (t *TrustedRoot) Digest() string { return t.digest }

// ParseTrustedRoot pins and parses trusted-root bytes. Fully offline:
// the bytes are the trust anchor, with no TUF refresh of any kind.
func ParseTrustedRoot(raw []byte) (*TrustedRoot, error) {
	sum := sha256.Sum256(raw)
	tr, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("gitprov: parse trusted root: %w", err)
	}
	return &TrustedRoot{root: tr, digest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

// LoadTrustedRoot reads and pins the trusted root at path.
func LoadTrustedRoot(path string) (*TrustedRoot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gitprov: read trusted root %q: %w", path, err)
	}
	tr, err := ParseTrustedRoot(raw)
	if err != nil {
		return nil, fmt.Errorf("gitprov: trusted root %q: %w", path, err)
	}
	return tr, nil
}

// fulcioPools builds the Fulcio root and intermediate x509 pools the
// gitsign CertVerifier needs, from the pinned trusted root's Fulcio
// certificate authorities.
func (t *TrustedRoot) fulcioPools() (roots, intermediates *x509.CertPool, err error) {
	roots = x509.NewCertPool()
	intermediates = x509.NewCertPool()
	cas := t.root.FulcioCertificateAuthorities()
	if len(cas) == 0 {
		return nil, nil, fmt.Errorf("gitprov: trusted root has no Fulcio certificate authorities")
	}
	n := 0
	for _, ca := range cas {
		fca, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			continue
		}
		if fca.Root != nil {
			roots.AddCert(fca.Root)
			n++
		}
		for _, ic := range fca.Intermediates {
			intermediates.AddCert(ic)
		}
	}
	if n == 0 {
		return nil, nil, fmt.Errorf("gitprov: no usable Fulcio root certificates in trusted root")
	}
	return roots, intermediates, nil
}
