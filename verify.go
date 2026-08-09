package gitprov

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	gitsign "github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// VerifiedIdentity is the proven outcome of a successful verification
// — everything a consumer needs to record what was verified and
// against what.
type VerifiedIdentity struct {
	Subject             string // the cert SAN that matched policy
	Issuer              string // the cert OIDC issuer
	CertFingerprint     string // "sha256:<hex>" of the leaf cert DER
	RekorLogIndex       int64  // transparency not required ⇒ 0; with it, a genuine entry MAY still be index 0 (Rekor logIndex minimum is 0) — not an unset sentinel
	RekorIntegratedTime int64  // 0 iff transparency was not required (a real entry's integratedTime is wall-clock seconds, never the 1970 epoch — this IS a reliable unset signal)
	TrustedRootDigest   string // the pinned-root digest verified against (TrustedRoot.Digest)
}

// Verify verifies a git object's provenance against the policy and the
// pinned trusted root, fully offline (REQ-verify-offline): the CMS
// signature at the object form's location verifies as a detached
// signature over the split payload against a Fulcio chain ending in the
// pinned root (REQ-verify-cert-chain); with requireTransparency, the
// Rekor inclusion proof and signed entry timestamp embedded in the
// signature's unsigned attributes are bound to this signature and
// verified against the pinned root's log keys
// (REQ-verify-embedded-rekor) — a signature with no embedded proof
// (gitsign's default online mode) is unverifiable and fails, with no
// network recovery; and the certificate identity must match policy on
// both axes (REQ-verify-identity-match). Every failure returns an error
// and no VerifiedIdentity (REQ-verify-fail-closed).
func Verify(ctx context.Context, obj Object, id Identity, tr *TrustedRoot, requireTransparency bool) (*VerifiedIdentity, error) {
	if err := obj.validate(); err != nil {
		return nil, err
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	// tr.root is nil only for the zero value — the constructors are the
	// sole producers of a populated TrustedRoot — and the zero value is
	// an unusable root that must error, never panic downstream.
	if tr == nil || tr.root == nil {
		return nil, fmt.Errorf("gitprov: nil or uninitialized trusted root")
	}

	leaf, sig, err := verifyCertChain(ctx, obj, tr)
	if err != nil {
		return nil, err
	}

	vi := &VerifiedIdentity{
		CertFingerprint:   certFingerprint(leaf),
		TrustedRootDigest: tr.digest,
	}
	if requireTransparency {
		tlog, err := offlineRekorVerify(ctx, sig, leaf, tr)
		if err != nil {
			return nil, fmt.Errorf("gitprov: rekor inclusion (offline): %w", err)
		}
		if err := setRekor(vi, tlog); err != nil {
			return nil, err
		}
	}

	subject, issuer, err := id.match(leaf)
	if err != nil {
		return nil, err
	}
	vi.Subject, vi.Issuer = subject, issuer
	return vi, nil
}

// verifyCertChain runs the gitsign Fulcio cert-chain verification on
// the object's detached signature against the pinned trusted root,
// returning the verified leaf and the (PEM) CMS signature bytes.
func verifyCertChain(ctx context.Context, obj Object, tr *TrustedRoot) (leaf *x509.Certificate, sig []byte, err error) {
	payload, sig, err := splitSignature(obj)
	if err != nil {
		return nil, nil, err
	}
	roots, intermediates, err := tr.fulcioPools()
	if err != nil {
		return nil, nil, err
	}
	cv, err := gitsign.NewCertVerifier(
		gitsign.WithRootPool(roots),
		gitsign.WithIntermediatePool(intermediates),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("gitprov: build cert verifier: %w", err)
	}
	// Detached: a git signature signs the payload, not an embedded
	// econtent.
	leaf, err = cv.Verify(ctx, payload, sig, true)
	if err != nil {
		return nil, nil, fmt.Errorf("gitprov: certificate chain: %w", err)
	}
	return leaf, sig, nil
}

func setRekor(vi *VerifiedIdentity, tlog *models.LogEntryAnon) error {
	if tlog.LogIndex == nil || tlog.IntegratedTime == nil {
		return fmt.Errorf("gitprov: rekor entry missing logIndex/integratedTime")
	}
	vi.RekorLogIndex = *tlog.LogIndex
	vi.RekorIntegratedTime = *tlog.IntegratedTime
	return nil
}

func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// parseCMS PEM/DER-decodes a gitsign CMS signature to its first
// SignerInfo. This is the single CMS-structural-parse path of the
// package (embedded-proof detection and signed-attrs extraction), so
// the security-critical parse is audited in exactly one place.
func parseCMS(sig []byte) (protocol.SignerInfo, error) {
	der := sig
	if blk, _ := pem.Decode(sig); blk != nil {
		der = blk.Bytes
	}
	ci, err := protocol.ParseContentInfo(der)
	if err != nil {
		return protocol.SignerInfo{}, fmt.Errorf("gitprov: parse CMS: %w", err)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		return protocol.SignerInfo{}, fmt.Errorf("gitprov: CMS signed-data: %w", err)
	}
	if len(sd.SignerInfos) == 0 {
		return protocol.SignerInfo{}, fmt.Errorf("gitprov: no signers in signature")
	}
	return sd.SignerInfos[0], nil
}

// parseSignerInfo extracts the first CMS SignerInfo's signed-attrs
// "message" (the bytes the signature actually covers), its signature,
// and its unsigned attributes, asserting the signer cert is leaf. Used
// by the embedded transparency verification path.
func parseSignerInfo(sig []byte, leaf *x509.Certificate) (message, siSig []byte, attrs protocol.Attributes, err error) {
	si, err := parseCMS(sig)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := si.FindCertificate([]*x509.Certificate{leaf}); err != nil {
		return nil, nil, nil, fmt.Errorf("gitprov: signer certificate mismatch: %w", err)
	}
	message, err = si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("gitprov: marshal signed attrs: %w", err)
	}
	return message, si.Signature, si.UnsignedAttrs, nil
}

// offlineRekorVerify is the embedded transparency path
// (REQ-verify-embedded-rekor): the entry is decoded from the
// signature's CMS unsigned attributes, bound to this signature, and
// verified offline against the pinned trusted root's Rekor keys. It
// re-implements gitsign pkg/rekor.Client.VerifyInclusion's logic
// without its hard-wired cosign TUF/network global.
func offlineRekorVerify(ctx context.Context, sig []byte, leaf *x509.Certificate, tr *TrustedRoot) (*models.LogEntryAnon, error) {
	message, siSig, attrs, err := parseSignerInfo(sig, leaf)
	if err != nil {
		return nil, err
	}
	e, err := entryFromAttrs(attrs)
	if err != nil {
		return nil, err
	}
	if err := bindHashedRekordBody(ctx, e, message, siSig, leaf); err != nil {
		return nil, err
	}
	if err := cosign.VerifyTLogEntryOffline(ctx, e, nil, tr.root); err != nil {
		return nil, err
	}
	return e, nil
}
