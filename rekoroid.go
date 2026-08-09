package gitprov

// rekoroid is a faithful, verify-path-only port of gitsign v0.16.0
// internal/rekor/oid (oid.go ToLogEntry/unmarshalAttribute + pbcompat.go
// logEntryAnonFromProto). That package is Go-internal and un-importable, and
// gitsign's pkg/rekor.Client.VerifyInclusion is hard-wired to a TUF/network
// global (cosign.TrustedRoot), so the offline reconstruction must live here.
//
// SECURITY-CRITICAL — this reconstructs the Rekor HashedRekord that the
// inclusion proof + SET are verified against; a divergence from upstream
// silently weakens transparency verification. Keep byte-for-byte faithful to
// the pinned gitsign v0.16.0 source; re-audit on any gitsign bump (Apache-2.0,
// © The Sigstore Authors). This file is the one home of that port for every
// consumer of the library — fixes land here, never in downstream copies.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/proto"
)

// oidRekorTransparencyLogEntry is the OID for a serialized Rekor
// TransparencyLogEntry proto (https://github.com/sigstore/rekor/pull/1390).
var oidRekorTransparencyLogEntry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}

// entryFromAttrs decodes the serialized Rekor TransparencyLogEntry proto from
// the CMS unsigned attributes into a LogEntryAnon. It does NOT bind the body
// to any commit — the inclusion proof / SET it carries are attacker-supplied
// until verified; bindHashedRekordBody + cosign.VerifyTLogEntryOffline are
// what make it trustworthy. Faithful port of the decode half of gitsign
// internal/rekor/oid.ToLogEntry.
func entryFromAttrs(attrs protocol.Attributes) (*models.LogEntryAnon, error) {
	var b []byte
	if err := unmarshalAttribute(attrs, oidRekorTransparencyLogEntry, &b); err != nil {
		return nil, fmt.Errorf("error unmarshalling attribute: %w", err)
	}
	pb := new(rekorpb.TransparencyLogEntry)
	if err := proto.Unmarshal(b, pb); err != nil {
		return nil, fmt.Errorf("error unmarshalling TransparencyLogEntry attribute: %w", err)
	}
	return logEntryAnonFromProto(pb), nil
}

// bindHashedRekordBody recomputes the canonical Rekor HashedRekord for
// (message, sig, cert) and **sets e.Body to it**. This is the security-
// critical commit↔entry binding shared by the embedded and the
// supplied/fetched paths: cosign.VerifyTLogEntryOffline verifies the
// inclusion proof and SET against e.Body, so an entry whose logged body is
// not exactly OUR (message, sig, cert) HashedRekord cannot satisfy the proof
// — it fails closed. The entry source (embedded CMS attribute, Rekor query,
// or a lockfile pin) is therefore irrelevant to trust: only an entry whose
// Merkle inclusion commits to this exact HashedRekord passes. Faithful port
// of the body-recompute half of gitsign internal/rekor/oid.ToLogEntry.
func bindHashedRekordBody(ctx context.Context, e *models.LogEntryAnon, message, sig []byte, cert *x509.Certificate) error {
	hash := sha256.Sum256(message)
	certPEM, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return fmt.Errorf("error marshalling cert: %w", err)
	}
	re := &hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: conv.Pointer("sha256"),
					Value:     conv.Pointer(hex.EncodeToString(hash[:])),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(sig),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(certPEM),
				},
			},
		},
	}
	body, err := types.CanonicalizeEntry(ctx, re)
	if err != nil {
		return fmt.Errorf("error canonicalizing entry: %w", err)
	}
	e.Body = base64.StdEncoding.EncodeToString(body)
	return nil
}

func unmarshalAttribute(attrs protocol.Attributes, oid asn1.ObjectIdentifier, target any) error {
	rv, err := attrs.GetOnlyAttributeValueBytes(oid)
	if err != nil {
		return fmt.Errorf("get oid: %w", err)
	}
	if _, err := asn1.Unmarshal(rv.FullBytes, target); err != nil {
		return fmt.Errorf("asn1.unmarshal(%v): %w", oid, err)
	}
	return nil
}

// logEntryAnonFromProto is a faithful port of gitsign
// internal/rekor/oid.logEntryAnonFromProto.
func logEntryAnonFromProto(in *rekorpb.TransparencyLogEntry) *models.LogEntryAnon {
	out := &models.LogEntryAnon{
		LogID:          conv.Pointer(hex.EncodeToString(in.GetLogId().GetKeyId())),
		LogIndex:       conv.Pointer(in.GetLogIndex()),
		IntegratedTime: conv.Pointer(in.GetIntegratedTime()),
		Verification: &models.LogEntryAnonVerification{
			SignedEntryTimestamp: in.GetInclusionPromise().GetSignedEntryTimestamp(),
			InclusionProof: &models.InclusionProof{
				LogIndex:   conv.Pointer(in.GetInclusionProof().GetLogIndex()),
				Checkpoint: conv.Pointer(in.GetInclusionProof().GetCheckpoint().GetEnvelope()),
				TreeSize:   conv.Pointer(in.GetInclusionProof().GetTreeSize()),
				RootHash:   conv.Pointer(hex.EncodeToString(in.GetInclusionProof().GetRootHash())),
				Hashes:     make([]string, 0, len(in.GetInclusionProof().GetHashes())),
			},
		},
		Body: string(in.GetCanonicalizedBody()),
	}
	for _, h := range in.GetInclusionProof().GetHashes() {
		out.Verification.InclusionProof.Hashes = append(out.Verification.InclusionProof.Hashes, hex.EncodeToString(h))
	}
	return out
}
