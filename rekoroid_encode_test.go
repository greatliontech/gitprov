package gitprov

// Test-only faithful port of gitsign v0.16.0 internal/rekor/oid encode side
// (oid.go ToAttributes + pbcompat.go logEntryAnonToProto). Production needs
// only the decode side (rekoroid.go); the encode side exists solely to drive
// TestRekoroidGoldenFidelity exactly as gitsign's own TestOID does — a
// tlog.json → attrs → LogEntryAnon round-trip — so the decode port is
// validated against gitsign's golden vector with gitsign's proven method.
// Apache-2.0, © The Sigstore Authors. Re-audit on any gitsign bump.

import (
	"encoding/hex"
	"fmt"

	"github.com/github/smimesign/ietf-cms/protocol"
	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"google.golang.org/protobuf/proto"
)

func logEntryAnonToProto(le *models.LogEntryAnon, kind *rekorpb.KindVersion) (*rekorpb.TransparencyLogEntry, error) {
	if le == nil {
		return nil, nil
	}
	logID, err := hex.DecodeString(*le.LogID)
	if err != nil {
		return nil, fmt.Errorf("error decoding LogID: %w", err)
	}
	hashes := make([][]byte, 0, len(le.Verification.InclusionProof.Hashes))
	for i, h := range le.Verification.InclusionProof.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("error decoding Verification.InclusionProof.Hashes[%d]: %w", i, err)
		}
		hashes = append(hashes, b)
	}
	rootHash, err := hex.DecodeString(*le.Verification.InclusionProof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("error decoding Verification.InclusionProof.RootHash: %w", err)
	}
	out := &rekorpb.TransparencyLogEntry{
		LogIndex:       *le.LogIndex,
		LogId:          &commonv1.LogId{KeyId: logID},
		IntegratedTime: *le.IntegratedTime,
		InclusionPromise: &rekorpb.InclusionPromise{
			SignedEntryTimestamp: le.Verification.SignedEntryTimestamp,
		},
		InclusionProof: &rekorpb.InclusionProof{
			LogIndex:   *le.Verification.InclusionProof.LogIndex,
			RootHash:   rootHash,
			TreeSize:   *le.Verification.InclusionProof.TreeSize,
			Hashes:     hashes,
			Checkpoint: &rekorpb.Checkpoint{Envelope: *le.Verification.InclusionProof.Checkpoint},
		},
		KindVersion: kind,
	}
	switch b := le.Body.(type) {
	case string:
		out.CanonicalizedBody = []byte(b)
	default:
		return nil, fmt.Errorf("unknown body type %T", le.Body)
	}
	return out, nil
}

func toAttributes(tlog *models.LogEntryAnon) (protocol.Attributes, error) {
	pb, err := logEntryAnonToProto(tlog, &rekorpb.KindVersion{
		Kind:    hashedrekord.KIND,
		Version: hashedrekord_v001.APIVERSION,
	})
	if err != nil {
		return nil, err
	}
	pb.CanonicalizedBody = nil
	out, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}
	attrs := make(protocol.Attributes, 0, 1)
	attr, err := protocol.NewAttribute(oidRekorTransparencyLogEntry, out)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, attr)
	return attrs, nil
}
