package gitprov_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/greatliontech/gitprov"
	"github.com/greatliontech/gitprov/sigstoretest"
	gitsign "github.com/sigstore/gitsign/pkg/git"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/proto"
)

// The CMS unsigned attribute gitsign embeds the entry under, spelled
// here on its own.
var oidEmbeddedEntry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}

const tagPayload = "object 0123456789abcdef0123456789abcdef01234567\ntype commit\ntag v1.0.0\n" +
	"tagger Test Signer <signer@example.com> 1700000100 +0000\n\nrelease v1.0.0\n"

// signedTag is a tag gitsign's offline mode would write: a detached
// CMS signature over the payload by leaf, the entry shape builds
// over that signature embedded as the unsigned attribute, appended
// in-body.
func signedTag(t *testing.T, leaf *x509.Certificate, key *ecdsa.PrivateKey, shape func(message, sig []byte) *protorekor.TransparencyLogEntry) []byte {
	t.Helper()
	der, err := cms.SignDetached([]byte(tagPayload), []*x509.Certificate{leaf}, key)
	if err != nil {
		t.Fatal(err)
	}
	ci, err := protocol.ParseContentInfo(der)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		t.Fatal(err)
	}
	si := &sd.SignerInfos[0]
	message, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := proto.Marshal(shape(message, si.Signature))
	if err != nil {
		t.Fatal(err)
	}
	attr, err := protocol.NewAttribute(oidEmbeddedEntry, raw)
	if err != nil {
		t.Fatal(err)
	}
	si.UnsignedAttrs = append(si.UnsignedAttrs, attr)
	der, err = sd.ContentInfoDER()
	if err != nil {
		t.Fatal(err)
	}
	sig := pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: der})
	tag, err := gitsign.JoinTag(&gitsign.TagSig{Payload: []byte(tagPayload), InBody: sig})
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

// A git object's embedded entry is judged under its checkpoint by the
// pinned log: the log's own verifies; one another log's key signed
// over the same tree fails; one carrying none fails
// (REQ-verify-embedded-rekor).
func TestVerifyJudgesEmbeddedCheckpoint(t *testing.T) {
	s := sigstoretest.New(t)
	leaf, key := s.Leaf(t, "signer@example.com", "https://accounts.example.com")
	id := gitprov.Identity{Subject: "signer@example.com", Issuer: "https://accounts.example.com"}
	body := func(message, sig []byte) []byte {
		b, err := gitprov.HashedRekordBody(context.Background(), message, sig, leaf)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	verify := func(tag []byte) error {
		_, err := gitprov.Verify(context.Background(), gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: tag}, id, s.TrustedRoot(), true)
		return err
	}
	own := signedTag(t, leaf, key, func(message, sig []byte) *protorekor.TransparencyLogEntry {
		return s.LogEntry(t, leaf, body(message, sig), time.Time{})
	})
	if err := verify(own); err != nil {
		t.Fatalf("the log's own checkpoint: %v", err)
	}
	foreign := signedTag(t, leaf, key, func(message, sig []byte) *protorekor.TransparencyLogEntry {
		return s.LogEntryWith(t, leaf, body(message, sig), time.Time{}, sigstoretest.EntryOptions{CheckpointBy: sigstoretest.New(t)})
	})
	if err := verify(foreign); err == nil || !strings.Contains(err.Error(), "checkpoint") || !strings.Contains(err.Error(), "pinned log key") {
		t.Fatalf("a checkpoint another log signed: %v", err)
	}
	none := signedTag(t, leaf, key, func(message, sig []byte) *protorekor.TransparencyLogEntry {
		e := s.LogEntry(t, leaf, body(message, sig), time.Time{})
		e.InclusionProof.Checkpoint = nil
		return e
	})
	if err := verify(none); err == nil || !strings.Contains(err.Error(), "carries none") {
		t.Fatalf("an entry without a checkpoint: %v", err)
	}
}
