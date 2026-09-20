package gitprov_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gitprov"
	"github.com/greatliontech/gitprov/sigstoretest"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
)

const tagPayload = "object 0123456789abcdef0123456789abcdef01234567\ntype commit\ntag v1.0.0\n" +
	"tagger Test Signer <signer@example.com> 1700000100 +0000\n\nrelease v1.0.0\n"

// A git object's embedded entry is judged under its checkpoint by the
// pinned log: the log's own verifies; one another log's key signed
// over the same tree fails; one carrying none fails
// (REQ-verify-embedded-rekor).
func TestVerifyJudgesEmbeddedCheckpoint(t *testing.T) {
	s := sigstoretest.New(t)
	leaf, key := s.Leaf(t, "signer@example.com", "https://accounts.example.com")
	id := gitprov.Identity{Subject: "signer@example.com", Issuer: "https://accounts.example.com"}
	verify := func(tag []byte) error {
		_, err := gitprov.Verify(context.Background(), gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: tag}, id, s.TrustedRoot(), true)
		return err
	}
	own := s.SignedTag(t, leaf, key, []byte(tagPayload), sigstoretest.TagOptions{})
	if err := verify(own); err != nil {
		t.Fatalf("the log's own checkpoint: %v", err)
	}
	foreign := s.SignedTag(t, leaf, key, []byte(tagPayload), sigstoretest.TagOptions{Entry: sigstoretest.EntryOptions{CheckpointBy: sigstoretest.New(t)}})
	if err := verify(foreign); err == nil || !strings.Contains(err.Error(), "checkpoint") || !strings.Contains(err.Error(), "pinned log key") {
		t.Fatalf("a checkpoint another log signed: %v", err)
	}
	none := s.SignedTag(t, leaf, key, []byte(tagPayload), sigstoretest.TagOptions{Shape: func(message, sig []byte) *protorekor.TransparencyLogEntry {
		body, err := gitprov.HashedRekordBody(context.Background(), message, sig, leaf)
		if err != nil {
			t.Fatal(err)
		}
		e := s.LogEntry(t, leaf, body, time.Time{})
		e.InclusionProof.Checkpoint = nil
		return e
	}})
	if err := verify(none); err == nil || !strings.Contains(err.Error(), "carries none") {
		t.Fatalf("an entry without a checkpoint: %v", err)
	}
}
