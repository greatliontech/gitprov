package gitprov

import (
	"crypto"
	"crypto/x509"
	"testing"

	gitsign "github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

func TestHasEmbeddedRekor(t *testing.T) {
	t.Run("true: real rekorMode=offline fixture has the embedded entry", func(t *testing.T) {
		raw, _ := loadEmbeddedFixture(t)
		got, err := HasEmbeddedRekor(Object{Kind: Commit, Format: SHA1, Raw: raw})
		if err != nil {
			t.Fatalf("HasEmbeddedRekor = %v, want nil", err)
		}
		if !got {
			t.Fatal("HasEmbeddedRekor = false, want true for the embedded-path fixture")
		}
	})

	t.Run("false: a default-mode signed commit embeds no Rekor attribute", func(t *testing.T) {
		vs, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatalf("NewVirtualSigstore: %v", err)
		}
		leaf, key, err := vs.GenerateLeafCert(testSubject, testIssuer)
		if err != nil {
			t.Fatalf("GenerateLeafCert: %v", err)
		}
		payload := minimalCommitPayload()
		sig := detachedCMS(t, payload, []*x509.Certificate{leaf}, key.(crypto.Signer))
		raw, err := gitsign.JoinCommit(&gitsign.CommitSig{Payload: payload, Gpgsig: sig})
		if err != nil {
			t.Fatalf("JoinCommit: %v", err)
		}
		got, err := HasEmbeddedRekor(Object{Kind: Commit, Format: SHA1, Raw: raw})
		if err != nil {
			t.Fatalf("HasEmbeddedRekor = %v, want nil", err)
		}
		if got {
			t.Fatal("HasEmbeddedRekor = true, want false for a default-mode (no embedded proof) commit")
		}
	})

	t.Run("error: unsigned commit fails closed", func(t *testing.T) {
		if _, err := HasEmbeddedRekor(Object{Kind: Commit, Format: SHA1, Raw: minimalCommitPayload()}); err == nil {
			t.Fatal("HasEmbeddedRekor = nil error, want error for an unsigned commit")
		}
	})

	t.Run("error: invalid object descriptor fails closed", func(t *testing.T) {
		if _, err := HasEmbeddedRekor(Object{Kind: "blob", Format: SHA1, Raw: minimalCommitPayload()}); err == nil {
			t.Fatal("HasEmbeddedRekor = nil error, want error for an unknown kind")
		}
	})
}
