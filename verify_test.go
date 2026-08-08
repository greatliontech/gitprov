package gitprov

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"encoding/pem"
	cms "github.com/github/smimesign/ietf-cms"

	gitsign "github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

const (
	testSubject = "nikolas.sepos@gmail.com"
	testIssuer  = "https://accounts.google.com"
)

// detachedCMS produces a PEM-armored detached CMS/PKCS7 signature over
// payload, the shape gitsign writes into a git signature location.
func detachedCMS(t *testing.T, payload []byte, chain []*x509.Certificate, signer crypto.Signer) []byte {
	t.Helper()
	der, err := cms.SignDetached(payload, chain, signer)
	if err != nil {
		t.Fatalf("cms.SignDetached: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: der})
}

func TestVerify(t *testing.T) {
	ctx := context.Background()

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	leaf, key, err := vs.GenerateLeafCert(testSubject, testIssuer)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("leaf key %T is not a crypto.Signer", key)
	}
	trPath, _ := newVirtualTrustedRoot(t, vs)
	tr, err := LoadTrustedRoot(trPath)
	if err != nil {
		t.Fatalf("LoadTrustedRoot: %v", err)
	}
	policy := Identity{Issuer: testIssuer, Subject: testSubject}

	wantFP := "sha256:" + hex.EncodeToString(func() []byte { s := sha256.Sum256(leaf.Raw); return s[:] }())

	signedCommit := func(t *testing.T, payload []byte, format ObjectFormat) Object {
		t.Helper()
		sig := detachedCMS(t, payload, []*x509.Certificate{leaf}, signer)
		cs := &gitsign.CommitSig{Payload: payload}
		if format == SHA256 {
			cs.GpgsigSha256 = sig
		} else {
			cs.Gpgsig = sig
		}
		raw, err := gitsign.JoinCommit(cs)
		if err != nil {
			t.Fatalf("JoinCommit: %v", err)
		}
		return Object{Kind: Commit, Format: format, Raw: raw}
	}

	t.Run("happy: certificate-only commit, sha1 form", func(t *testing.T) {
		vi, err := Verify(ctx, signedCommit(t, minimalCommitPayload(), SHA1), policy, tr, false)
		if err != nil {
			t.Fatalf("Verify = %v, want nil", err)
		}
		if vi.Subject != testSubject || vi.Issuer != testIssuer {
			t.Fatalf("identity = (%q,%q), want (%q,%q)", vi.Subject, vi.Issuer, testSubject, testIssuer)
		}
		if vi.CertFingerprint != wantFP {
			t.Fatalf("CertFingerprint = %q, want %q", vi.CertFingerprint, wantFP)
		}
		if vi.TrustedRootDigest != tr.Digest {
			t.Fatalf("TrustedRootDigest = %q, want %q", vi.TrustedRootDigest, tr.Digest)
		}
		if vi.RekorLogIndex != 0 || vi.RekorIntegratedTime != 0 {
			t.Fatalf("rekor fields = (%d,%d), want (0,0) without transparency",
				vi.RekorLogIndex, vi.RekorIntegratedTime)
		}
	})

	t.Run("happy: certificate-only commit, sha256 form", func(t *testing.T) {
		vi, err := Verify(ctx, signedCommit(t, minimalCommitPayload(), SHA256), policy, tr, false)
		if err != nil {
			t.Fatalf("Verify(sha256 form) = %v, want nil", err)
		}
		if vi.Subject != testSubject {
			t.Fatalf("subject = %q, want %q", vi.Subject, testSubject)
		}
	})

	t.Run("happy: annotated tag (in-body), either form", func(t *testing.T) {
		payload := minimalTagPayload()
		sig := detachedCMS(t, payload, []*x509.Certificate{leaf}, signer)
		raw, err := gitsign.JoinTag(&gitsign.TagSig{Payload: payload, InBody: sig})
		if err != nil {
			t.Fatalf("JoinTag: %v", err)
		}
		for _, format := range []ObjectFormat{SHA1, SHA256} {
			vi, err := Verify(ctx, Object{Kind: Tag, Format: format, Raw: raw}, policy, tr, false)
			if err != nil {
				t.Fatalf("Verify(tag, %s) = %v, want nil", format, err)
			}
			if vi.Subject != testSubject || vi.Issuer != testIssuer {
				t.Fatalf("tag identity = (%q,%q), want (%q,%q)", vi.Subject, vi.Issuer, testSubject, testIssuer)
			}
		}
	})

	t.Run("invalid object is rejected before any crypto", func(t *testing.T) {
		if _, err := Verify(ctx, Object{Kind: "blob", Format: SHA1, Raw: []byte("x")}, policy, tr, false); err == nil ||
			!strings.Contains(err.Error(), "unknown object kind") {
			t.Fatalf("Verify = %v, want object-validation error", err)
		}
	})

	t.Run("invalid policy is rejected before any crypto", func(t *testing.T) {
		obj := signedCommit(t, minimalCommitPayload(), SHA1)
		if _, err := Verify(ctx, obj, Identity{}, tr, false); err == nil ||
			!strings.Contains(err.Error(), "is required") {
			t.Fatalf("Verify = %v, want policy-validation error", err)
		}
	})

	t.Run("nil trusted root", func(t *testing.T) {
		obj := signedCommit(t, minimalCommitPayload(), SHA1)
		if _, err := Verify(ctx, obj, policy, nil, false); err == nil ||
			!strings.Contains(err.Error(), "nil trusted root") {
			t.Fatalf("Verify = %v, want nil-trusted-root error", err)
		}
	})

	t.Run("fail-closed: unsigned commit", func(t *testing.T) {
		obj := Object{Kind: Commit, Format: SHA1, Raw: minimalCommitPayload()}
		if _, err := Verify(ctx, obj, policy, tr, false); err == nil ||
			!strings.Contains(err.Error(), "commit is not signed") {
			t.Fatalf("Verify = %v, want unsigned-commit error", err)
		}
	})

	t.Run("fail-closed: identity mismatch", func(t *testing.T) {
		obj := signedCommit(t, minimalCommitPayload(), SHA1)
		wrong := Identity{Issuer: testIssuer, Subject: "attacker@evil.example"}
		if _, err := Verify(ctx, obj, wrong, tr, false); err == nil ||
			!strings.Contains(err.Error(), "SAN") {
			t.Fatalf("Verify = %v, want identity-mismatch error", err)
		}
	})

	t.Run("fail-closed: tampered payload", func(t *testing.T) {
		good := minimalCommitPayload()
		sig := detachedCMS(t, good, []*x509.Certificate{leaf}, signer)
		tampered := bytes.Replace(good, []byte("fixture commit"), []byte("ATTACKER commit"), 1)
		raw, err := gitsign.JoinCommit(&gitsign.CommitSig{Payload: tampered, Gpgsig: sig})
		if err != nil {
			t.Fatalf("JoinCommit: %v", err)
		}
		if _, err := Verify(ctx, Object{Kind: Commit, Format: SHA1, Raw: raw}, policy, tr, false); err == nil ||
			!strings.Contains(err.Error(), "certificate chain") {
			t.Fatalf("Verify = %v, want detached-verify failure on tampered payload", err)
		}
	})

	t.Run("fail-closed: untrusted signer (different CA)", func(t *testing.T) {
		other, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatalf("NewVirtualSigstore(other): %v", err)
		}
		oLeaf, oKey, err := other.GenerateLeafCert(testSubject, testIssuer)
		if err != nil {
			t.Fatalf("GenerateLeafCert(other): %v", err)
		}
		payload := minimalCommitPayload()
		sig := detachedCMS(t, payload, []*x509.Certificate{oLeaf}, oKey.(crypto.Signer))
		raw, err := gitsign.JoinCommit(&gitsign.CommitSig{Payload: payload, Gpgsig: sig})
		if err != nil {
			t.Fatalf("JoinCommit: %v", err)
		}
		// Verified against the *original* trusted root: the chain must
		// fail.
		if _, err := Verify(ctx, Object{Kind: Commit, Format: SHA1, Raw: raw}, policy, tr, false); err == nil ||
			!strings.Contains(err.Error(), "certificate chain") {
			t.Fatalf("Verify = %v, want untrusted-chain failure", err)
		}
	})

	t.Run("fail-closed: transparency required but no embedded proof", func(t *testing.T) {
		obj := signedCommit(t, minimalCommitPayload(), SHA1)
		if _, err := Verify(ctx, obj, policy, tr, true); err == nil ||
			!strings.Contains(err.Error(), "rekor inclusion (offline)") {
			t.Fatalf("Verify = %v, want fail-closed transparency error", err)
		}
	})
}

// TestVerify_EmbeddedFixture is the real-bytes end-to-end proof of the
// embedded offline-verifiable path: a genuine gitsign rekorMode=offline
// commit, transparency required, verified fully offline against the
// contemporaneous pinned trusted root. Asserts the exact identity
// recorded in testdata/NOTICE.md.
func TestVerify_EmbeddedFixture(t *testing.T) {
	raw, tr := loadEmbeddedFixture(t)
	vi, err := Verify(context.Background(), Object{Kind: Commit, Format: SHA1, Raw: raw},
		Identity{Issuer: fixtureIssuer, Subject: fixtureSubject}, tr, true)
	if err != nil {
		t.Fatalf("Verify(embedded fixture, transparency) = %v, want nil", err)
	}
	if vi.Subject != fixtureSubject || vi.Issuer != fixtureIssuer {
		t.Fatalf("identity = (%q,%q), want (%q,%q)", vi.Subject, vi.Issuer, fixtureSubject, fixtureIssuer)
	}
	if vi.CertFingerprint != fixtureCertFP {
		t.Fatalf("CertFingerprint = %q, want %q", vi.CertFingerprint, fixtureCertFP)
	}
	if vi.RekorLogIndex != fixtureLogIdx || vi.RekorIntegratedTime != fixtureIntTime {
		t.Fatalf("rekor = (%d,%d), want (%d,%d)", vi.RekorLogIndex, vi.RekorIntegratedTime, fixtureLogIdx, fixtureIntTime)
	}
	if vi.TrustedRootDigest != fixtureRootDig {
		t.Fatalf("TrustedRootDigest = %q, want %q", vi.TrustedRootDigest, fixtureRootDig)
	}
}

// TestVerify_OnlineModeFixtureFailsClosed is the real-bytes proof of the
// embedded-only stance: a genuine gitsign default-online-mode commit (no
// embedded proof) is unverifiable with transparency required and MUST
// fail closed — even though the commit IS in Rekor and its signature is
// valid (gitsign verify confirmed identity + tlog index 1566725997).
// There is no network recovery.
func TestVerify_OnlineModeFixtureFailsClosed(t *testing.T) {
	raw, err := os.ReadFile("testdata/gitsign-online-fixture-commit.txt")
	if err != nil {
		t.Fatalf("read online fixture: %v", err)
	}
	obj := Object{Kind: Commit, Format: SHA1, Raw: raw}

	has, err := HasEmbeddedRekor(obj)
	if err != nil {
		t.Fatalf("HasEmbeddedRekor = %v, want nil (commit is validly signed, just online-mode)", err)
	}
	if has {
		t.Fatal("HasEmbeddedRekor = true, want false for a default-online-mode commit")
	}

	_, tr := loadEmbeddedFixture(t) // any pinned root; verification never reaches log matching
	if _, err := Verify(context.Background(), obj,
		Identity{Issuer: fixtureIssuer, Subject: fixtureSubject}, tr, true); err == nil {
		t.Fatal("Verify(online-mode, transparency) = nil, want fail-closed error")
	}
}
