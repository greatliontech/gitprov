package gitprov

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/greatliontech/stipulator/stipulate/structural"
	gitsign "github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"pgregory.net/rapid"
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
	tr, err := ParseTrustedRoot(virtualTrustedRootBytes(t, vs))
	if err != nil {
		t.Fatalf("ParseTrustedRoot: %v", err)
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
		if vi.TrustedRootDigest != tr.Digest() {
			t.Fatalf("TrustedRootDigest = %q, want %q", vi.TrustedRootDigest, tr.Digest())
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

	t.Run("tag message containing PEM armor still verifies: genuine trailer is last", func(t *testing.T) {
		// An attacker (or an unlucky release note) can embed a full PEM
		// block in the tag MESSAGE. The in-body trailer split takes the
		// LAST block, and the genuine signature is always appended after
		// the message — so the decoy rides inside the signed payload and
		// verification still succeeds over exactly what was signed. A
		// decoy can displace nothing: were it selected, it would have to
		// verify as a signature over the remaining bytes against the
		// pinned Fulcio root.
		decoy := pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: []byte("decoy, not a signature")})
		payload := append([]byte{}, minimalTagPayload()...)
		payload = append(payload, decoy...)
		payload = append(payload, []byte("trailing release notes\n")...)
		sig := detachedCMS(t, payload, []*x509.Certificate{leaf}, signer)
		raw, err := gitsign.JoinTag(&gitsign.TagSig{Payload: payload, InBody: sig})
		if err != nil {
			t.Fatalf("JoinTag: %v", err)
		}
		vi, err := Verify(ctx, Object{Kind: Tag, Format: SHA1, Raw: raw}, policy, tr, false)
		if err != nil {
			t.Fatalf("Verify(tag with PEM decoy in message) = %v, want nil", err)
		}
		if vi.Subject != testSubject {
			t.Fatalf("subject = %q, want %q", vi.Subject, testSubject)
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

	t.Run("nil or zero-value trusted root fails closed, never panics", func(t *testing.T) {
		obj := signedCommit(t, minimalCommitPayload(), SHA1)
		// The zero value is constructible by any caller (unexported
		// fields cannot prevent &TrustedRoot{}); a signed object used to
		// drive it into a nil-pointer panic inside fulcioPools.
		for name, badRoot := range map[string]*TrustedRoot{"nil": nil, "zero-value": {}} {
			if _, err := Verify(ctx, obj, policy, badRoot, false); err == nil ||
				!strings.Contains(err.Error(), "uninitialized trusted root") {
				t.Fatalf("Verify(%s root) = %v, want uninitialized-trusted-root error", name, err)
			}
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

	t.Run("fail-closed: trusted root without Fulcio CAs", func(t *testing.T) {
		empty, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("root.NewTrustedRoot(empty): %v", err)
		}
		obj := signedCommit(t, minimalCommitPayload(), SHA1)
		if _, err := Verify(ctx, obj, policy, &TrustedRoot{root: empty, digest: "sha256:empty"}, false); err == nil ||
			!strings.Contains(err.Error(), "no Fulcio certificate authorities") {
			t.Fatalf("Verify(no-CA root) = %v, want no-Fulcio-CA error", err)
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

// TestSetRekor pins the guard against a transparency entry missing its
// log coordinates: the fields are copied only when both are present,
// and a partial entry is an error, never a zero-valued identity field.
func TestSetRekor(t *testing.T) {
	idx, ts := int64(5), int64(1700000001)
	t.Run("nil logIndex fails", func(t *testing.T) {
		vi := &VerifiedIdentity{}
		if err := setRekor(vi, &models.LogEntryAnon{IntegratedTime: &ts}); err == nil ||
			!strings.Contains(err.Error(), "missing logIndex/integratedTime") {
			t.Fatalf("setRekor = %v, want missing-fields error", err)
		}
	})
	t.Run("nil integratedTime fails", func(t *testing.T) {
		vi := &VerifiedIdentity{}
		if err := setRekor(vi, &models.LogEntryAnon{LogIndex: &idx}); err == nil ||
			!strings.Contains(err.Error(), "missing logIndex/integratedTime") {
			t.Fatalf("setRekor = %v, want missing-fields error", err)
		}
	})
	t.Run("copies both coordinates", func(t *testing.T) {
		vi := &VerifiedIdentity{}
		if err := setRekor(vi, &models.LogEntryAnon{LogIndex: &idx, IntegratedTime: &ts}); err != nil {
			t.Fatalf("setRekor = %v, want nil", err)
		}
		if vi.RekorLogIndex != idx || vi.RekorIntegratedTime != ts {
			t.Fatalf("rekor = (%d,%d), want (%d,%d)", vi.RekorLogIndex, vi.RekorIntegratedTime, idx, ts)
		}
	})
}

// TestParseCMS pins the single CMS-structural-parse path: the DER the
// kind selection yielded parses, a PEM block handed to it does not —
// the block type is judged before the bytes are read, and the parse
// takes the bytes alone — and each malformed layer fails with its own
// error so no failure is silently absorbed by a later stage.
func TestParseCMS(t *testing.T) {
	der, _ := fixtureSigLeaf(t)

	t.Run("the signature's DER parses", func(t *testing.T) {
		if _, err := parseCMS(der); err != nil {
			t.Fatalf("parseCMS(DER) = %v, want nil", err)
		}
	})
	t.Run("a PEM block is not the parse's input", func(t *testing.T) {
		armored := pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: der})
		if _, err := parseCMS(armored); err == nil ||
			!strings.Contains(err.Error(), "parse CMS") {
			t.Fatalf("parseCMS(PEM) = %v, want parse-CMS error", err)
		}
	})
	t.Run("garbage fails at ContentInfo", func(t *testing.T) {
		if _, err := parseCMS([]byte("not a signature")); err == nil ||
			!strings.Contains(err.Error(), "parse CMS") {
			t.Fatalf("parseCMS(garbage) = %v, want parse-CMS error", err)
		}
	})
	t.Run("non-signed-data content type fails at signed-data", func(t *testing.T) {
		inner, err := asn1.Marshal([]byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		// asn1.Marshal writes RawValue fields verbatim (the struct's
		// explicit-tag annotation applies only on parse), so the [0]
		// wrapper is built by hand.
		der, err := asn1.Marshal(protocol.ContentInfo{
			ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, // id-data, not id-signedData
			Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseCMS(der); err == nil ||
			!strings.Contains(err.Error(), "CMS signed-data") {
			t.Fatalf("parseCMS(id-data) = %v, want signed-data error", err)
		}
	})
	t.Run("signed-data without signers fails", func(t *testing.T) {
		eci, err := protocol.NewDataEncapsulatedContentInfo([]byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		sd, err := protocol.NewSignedData(eci)
		if err != nil {
			t.Fatal(err)
		}
		der, err := sd.ContentInfoDER()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseCMS(der); err == nil ||
			!strings.Contains(err.Error(), "no signers") {
			t.Fatalf("parseCMS(no signers) = %v, want no-signers error", err)
		}
	})
}

// TestParseSignerInfo pins the signer-extraction stage: parse failures
// pass through unchanged and a leaf that is not the CMS signer is a
// mismatch, never silently accepted.
func TestParseSignerInfo(t *testing.T) {
	sig, leaf := fixtureSigLeaf(t)

	t.Run("happy: fixture signer yields message, signature, attrs", func(t *testing.T) {
		message, siSig, attrs, err := parseSignerInfo(sig, leaf)
		if err != nil {
			t.Fatalf("parseSignerInfo = %v, want nil", err)
		}
		if len(message) == 0 || len(siSig) == 0 || len(attrs) == 0 {
			t.Fatalf("empty extraction: message=%d sig=%d attrs=%d", len(message), len(siSig), len(attrs))
		}
	})
	t.Run("garbage passes the parse error through", func(t *testing.T) {
		if _, _, _, err := parseSignerInfo([]byte("junk"), leaf); err == nil ||
			!strings.Contains(err.Error(), "parse CMS") {
			t.Fatalf("parseSignerInfo(junk) = %v, want parse-CMS error", err)
		}
	})
	t.Run("wrong leaf is a signer mismatch", func(t *testing.T) {
		other := selfSignedNoIssuer(t, "other@example.com")
		if _, _, _, err := parseSignerInfo(sig, other); err == nil ||
			!strings.Contains(err.Error(), "signer certificate mismatch") {
			t.Fatalf("parseSignerInfo(wrong leaf) = %v, want mismatch error", err)
		}
	})
}

// TestOfflineRekorVerify pins the embedded transparency stage in
// isolation: the fixture proof verifies against its pinned root, fails
// against a different root's log keys, and a wrong leaf never reaches
// log verification.
func TestOfflineRekorVerify(t *testing.T) {
	ctx := context.Background()
	sig, leaf := fixtureSigLeaf(t)
	_, fixtureTr := loadEmbeddedFixture(t)

	t.Run("happy: proof verifies against the pinned root", func(t *testing.T) {
		e, err := offlineRekorVerify(ctx, sig, leaf, fixtureTr)
		if err != nil {
			t.Fatalf("offlineRekorVerify = %v, want nil", err)
		}
		if e.LogIndex == nil || *e.LogIndex != fixtureLogIdx {
			t.Fatalf("logIndex = %v, want %d", e.LogIndex, fixtureLogIdx)
		}
	})
	t.Run("fail-closed: a different trusted root's log keys reject the proof", func(t *testing.T) {
		vs, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		wrongTr, err := ParseTrustedRoot(virtualTrustedRootBytes(t, vs))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := offlineRekorVerify(ctx, sig, leaf, wrongTr); err == nil {
			t.Fatal("offlineRekorVerify(wrong root) = nil, want error")
		}
	})
	t.Run("fail-closed: wrong leaf is rejected before log verification", func(t *testing.T) {
		other := selfSignedNoIssuer(t, "other@example.com")
		if _, err := offlineRekorVerify(ctx, sig, other, fixtureTr); err == nil ||
			!strings.Contains(err.Error(), "signer certificate mismatch") {
			t.Fatalf("offlineRekorVerify(wrong leaf) = %v, want mismatch error", err)
		}
	})

	t.Run("fail-closed: a genuine embedded entry does not cover a tampered signature", func(t *testing.T) {
		// THE binding property. The fixture's embedded entry is a real,
		// SET-signed, inclusion-proven Rekor entry — for the original
		// signature. Tampering one byte of the SignerInfo signature while
		// keeping that genuine entry must fail: were the recomputed-body
		// binding dropped, the attacker-supplied entry body would verify
		// against the pinned log on its own and lend transparency to a
		// signature the log never saw.
		ci, err := protocol.ParseContentInfo(sig)
		if err != nil {
			t.Fatal(err)
		}
		sd, err := ci.SignedDataContent()
		if err != nil {
			t.Fatal(err)
		}
		sd.SignerInfos[0].Signature[0] ^= 0x01
		tampered, err := sd.ContentInfoDER()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := offlineRekorVerify(ctx, tampered, leaf, fixtureTr); err == nil ||
			!strings.Contains(err.Error(), "canonicalizing entry") {
			t.Fatalf("offlineRekorVerify(tampered sig, genuine entry) = %v, want binding failure", err)
		}
	})

	t.Run("fail-closed: transparency cannot be transplanted onto a different signature", func(t *testing.T) {
		// The other arm of the binding: a signature that is VALID — but
		// for a different message and key — carrying the fixture's
		// genuine, SET-signed, inclusion-proven entry. Canonicalization
		// succeeds (the triple is self-consistent), so the recomputed
		// body diverges from the logged one and the proof must fail at
		// the inclusion stage: an attacker cannot borrow a real log
		// entry to lend transparency to a signature the log never saw.
		vs, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		vLeaf, vKey, err := vs.GenerateLeafCert(testSubject, testIssuer)
		if err != nil {
			t.Fatal(err)
		}
		ownSig := detachedCMS(t, minimalCommitPayload(), []*x509.Certificate{vLeaf}, vKey.(crypto.Signer))
		ownBlk, _ := pem.Decode(ownSig)
		ownCI, err := protocol.ParseContentInfo(ownBlk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		ownSD, err := ownCI.SignedDataContent()
		if err != nil {
			t.Fatal(err)
		}

		fixCI, err := protocol.ParseContentInfo(sig)
		if err != nil {
			t.Fatal(err)
		}
		fixSD, err := fixCI.SignedDataContent()
		if err != nil {
			t.Fatal(err)
		}
		var tlogAttr *protocol.Attribute
		for i, a := range fixSD.SignerInfos[0].UnsignedAttrs {
			if a.Type.Equal(oidRekorTransparencyLogEntry) {
				tlogAttr = &fixSD.SignerInfos[0].UnsignedAttrs[i]
				break
			}
		}
		if tlogAttr == nil {
			t.Fatal("fixture carries no embedded tlog attribute")
		}
		ownSD.SignerInfos[0].UnsignedAttrs = append(ownSD.SignerInfos[0].UnsignedAttrs, *tlogAttr)
		transplanted, err := ownSD.ContentInfoDER()
		if err != nil {
			t.Fatal(err)
		}

		_, err = offlineRekorVerify(ctx, transplanted, vLeaf, fixtureTr)
		if err == nil {
			t.Fatal("offlineRekorVerify(transplanted entry) = nil, want inclusion failure")
		}
		if strings.Contains(err.Error(), "canonicalizing entry") {
			t.Fatalf("failed at canonicalization (%v); the transplant must survive to the inclusion stage to witness the body binding", err)
		}
	})
}

// TestVerifyFailsClosedUnderCorruption proves REQ-verify-fail-closed as
// a for-all property over corruptions of genuinely verifiable objects —
// the real transparency-carrying SHA-1 commit fixture, a certificate-
// only SHA-256-form commit, and an in-body-signed tag: for any
// single-byte flip, truncation, or insertion anywhere in the raw bytes,
// Verify either fails with an error and no identity, or — when the
// corruption is semantically neutral (e.g. inside tolerated PEM slack)
// — succeeds with the exact identity of the uncorrupted object. There
// is no third outcome: no partial success, and no corruption that mints
// a different verified identity.
func TestVerifyFailsClosedUnderCorruption(t *testing.T) {
	ctx := context.Background()
	fixtureRaw, fixtureTr := loadEmbeddedFixture(t)

	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	leaf, key, err := vs.GenerateLeafCert(testSubject, testIssuer)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}
	vsTr, err := ParseTrustedRoot(virtualTrustedRootBytes(t, vs))
	if err != nil {
		t.Fatalf("ParseTrustedRoot: %v", err)
	}
	commitPayload := minimalCommitPayload()
	commitSig := detachedCMS(t, commitPayload, []*x509.Certificate{leaf}, key.(crypto.Signer))
	sha256Commit, err := gitsign.JoinCommit(&gitsign.CommitSig{Payload: commitPayload, GpgsigSha256: commitSig})
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	tagPayload := minimalTagPayload()
	tagSig := detachedCMS(t, tagPayload, []*x509.Certificate{leaf}, key.(crypto.Signer))
	signedTag, err := gitsign.JoinTag(&gitsign.TagSig{Payload: tagPayload, InBody: tagSig})
	if err != nil {
		t.Fatalf("JoinTag: %v", err)
	}

	shapes := []struct {
		name     string
		obj      Object
		tr       *TrustedRoot
		requireT bool
	}{
		{"embedded sha1 commit", Object{Commit, SHA1, fixtureRaw}, fixtureTr, true},
		{"certificate-only sha256-form commit", Object{Commit, SHA256, sha256Commit}, vsTr, false},
		{"in-body signed tag", Object{Tag, SHA1, signedTag}, vsTr, false},
	}
	policy := Identity{Issuer: fixtureIssuer, Subject: fixtureSubject} // fixture identity == virtual identity
	genuine := make([]VerifiedIdentity, len(shapes))
	for i, s := range shapes {
		vi, err := Verify(ctx, s.obj, policy, s.tr, s.requireT)
		if err != nil {
			t.Fatalf("uncorrupted %s does not verify: %v", s.name, err)
		}
		genuine[i] = *vi
	}

	rapid.Check(t, func(rt *rapid.T) {
		si := rapid.IntRange(0, len(shapes)-1).Draw(rt, "shape")
		s, raw := shapes[si], shapes[si].obj.Raw
		pos := rapid.IntRange(0, len(raw)-1).Draw(rt, "pos")
		corrupted := make([]byte, 0, len(raw)+1)
		switch rapid.IntRange(0, 2).Draw(rt, "op") {
		case 0: // flip the byte to a different value
			corrupted = append(corrupted, raw...)
			b := rapid.Byte().Draw(rt, "byte")
			if b == corrupted[pos] {
				b ^= 0xff
			}
			corrupted[pos] = b
		case 1: // truncate at pos (never empty: pos >= 1 branch below)
			if pos == 0 {
				pos = 1
			}
			corrupted = append(corrupted, raw[:pos]...)
		default: // insert a byte at pos
			corrupted = append(corrupted, raw[:pos]...)
			corrupted = append(corrupted, rapid.Byte().Draw(rt, "ins"))
			corrupted = append(corrupted, raw[pos:]...)
		}
		vi, err := Verify(ctx, Object{Kind: s.obj.Kind, Format: s.obj.Format, Raw: corrupted}, policy, s.tr, s.requireT)
		if (vi == nil) == (err == nil) {
			t.Fatalf("%s: partial success: vi=%v err=%v", s.name, vi, err)
		}
		if err == nil && *vi != genuine[si] {
			t.Fatalf("%s: corruption minted a different identity:\ngot  %+v\nwant %+v", s.name, *vi, genuine[si])
		}
	})
}

// TestVerifyEmbeddedFixtureUsesNoNetwork witnesses REQ-verify-offline
// over the full real-bytes path: with the process-default HTTP
// transport replaced by one that fails every request, the complete
// transparency-required verification still succeeds. Guards the
// default-client escape hatch the upstream gitsign/cosign stack uses
// for its online fallbacks; the structural half of the claim — no
// client construction anywhere in the package — is the attested part.
func TestVerifyEmbeddedFixtureUsesNoNetwork(t *testing.T) {
	raw, tr := loadEmbeddedFixture(t)
	prev := http.DefaultTransport
	http.DefaultTransport = networkGuard{t: t}
	defer func() { http.DefaultTransport = prev }()

	vi, err := Verify(context.Background(), Object{Kind: Commit, Format: SHA1, Raw: raw},
		Identity{Issuer: fixtureIssuer, Subject: fixtureSubject}, tr, true)
	if err != nil {
		t.Fatalf("Verify with network disabled = %v, want nil", err)
	}
	if vi.Subject != fixtureSubject {
		t.Fatalf("subject = %q, want %q", vi.Subject, fixtureSubject)
	}
}

// TestProductionImportsCarryNoNetworkCapability proves the structural
// half of REQ-verify-offline at the direct-import altitude: production
// code imports exactly the enumerated surface — no net, no net/http, no
// sigstore service client (rekor/pkg/client, gitsign/pkg/rekor,
// sigstore/pkg/tuf) can be referenced directly without failing this
// analyzer. Allowlisted packages (cosign, gitsign) do transitively
// carry network stacks; that this library only ever drives their
// offline entry points is the runtime half, witnessed by
// TestVerifyEmbeddedFixtureUsesNoNetwork.
func TestProductionImportsCarryNoNetworkCapability(t *testing.T) {
	structural.ImportAllowlist(t, "github.com/greatliontech/gitprov", map[string]structural.ImportRule{
		"github.com/greatliontech/gitprov": {
			ThirdParty: []string{
				"github.com/github/smimesign/ietf-cms/protocol",
				"github.com/go-openapi/strfmt",
				"github.com/greatliontech/glob",
				"golang.org/x/crypto/ssh",
				"github.com/go-openapi/swag/conv",
				"github.com/sigstore/cosign/v3/pkg/cosign",
				"github.com/sigstore/cosign/v3/pkg/cosign/bundle",
				"github.com/sigstore/fulcio/pkg/certificate",
				"github.com/sigstore/gitsign/pkg/git",
				"github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1",
				"github.com/sigstore/rekor/pkg/generated/models",
				"github.com/sigstore/rekor-tiles/v2/pkg/note",
				"github.com/transparency-dev/formats/log",
				"golang.org/x/mod/sumdb/note",
				"github.com/sigstore/rekor/pkg/types",
				"github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1",
				"github.com/sigstore/sigstore-go/pkg/bundle",
				"github.com/sigstore/sigstore-go/pkg/root",
				"github.com/sigstore/sigstore-go/pkg/tlog",
				"github.com/sigstore/sigstore-go/pkg/verify",
				"github.com/sigstore/sigstore/pkg/cryptoutils",
				"github.com/sigstore/sigstore/pkg/signature",
				"github.com/sigstore/sigstore/pkg/signature/payload",
				"google.golang.org/protobuf/proto",
			},
			RestrictStandardLibrary: true,
			StandardLibrary: []string{
				"bytes", "context", "crypto", "crypto/rsa", "crypto/sha256", "crypto/sha512", "crypto/x509",
				"encoding/asn1", "encoding/base64", "encoding/binary", "encoding/hex", "encoding/json", "encoding/pem",
				"errors", "fmt", "hash", "net/url", "os", "regexp", "strconv", "strings", "time", "unicode", "unicode/utf8",
			},
		},
	})
}

type networkGuard struct{ t *testing.T }

func (g networkGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	g.t.Errorf("network attempt during offline verification: %s %s", r.Method, r.URL)
	return nil, fmt.Errorf("network disabled: %s", r.URL)
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
