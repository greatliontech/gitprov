package gitprov

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	gitsign "github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// commitSignedWith joins a commit payload with the signature bytes as
// its SHA-1-form signature, whatever the bytes are: the tests hand it
// blocks of every label and shapes that are no block.
func commitSignedWith(t *testing.T, sig []byte) Object {
	t.Helper()
	raw, err := gitsign.JoinCommit(&gitsign.CommitSig{Payload: minimalCommitPayload(), Gpgsig: sig})
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	return Object{Kind: Commit, Format: SHA1, Raw: raw}
}

func block(label string, body []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: body})
}

// pgpArmor is the ASCII armor OpenPGP writes: armor headers, a blank
// line, the body, a checksum line, which no PEM decoder reads.
const pgpArmor = "-----BEGIN PGP SIGNATURE-----\nVersion: test\n\nQUJD\n=abcd\n-----END PGP SIGNATURE-----\n"

// The header line's label selects the kind and nothing but the frame
// is read (REQ-verify-signature-kind): the body under the label does
// not decide, and the signature is exactly one block beginning at its
// first byte.
func TestSignatureKindOf(t *testing.T) {
	der, _ := fixtureSigLeaf(t)
	sigstore := block(sigstoreLabel, der)
	for _, tt := range []struct {
		name    string
		sig     []byte
		want    SignatureKind
		wantErr string
	}{
		{name: "SIGNED MESSAGE is sigstore", sig: sigstore, want: Sigstore},
		{name: "PGP SIGNATURE is OpenPGP", sig: []byte(pgpArmor), want: OpenPGP},
		{name: "SSH SIGNATURE is SSH", sig: block(sshLabel, []byte("opaque")), want: SSH},
		{name: "the label, not the body, decides", sig: block(openPGPLabel, der), want: OpenPGP},
		{name: "an empty body is the label's kind", sig: block(sigstoreLabel, nil), want: Sigstore},
		{name: "whitespace after the footer is the block's", sig: append(append([]byte(nil), sigstore...), "\n\n"...), want: Sigstore},
		{name: "an armor header carrying the marker text", sig: []byte("-----BEGIN PGP SIGNATURE-----\nComment: see -----BEGIN x-----\n\nQUJD\n=abcd\n-----END PGP SIGNATURE-----\n"), want: OpenPGP},
		{name: "a label naming no kind", sig: block("CERTIFICATE", der), wantErr: `"CERTIFICATE" names no signature kind`},
		{name: "PGP MESSAGE names no kind", sig: []byte("-----BEGIN PGP MESSAGE-----\n\nQUJD\n=abcd\n-----END PGP MESSAGE-----\n"), wantErr: `"PGP MESSAGE" names no signature kind`},
		{name: "a bare body is no block", sig: []byte("MIIBCg==\n"), wantErr: "does not begin with an armor header line"},
		{name: "text is no block", sig: []byte("not a signature\n"), wantErr: "does not begin with an armor header line"},
		{name: "bytes before the block", sig: append([]byte("garbage line\n"), sigstore...), wantErr: "does not begin with an armor header line"},
		{name: "a malformed header line", sig: []byte("-----BEGIN SIGNED MESSAGE\nQUJD\n-----END SIGNED MESSAGE-----\n"), wantErr: "header line is malformed"},
		{name: "a malformed block before a sound one", sig: append([]byte("-----BEGIN PGP SIGNATURE-----\nnot base64!\n-----END PGP SIGNATURE-----\n"), sigstore...), wantErr: "more than one armor header line"},
		{name: "two blocks", sig: append(append([]byte(nil), sigstore...), block(openPGPLabel, []byte("x"))...), wantErr: "more than one armor header line"},
		{name: "bytes after the block", sig: append(append([]byte(nil), sigstore...), "trailing"...), wantErr: "beside its armored block"},
		{name: "no footer line", sig: []byte("-----BEGIN SIGNED MESSAGE-----\nQUJD\n"), wantErr: "no armor footer line"},
		{name: "a footer of another label", sig: []byte("-----BEGIN SIGNED MESSAGE-----\nQUJD\n-----END PGP SIGNATURE-----\n"), wantErr: "no armor footer line"},
		{name: "a footer not opening its line", sig: []byte("-----BEGIN SIGNED MESSAGE-----\nQUJD-----END SIGNED MESSAGE-----\n"), wantErr: "no armor footer line"},
		{name: "a second footer within the block", sig: []byte("-----BEGIN SIGNED MESSAGE-----\n-----END PGP SIGNATURE-----\nQUJD\n-----END SIGNED MESSAGE-----\n"), wantErr: "more than one armor footer line"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignatureKindOf(commitSignedWith(t, tt.sig))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("SignatureKindOf = %q, %v; want error %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("SignatureKindOf = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
	t.Run("a non-ASCII space after the footer", func(t *testing.T) {
		// Read at the frame: a commit's signature header cannot carry
		// one, the split stripping Unicode whitespace from its
		// continuation lines and the object then refused as lossy.
		if _, err := signatureFrame(append(append([]byte(nil), sigstore...), "\u00a0\n"...)); err == nil ||
			!strings.Contains(err.Error(), "beside its armored block") {
			t.Fatalf("signatureFrame(non-ASCII space) = %v, want beside-the-block error", err)
		}
	})
	t.Run("an unsigned object has no kind", func(t *testing.T) {
		if _, err := SignatureKindOf(Object{Kind: Commit, Format: SHA1, Raw: minimalCommitPayload()}); err == nil ||
			!strings.Contains(err.Error(), "not signed") {
			t.Fatalf("SignatureKindOf(unsigned) = %v, want not-signed error", err)
		}
	})
	t.Run("an invalid descriptor fails closed", func(t *testing.T) {
		if _, err := SignatureKindOf(Object{Kind: "blob", Format: SHA1, Raw: minimalCommitPayload()}); err == nil ||
			!strings.Contains(err.Error(), "unknown object kind") {
			t.Fatalf("SignatureKindOf(blob) = %v, want unknown-kind error", err)
		}
	})
	t.Run("the fixture's own signature", func(t *testing.T) {
		raw, _ := loadEmbeddedFixture(t)
		got, err := SignatureKindOf(Object{Kind: Commit, Format: SHA1, Raw: raw})
		if err != nil || got != Sigstore {
			t.Fatalf("SignatureKindOf(fixture) = %q, %v; want sigstore", got, err)
		}
	})
}

// The sigstore verifier and the embedded-proof probe read a sigstore
// signature alone: a block of another label — one whose body is no
// CMS, so a parse before the kind check would fail otherwise, and one
// whose body is a CMS signature that would verify — is
// ErrSignatureKind, never read as CMS and never answered false
// (REQ-verify-signature-kind, REQ-detect-embedded). And what the
// verifier is handed is the labelled block's bytes and no other:
// armor text within them names no second block.
func TestSigstorePathsRefuseOtherKinds(t *testing.T) {
	ctx := context.Background()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	tr, err := ParseTrustedRoot(virtualTrustedRootBytes(t, vs))
	if err != nil {
		t.Fatalf("ParseTrustedRoot: %v", err)
	}
	der, _ := fixtureSigLeaf(t)
	raw, fixtureTr := loadEmbeddedFixture(t)
	id := Identity{Subject: fixtureSubject, Issuer: fixtureIssuer}
	for _, tt := range []struct {
		name string
		sig  []byte
	}{
		{"OpenPGP armor", []byte(pgpArmor)},
		{"an SSH block", block(sshLabel, []byte("opaque"))},
		{"CMS bytes under the OpenPGP label", block(openPGPLabel, der)},
	} {
		obj := commitSignedWith(t, tt.sig)
		t.Run(tt.name+" under Verify", func(t *testing.T) {
			if _, err := Verify(ctx, obj, id, tr, false); !errors.Is(err, ErrSignatureKind) {
				t.Fatalf("Verify = %v, want ErrSignatureKind", err)
			}
		})
		t.Run(tt.name+" under HasEmbeddedRekor", func(t *testing.T) {
			if _, err := HasEmbeddedRekor(obj); !errors.Is(err, ErrSignatureKind) {
				t.Fatalf("HasEmbeddedRekor = %v, want ErrSignatureKind", err)
			}
		})
	}
	t.Run("a label naming no kind under Verify", func(t *testing.T) {
		if _, err := Verify(ctx, commitSignedWith(t, block("CERTIFICATE", der)), id, tr, false); err == nil ||
			!strings.Contains(err.Error(), "names no signature kind") {
			t.Fatalf("Verify = %v, want unknown-label error", err)
		}
	})
	t.Run("no block under HasEmbeddedRekor", func(t *testing.T) {
		if _, err := HasEmbeddedRekor(commitSignedWith(t, []byte("MIIBCg==\n"))); err == nil ||
			!strings.Contains(err.Error(), "does not begin with an armor header line") {
			t.Fatalf("HasEmbeddedRekor = %v, want no-block error", err)
		}
	})
	t.Run("armor within the body names no second block", func(t *testing.T) {
		// A sigstore block whose bytes are junk followed by the
		// fixture's whole armored signature: the block's bytes are no
		// CMS, and the verifier must not find the signature within them
		// and verify that instead.
		cs, err := gitsign.SplitCommit(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		nested := block(sigstoreLabel, append([]byte("this is not CMS DER at all\n"), cs.Gpgsig...))
		obj := Object{Kind: Commit, Format: SHA1, Raw: mustJoin(t, cs.Payload, nested)}
		if _, err := Verify(ctx, obj, id, fixtureTr, false); err == nil || errors.Is(err, ErrSignatureKind) {
			t.Fatalf("Verify(nested armor) = %v, want a parse failure", err)
		}
		if _, err := HasEmbeddedRekor(obj); err == nil {
			t.Fatal("HasEmbeddedRekor(nested armor) = nil, want error")
		}
	})
	t.Run("the fixture under its own root verifies as sigstore", func(t *testing.T) {
		obj := Object{Kind: Commit, Format: SHA1, Raw: raw}
		if _, err := Verify(ctx, obj, id, fixtureTr, true); err != nil {
			t.Fatalf("Verify(fixture) = %v, want nil", err)
		}
	})
}

func mustJoin(t *testing.T, payload, sig []byte) []byte {
	t.Helper()
	raw, err := gitsign.JoinCommit(&gitsign.CommitSig{Payload: payload, Gpgsig: sig})
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	return raw
}
