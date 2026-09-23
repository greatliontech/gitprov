package gitprov

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/google/go-cmp/cmp"
	gitsign "github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// TestRekoroidGoldenFidelity is the highest-leverage test of the
// security-critical port in rekoroid.go. It reproduces gitsign v0.16.0's own
// TestOID assertion exactly — round-trip the golden tlog.json through the
// (test-only) ported encode side into CMS attributes, recompute the
// HashedRekord body from gitsign's recorded real signed commit
// (message/sig/cert), decode via the production port, and assert the result
// is byte-identical to the golden LogEntryAnon. A divergence from upstream
// silently weakens transparency verification, so this must stay green across
// gitsign bumps (re-vendor testdata + re-audit the port if it changes). No
// network; fully deterministic.
func TestRekoroidGoldenFidelity(t *testing.T) {
	raw, err := os.ReadFile("testdata/gitsign-oid-commit.txt")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := gitsign.SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("split commit: %v", err)
	}
	if cs.Gpgsig == nil {
		t.Fatal("vendored fixture commit has no gpgsig")
	}

	der, leaf := signerOf(t, cs.Gpgsig)
	si, err := parseCMS(der)
	if err != nil {
		t.Fatalf("parse CMS: %v", err)
	}
	message, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		t.Fatalf("marshal signed attrs: %v", err)
	}

	want := new(models.LogEntryAnon)
	if err := json.Unmarshal(readFile(t, "testdata/gitsign-oid-tlog.json"), want); err != nil {
		t.Fatal(err)
	}
	// Round-trip exactly as gitsign's own TestOID: golden tlog → ported
	// encode → attrs; the real recorded commit supplies message/sig/cert for
	// the HashedRekord Body recompute; ported decode must reproduce the
	// golden byte-for-byte.
	attrs, err := toAttributes(want)
	if err != nil {
		t.Fatalf("toAttributes (ported, test-only): %v", err)
	}
	got, err := toLogEntry(context.Background(), message, si.Signature, leaf, attrs)
	if err != nil {
		t.Fatalf("toLogEntry (ported): %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ported toLogEntry diverged from gitsign golden (-want +got):\n%s", diff)
	}
}

// toLogEntry is the intact 1:1 mirror of gitsign v0.16.0
// internal/rekor/oid.ToLogEntry, kept test-side as the golden-fidelity
// anchor: production uses its two halves (entryFromAttrs +
// bindHashedRekordBody) directly, and this mirror proves the halves
// compose to exactly the upstream shape.
func toLogEntry(ctx context.Context, message []byte, sig []byte, cert *x509.Certificate, attrs protocol.Attributes) (*models.LogEntryAnon, error) {
	out, err := entryFromAttrs(attrs)
	if err != nil {
		return nil, err
	}
	if err := bindHashedRekordBody(ctx, out, message, sig, cert); err != nil {
		return nil, err
	}
	return out, nil
}

// TestEntryFromAttrs pins the embedded-entry decode stage: each layer's
// failure carries its own message so a missing attribute is never
// misread as a corrupt one.
func TestEntryFromAttrs(t *testing.T) {
	t.Run("missing attribute fails", func(t *testing.T) {
		if _, err := entryFromAttrs(protocol.Attributes{}); err == nil ||
			!strings.Contains(err.Error(), "error unmarshalling attribute") {
			t.Fatalf("entryFromAttrs(empty) = %v, want attribute error", err)
		}
	})
	t.Run("attribute with invalid proto bytes fails", func(t *testing.T) {
		attr, err := protocol.NewAttribute(oidRekorTransparencyLogEntry, []byte("not a proto"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entryFromAttrs(protocol.Attributes{attr}); err == nil ||
			!strings.Contains(err.Error(), "unmarshalling TransparencyLogEntry") {
			t.Fatalf("entryFromAttrs(bad proto) = %v, want proto error", err)
		}
	})
}

// TestUnmarshalAttribute pins the attribute plumbing shared by decode
// and detection: a missing OID and an ASN.1 type mismatch each report
// their own stage.
func TestUnmarshalAttribute(t *testing.T) {
	t.Run("missing oid", func(t *testing.T) {
		var b []byte
		if err := unmarshalAttribute(protocol.Attributes{}, oidRekorTransparencyLogEntry, &b); err == nil ||
			!strings.Contains(err.Error(), "get oid") {
			t.Fatalf("unmarshalAttribute(empty) = %v, want get-oid error", err)
		}
	})
	t.Run("wrong ASN.1 type", func(t *testing.T) {
		attr, err := protocol.NewAttribute(oidRekorTransparencyLogEntry, 42) // INTEGER, not OCTET STRING
		if err != nil {
			t.Fatal(err)
		}
		var b []byte
		if err := unmarshalAttribute(protocol.Attributes{attr}, oidRekorTransparencyLogEntry, &b); err == nil ||
			!strings.Contains(err.Error(), "asn1.unmarshal") {
			t.Fatalf("unmarshalAttribute(INTEGER) = %v, want asn1 error", err)
		}
	})
}

// TestBindHashedRekordBody pins the binding stage in isolation. Rekor's
// HashedRekord canonicalization VERIFIES the signature over the data
// hash against the certificate's key — so only a genuinely valid
// (message, sig, cert) triple produces a body, a mismatched triple
// fails at canonicalization, and a nil certificate fails at the marshal
// step, each with its own message.
func TestBindHashedRekordBody(t *testing.T) {
	ctx := context.Background()
	t.Run("nil certificate fails at marshal", func(t *testing.T) {
		e := &models.LogEntryAnon{}
		if err := bindHashedRekordBody(ctx, e, []byte("m"), []byte("s"), nil); err == nil ||
			!strings.Contains(err.Error(), "error marshalling cert") {
			t.Fatalf("bindHashedRekordBody(nil cert) = %v, want marshal error", err)
		}
	})
	t.Run("mismatched triple fails at canonicalization", func(t *testing.T) {
		_, leaf := fixtureSigLeaf(t)
		e := &models.LogEntryAnon{}
		if err := bindHashedRekordBody(ctx, e, []byte("m"), []byte("not the signature"), leaf); err == nil ||
			!strings.Contains(err.Error(), "canonicalizing entry") {
			t.Fatalf("bindHashedRekordBody(bad triple) = %v, want canonicalize error", err)
		}
	})
	t.Run("sets the recomputed body for the genuine triple", func(t *testing.T) {
		sig, leaf := fixtureSigLeaf(t)
		message, siSig, _, err := parseSignerInfo(sig, leaf)
		if err != nil {
			t.Fatalf("parseSignerInfo: %v", err)
		}
		e := &models.LogEntryAnon{}
		if err := bindHashedRekordBody(ctx, e, message, siSig, leaf); err != nil {
			t.Fatalf("bindHashedRekordBody = %v, want nil", err)
		}
		body, ok := e.Body.(string)
		if !ok || body == "" {
			t.Fatalf("e.Body = %#v, want non-empty base64 string", e.Body)
		}
		if _, err := base64.StdEncoding.DecodeString(body); err != nil {
			t.Fatalf("e.Body is not base64: %v", err)
		}
	})
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
