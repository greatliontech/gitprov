package gitprov

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
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

	der := cs.Gpgsig
	if blk, _ := pem.Decode(cs.Gpgsig); blk != nil {
		der = blk.Bytes
	}
	ci, err := protocol.ParseContentInfo(der)
	if err != nil {
		t.Fatalf("parse CMS: %v", err)
	}
	sd, err := ci.SignedDataContent()
	if err != nil {
		t.Fatalf("signed data: %v", err)
	}
	certs, err := sd.X509Certificates()
	if err != nil || len(certs) == 0 {
		t.Fatalf("certs: %v (n=%d)", err, len(certs))
	}
	si := sd.SignerInfos[0]
	leaf, err := si.FindCertificate(certs)
	if err != nil {
		t.Fatalf("find signer cert: %v", err)
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

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
