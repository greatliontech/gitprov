package gitprov

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// With transparency required, the leaf of a real gitsign signature is
// judged at the entry's integrated time (REQ-verify-signed-time): the
// contemporaneous root verifies it; a root whose
// certificate-transparency logs are gone cannot verify the leaf's
// signed certificate timestamp and fails; the certificate-only mode
// judges no time and still passes on the same root.
func TestVerifyJudgesLeafAtIntegratedTime(t *testing.T) {
	raw, tr := loadEmbeddedFixture(t)
	obj := Object{Kind: Commit, Format: SHA1, Raw: raw}
	policy := Identity{Issuer: fixtureIssuer, Subject: fixtureSubject}
	vi, err := Verify(context.Background(), obj, policy, tr, true)
	if err != nil {
		t.Fatalf("Verify with transparency: %v", err)
	}
	if vi.RekorIntegratedTime != fixtureIntTime {
		t.Fatalf("integrated time %d, want %d", vi.RekorIntegratedTime, fixtureIntTime)
	}
	// The same root without its certificate-transparency logs.
	rootBytes, err := os.ReadFile("testdata/gitsign-fixture-trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(rootBytes, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "ctlogs")
	stripped, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	noCT, err := ParseTrustedRoot(stripped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), obj, policy, noCT, true); err == nil || !strings.Contains(err.Error(), "signed certificate timestamp") {
		t.Fatalf("a root without CT logs, transparency required: %v", err)
	}
	if _, err := Verify(context.Background(), obj, policy, noCT, false); err != nil {
		t.Fatalf("certificate-only verification judges no signed time: %v", err)
	}
}

// The judgement itself: the real leaf holds at the entry's integrated
// time and fails past its own validity, whatever the clock says now.
func TestJudgeLeafAt(t *testing.T) {
	sig, leaf := fixtureSigLeaf(t)
	_, tr := loadEmbeddedFixture(t)
	extra, err := cmsCertificates(sig)
	if err != nil {
		t.Fatal(err)
	}
	if err := judgeLeafAt(leaf, extra, time.Unix(fixtureIntTime, 0), tr); err != nil {
		t.Fatalf("at the integrated time: %v", err)
	}
	if err := judgeLeafAt(leaf, extra, leaf.NotAfter.Add(time.Hour), tr); err == nil || !strings.Contains(err.Error(), "at the signed time") {
		t.Fatalf("past the leaf's validity: %v", err)
	}
	if err := judgeLeafAt(leaf, extra, time.Now(), tr); err == nil {
		t.Fatal("the leaf, expired long ago, verified at the present")
	}
}
