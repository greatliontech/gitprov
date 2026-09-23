package gitprov

import (
	"bytes"
	"crypto/x509"
	"os"
	"testing"

	gitsign "github.com/sigstore/gitsign/pkg/git"
)

// The real-bytes fixtures under testdata: a genuine gitsign
// rekorMode=offline commit with its contemporaneous trusted root, and a
// genuine default-online-mode commit with no embedded proof. Expected
// values are recorded in testdata/NOTICE.md.
const (
	fixtureSubject = "nikolas.sepos@gmail.com"
	fixtureIssuer  = "https://accounts.google.com"
	fixtureCertFP  = "sha256:ba3d1238f87b7ed76b429476a21c3bc69176a52612ee6519ff4bdccf4ec4d0d4"
	fixtureLogIdx  = int64(1566540772)
	fixtureIntTime = int64(1779093580)
	fixtureRootDig = "sha256:0ba58f6c09c271f664f0f8c1fa62e2065844ca89a0397c0178ed5188f6096724"
)

func loadEmbeddedFixture(t *testing.T) (raw []byte, tr *TrustedRoot) {
	t.Helper()
	raw, err := os.ReadFile("testdata/gitsign-fixture-commit.txt")
	if err != nil {
		t.Fatalf("read fixture commit: %v", err)
	}
	tr, err = LoadTrustedRoot("testdata/gitsign-fixture-trusted-root.json")
	if err != nil {
		t.Fatalf("load fixture trusted root: %v", err)
	}
	return raw, tr
}

// fixtureSigLeaf extracts the CMS signature's DER and the signer leaf
// certificate from the embedded fixture commit, for tests that drive
// the unexported verification internals directly.
func fixtureSigLeaf(t *testing.T) (der []byte, leaf *x509.Certificate) {
	t.Helper()
	raw, _ := loadEmbeddedFixture(t)
	cs, err := gitsign.SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("split fixture commit: %v", err)
	}
	return signerOf(t, cs.Gpgsig)
}

// signerOf decodes an armored sigstore signature to its DER and the
// certificate that signed it, through the production readers.
func signerOf(t *testing.T, armored []byte) (der []byte, leaf *x509.Certificate) {
	t.Helper()
	der, err := sigstoreSignature(armored)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	certs, err := cmsCertificates(der)
	if err != nil || len(certs) == 0 {
		t.Fatalf("signature certs: %v (n=%d)", err, len(certs))
	}
	si, err := parseCMS(der)
	if err != nil {
		t.Fatalf("signature signer: %v", err)
	}
	if leaf, err = si.FindCertificate(certs); err != nil {
		t.Fatalf("signer cert: %v", err)
	}
	return der, leaf
}
