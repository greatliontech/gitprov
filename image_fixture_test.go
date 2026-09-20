package gitprov

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// virtualFulcio issues the leaves the image fixtures sign with: a
// root, an intermediate, and a certificate-transparency log whose
// signed certificate timestamp every leaf embeds — the part of a
// sigstore the virtual one does not model. Its Rekor and timestamp
// authority are the virtual sigstore's, which sign for any leaf.
type virtualFulcio struct {
	rootCert, intermediate *x509.Certificate
	interKey               *ecdsa.PrivateKey
	ctKey                  *ecdsa.PrivateKey
	serial                 int64
}

func newVirtualFulcio(t *testing.T) *virtualFulcio {
	t.Helper()
	rootKey := ecdsaKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fixture-fulcio-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootCert := issue(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	interKey := ecdsaKey(t)
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "fixture-fulcio-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediate := issue(t, interTemplate, rootCert, &interKey.PublicKey, rootKey)
	return &virtualFulcio{rootCert: rootCert, intermediate: intermediate, interKey: interKey, ctKey: ecdsaKey(t), serial: 100}
}

func ecdsaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t *testing.T, template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ctLogID is the log identifier a signed certificate timestamp names:
// the SHA-256 of the log key's SubjectPublicKeyInfo.
func (f *virtualFulcio) ctLogID(t *testing.T) [32]byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(&f.ctKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(spki)
}

// leaf issues a short-lived Fulcio leaf for subject and issuer, as
// Fulcio does: the email as a SAN, the issuer in the Fulcio
// extension, code signing, and an embedded signed certificate
// timestamp over the pre-certificate — the base leaf without the
// timestamp extension — signed by the log key, as the verifier
// reconstructs it from the final leaf and the issuing intermediate.
func (f *virtualFulcio) leaf(t *testing.T, subject, issuer string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	f.serial++
	key := ecdsaKey(t)
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(f.serial),
		EmailAddresses: []string{subject},
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       time.Now().Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Value: []byte(issuer),
		}},
	}
	base := issue(t, template, f.intermediate, &key.PublicKey, f.interKey)
	logID := f.ctLogID(t)
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logID},
		Timestamp:  uint64(time.Now().UnixMilli()),
	}
	entry := ct.LogEntry{Leaf: ct.MerkleTreeLeaf{
		Version:  ct.V1,
		LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: sct.Timestamp,
			EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{
				IssuerKeyHash:  sha256.Sum256(f.intermediate.RawSubjectPublicKeyInfo),
				TBSCertificate: base.RawTBSCertificate,
			},
		},
	}}
	input, err := ct.SerializeSCTSignatureInput(sct, entry)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(input)
	sig, err := f.ctKey.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sct.Signature = ct.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA256, Signature: tls.ECDSA},
		Signature: sig,
	}
	list, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		t.Fatal(err)
	}
	listBytes, err := tls.Marshal(*list)
	if err != nil {
		t.Fatal(err)
	}
	asnList, err := asn1.Marshal(listBytes)
	if err != nil {
		t.Fatal(err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT), Value: asnList})
	return issue(t, template, f.intermediate, &key.PublicKey, f.interKey), key
}

// trustedRoot pins a root naming this Fulcio, its transparency log,
// and the virtual sigstore's timestamp authority and Rekor log —
// the log identifiers decoded from the hex spelling the virtual
// sigstore holds them as, so the pinned root keys its logs as a real
// one does. rekor overrides the virtual Rekor logs where given.
func (f *virtualFulcio) trustedRoot(t *testing.T, vs *ca.VirtualSigstore, rekor map[string]*root.TransparencyLog) *TrustedRoot {
	t.Helper()
	if rekor == nil {
		rekor = logsWithDecodedIDs(t, vs.RekorLogs())
	}
	logID := f.ctLogID(t)
	ctlogs := map[string]*root.TransparencyLog{hex.EncodeToString(logID[:]): {
		ID:                  logID[:],
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(24 * time.Hour),
		HashFunc:            crypto.SHA256,
		PublicKey:           &f.ctKey.PublicKey,
		SignatureHashFunc:   crypto.SHA256,
	}}
	fulcio := &root.FulcioCertificateAuthority{
		Root:                f.rootCert,
		Intermediates:       []*x509.Certificate{f.intermediate},
		ValidityPeriodStart: time.Now().Add(-time.Hour),
		ValidityPeriodEnd:   time.Now().Add(24 * time.Hour),
		URI:                 "https://fulcio.fixture.invalid",
	}
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{fulcio}, ctlogs, vs.TimestampingAuthorities(), rekor)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := ParseTrustedRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	return pinned
}

func logsWithDecodedIDs(t *testing.T, logs map[string]*root.TransparencyLog) map[string]*root.TransparencyLog {
	t.Helper()
	out := map[string]*root.TransparencyLog{}
	for k, l := range logs {
		id, err := hex.DecodeString(string(l.ID))
		if err != nil {
			t.Fatal(err)
		}
		c := *l
		c.ID = id
		out[k] = &c
	}
	return out
}

// pemOf renders a certificate as PEM, as cosign annotates one.
func pemOf(c *x509.Certificate) string {
	b, _ := cryptoutils.MarshalCertificateToPEM(c)
	return string(b)
}
