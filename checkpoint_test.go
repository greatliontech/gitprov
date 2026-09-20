package gitprov

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	rekornote "github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

// checkpointLog is a Rekor log of a fresh key, pinned in a root as a
// real root keys it.
type checkpointLog struct {
	signer crypto.Signer
	log    *root.TransparencyLog
	tr     *TrustedRoot
}

func newCheckpointLog(t *testing.T, key crypto.Signer, baseURL string) *checkpointLog {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	l := &root.TransparencyLog{
		BaseURL: baseURL, ID: sum[:],
		ValidityPeriodStart: time.Now().Add(-time.Hour), HashFunc: crypto.SHA256,
		PublicKey: key.Public(), SignatureHashFunc: crypto.SHA256,
	}
	logs := map[string]*root.TransparencyLog{hex.EncodeToString(sum[:]): l}
	tr, err := root.NewTrustedRoot(root.TrustedRootMediaType01, nil, nil, nil, logs)
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
	return &checkpointLog{signer: key, log: pinned.root.RekorLogs()[hex.EncodeToString(sum[:])], tr: pinned}
}

func ecdsaLog(t *testing.T, baseURL string) *checkpointLog {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newCheckpointLog(t, key, baseURL)
}

// v1 is a checkpoint as Rekor v1 signs it: the origin the host and a
// tree identifier, the signer named by the host under the SPKI hash
// key hint.
func (l *checkpointLog) v1(t *testing.T, size uint64, rootHash []byte) string {
	t.Helper()
	sv, err := signature.LoadSignerVerifier(l.signer, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := util.CreateAndSignCheckpoint(context.Background(), "rekor.checkpoint.invalid", 1, size, rootHash, sv)
	if err != nil {
		t.Fatal(err)
	}
	return string(cp)
}

// v2 is a checkpoint as Rekor v2 signs it: the origin the log's host
// alone, the signer named by it under the C2SP key hint.
func (l *checkpointLog) v2(t *testing.T, origin string, size uint64, rootHash []byte) string {
	t.Helper()
	sv, err := signature.LoadSignerVerifier(l.signer, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := rekornote.NewNoteSigner(context.Background(), origin, sv)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := note.Sign(&note.Note{Text: string(log.Checkpoint{Origin: origin, Size: size, Hash: rootHash}.Marshal())}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// A checkpoint is judged by the pinned log the entry names: signed by
// its key under either generation's key-hint convention — Rekor v1's
// SPKI hash, Rekor v2's C2SP hint — in the log's name, over the
// proof's root and tree size, a v2 origin the pinned base URL's host;
// other signers on the note are passed over; anything else fails
// (REQ-verify-embedded-rekor).
func TestJudgeCheckpoint(t *testing.T) {
	l := ecdsaLog(t, "https://rekor.checkpoint.invalid")
	other := ecdsaLog(t, "https://rekor.checkpoint.invalid")
	rootHash := sha256.Sum256([]byte("a tree"))
	good := l.v1(t, 2, rootHash[:])
	if err := judgeCheckpoint(good, rootHash[:], 2, l.log); err != nil {
		t.Fatalf("a Rekor v1 checkpoint the log signed over the proof's root and size: %v", err)
	}
	if err := judgeCheckpoint(l.v2(t, "rekor.checkpoint.invalid", 2, rootHash[:]), rootHash[:], 2, l.log); err != nil {
		t.Fatalf("a Rekor v2 checkpoint the log signed: %v", err)
	}
	// An ed25519 log, the public-good Rekor v2 key kind, under the
	// C2SP hint.
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed := newCheckpointLog(t, edKey, "https://rekor.checkpoint.invalid")
	if err := judgeCheckpoint(ed.v2(t, "rekor.checkpoint.invalid", 2, rootHash[:]), rootHash[:], 2, ed.log); err != nil {
		t.Fatalf("an ed25519 log's Rekor v2 checkpoint: %v", err)
	}
	// A witness co-signature beside the log's is passed over: the
	// other log's signature line over the same note text, appended.
	others := other.v1(t, 2, rootHash[:])
	cosigned := good + others[strings.LastIndex(others, "\n\n")+2:]
	if err := judgeCheckpoint(cosigned, rootHash[:], 2, l.log); err != nil {
		t.Fatalf("a co-signed checkpoint: %v", err)
	}
	// The log's own signature line, its bytes tampered, is no signature
	// by the pinned key.
	sigLine := good[strings.LastIndex(good, "\n\n")+2:]
	tampered := good[:strings.LastIndex(good, "\n\n")+2] + strings.Replace(sigLine, sigLine[len(sigLine)-6:len(sigLine)-5], "A", 1)
	if tampered == good {
		tampered = good[:strings.LastIndex(good, "\n\n")+2] + strings.Replace(sigLine, sigLine[len(sigLine)-6:len(sigLine)-5], "B", 1)
	}
	if err := judgeCheckpoint(tampered, rootHash[:], 2, l.log); err == nil || !strings.Contains(err.Error(), "not signed by the pinned log key") {
		t.Fatalf("a tampered signature: %v", err)
	}
	for name, tc := range map[string]struct {
		envelope string
		root     []byte
		size     int64
		want     string
	}{
		"none carried":                      {"", rootHash[:], 2, "carries none"},
		"not a note":                        {"rekor.checkpoint.invalid - 1\n2\n", rootHash[:], 2, "malformed note"},
		"another log's key":                 {other.v1(t, 2, rootHash[:]), rootHash[:], 2, "not signed by the pinned log key"},
		"another root":                      {good, sha256.New().Sum(nil), 2, "root the inclusion proof does not reach"},
		"another size":                      {good, rootHash[:], 3, "names a tree of 2, the inclusion proof 3"},
		"v2 origin not the base URL's host": {l.v2(t, "elsewhere.invalid", 2, rootHash[:]), rootHash[:], 2, "not the host of the pinned log's base URL"},
		"neither generation's origin":       {strings.Replace(good, " - 1\n", " - tree\n", 1), rootHash[:], 2, "neither a Rekor v1 nor a Rekor v2 origin"},
	} {
		err := judgeCheckpoint(tc.envelope, tc.root, tc.size, l.log)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	// A root naming the log without a base URL admits no v2 checkpoint.
	bare := ecdsaLog(t, "")
	if err := judgeCheckpoint(bare.v2(t, "rekor.checkpoint.invalid", 2, rootHash[:]), rootHash[:], 2, bare.log); err == nil || !strings.Contains(err.Error(), "base URL") {
		t.Fatalf("a v2 checkpoint under a log with no base URL: %v", err)
	}
}
