package gitprov

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	rekornote "github.com/sigstore/rekor-tiles/v2/pkg/note"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/transparency-dev/formats/log"
	"golang.org/x/mod/sumdb/note"
)

// judgeCheckpoint verifies the checkpoint an inclusion proof carries
// against the pinned log the entry names: a signed note in the log's
// name — a Rekor v1 origin is that name and a tree identifier, a
// Rekor v2 origin the name alone, which must be the host of the
// pinned log's base URL — signed by the log's key under either
// generation's key-hint convention, other signers passed over, its
// root hash the proof's root and its size the proof's tree size: the
// log's witness that the entry is included under a tree state it
// signed, where the signed entry timestamp is its promise to include
// (REQ-verify-embedded-rekor, REQ-image-offline-verification).
func judgeCheckpoint(envelope string, rootHash []byte, treeSize int64, pinned *root.TransparencyLog) error {
	if envelope == "" {
		return errors.New("gitprov: checkpoint: the entry carries none")
	}
	origin, _, ok := strings.Cut(envelope, "\n")
	if !ok || origin == "" {
		return errors.New("gitprov: checkpoint: not a signed note")
	}
	// Rekor v1 signs in the log's name with a numeric tree identifier
	// after it in the origin; Rekor v2's origin is the name.
	name, treeID, generationOne := strings.Cut(origin, " - ")
	if generationOne {
		if _, err := strconv.ParseUint(treeID, 10, 64); err != nil {
			return fmt.Errorf("gitprov: checkpoint: origin %q is neither a Rekor v1 nor a Rekor v2 origin", origin)
		}
	} else {
		u, err := url.Parse(pinned.BaseURL)
		if err != nil || u.Hostname() == "" || u.Hostname() != origin {
			return fmt.Errorf("gitprov: checkpoint: origin %q is not the host of the pinned log's base URL", origin)
		}
	}
	if pinned.SignatureHashFunc == 0 {
		return errors.New("gitprov: checkpoint: the root states no signature hash for the log")
	}
	verifier, err := signature.LoadVerifier(pinned.PublicKey, pinned.SignatureHashFunc)
	if err != nil {
		return fmt.Errorf("gitprov: checkpoint: the pinned log key: %w", err)
	}
	// Rekor v1 hints the key by the SHA-256 of its subject public key
	// info; Rekor v2 by the C2SP convention, which for an ECDSA key
	// is the same bytes — one verifier then, the note's list refusing
	// two of one name and hint.
	v1 := rekorV1Verifier{name: name, hint: rekorV1Hint(pinned.PublicKey), verifier: verifier}
	verifiers := []note.Verifier{v1}
	if v2, err := rekornote.NewNoteVerifier(name, verifier); err == nil && v2.KeyHash() != v1.hint {
		verifiers = append(verifiers, v2)
	}
	n, err := note.Open([]byte(envelope), note.VerifierList(verifiers...))
	if err != nil {
		var unverified *note.UnverifiedNoteError
		var invalid *note.InvalidSignatureError
		if errors.As(err, &unverified) || errors.As(err, &invalid) {
			return errors.New("gitprov: checkpoint: not signed by the pinned log key")
		}
		return fmt.Errorf("gitprov: checkpoint: %w", err)
	}
	var cp log.Checkpoint
	if _, err := cp.Unmarshal([]byte(n.Text)); err != nil {
		return fmt.Errorf("gitprov: checkpoint: %w", err)
	}
	if !bytes.Equal(cp.Hash, rootHash) {
		return errors.New("gitprov: checkpoint: names a root the inclusion proof does not reach")
	}
	if treeSize < 0 || cp.Size != uint64(treeSize) {
		return fmt.Errorf("gitprov: checkpoint: names a tree of %d, the inclusion proof %d", cp.Size, treeSize)
	}
	return nil
}

// rekorV1Verifier verifies a note signature under Rekor v1's key-hint
// convention: the first four bytes of the SHA-256 of the key's
// subject public key info.
type rekorV1Verifier struct {
	name     string
	hint     uint32
	verifier signature.Verifier
}

func (v rekorV1Verifier) Name() string    { return v.name }
func (v rekorV1Verifier) KeyHash() uint32 { return v.hint }
func (v rekorV1Verifier) Verify(msg, sig []byte) bool {
	return v.verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(msg)) == nil
}

// rekorV1Hint is Rekor v1's key hint for a log key; a key that does
// not marshal yields a hint no signature carries.
func rekorV1Hint(pub crypto.PublicKey) uint32 {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return 0
	}
	sum := sha256.Sum256(spki)
	return binary.BigEndian.Uint32(sum[:4])
}
