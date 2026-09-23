package gitprov

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// PinnedKey is a public key the caller hands in for a verification —
// an SSH public key, or an OpenPGP one — verified against directly,
// never looked up (REQ-verify-pinned-key). It is made by ParsePinnedKey
// alone: its fingerprint is derived from the parsed key there, so a
// key and a fingerprint that disagree cannot be built.
type PinnedKey struct {
	kind        SignatureKind
	fingerprint string
	ssh         ssh.PublicKey
}

// Kind is the signature kind the key verifies: OpenPGP or SSH.
func (k PinnedKey) Kind() SignatureKind { return k.kind }

// Fingerprint is the key's fingerprint as its kind spells it: for an
// SSH key, OpenSSH's SHA-256 form ("SHA256:" and the unpadded base64
// of the hash of the key's wire form).
func (k PinnedKey) Fingerprint() string { return k.fingerprint }

// ParsePinnedKey reads a public key of the kind: for SSH, one OpenSSH
// public key line — the key type, its base64, an optional comment,
// nothing before it and no line beside it; an authorized_keys line
// carrying options is no public key, nor is a certificate, and a DSA
// key, or an RSA key under 1024 bits, which OpenSSH refuses, is
// refused.
func ParsePinnedKey(kind SignatureKind, key string) (PinnedKey, error) {
	switch kind {
	case SSH:
		return parseSSHKey(key)
	case OpenPGP:
		// The OpenPGP arm is not built
		// (docs/issues/pinned-key-signatures.md).
		return PinnedKey{}, fmt.Errorf("gitprov: no verifier for a %s key", kind)
	}
	return PinnedKey{}, fmt.Errorf("gitprov: %q is no pinned key kind", kind)
}

func parseSSHKey(line string) (PinnedKey, error) {
	// One line, read whole: the authorized_keys reader passes over
	// lines it cannot read and blank or comment lines to the first key
	// it can, which would pin a key beside a corrupt one silently.
	line = strings.TrimRight(line, " \t\r\n")
	if strings.ContainsAny(line, "\r\n") {
		return PinnedKey{}, errors.New("gitprov: SSH public key: more than one line")
	}
	if first, _ := utf8.DecodeRuneInString(line); line == "" || unicode.IsSpace(first) || first == '#' {
		return PinnedKey{}, errors.New("gitprov: SSH public key: not a public key line")
	}
	pk, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return PinnedKey{}, fmt.Errorf("gitprov: SSH public key: %w", err)
	}
	if len(options) != 0 {
		return PinnedKey{}, errors.New("gitprov: SSH public key: an authorized_keys line with options is no public key")
	}
	if _, isCert := pk.(*ssh.Certificate); isCert {
		return PinnedKey{}, errors.New("gitprov: SSH public key: a certificate is no pinned key")
	}
	if pk.Type() == ssh.KeyAlgoDSA {
		return PinnedKey{}, errors.New("gitprov: SSH public key: DSA keys are refused")
	}
	if ck, ok := pk.(ssh.CryptoPublicKey); ok {
		if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < sshRSAMinimumBits {
			return PinnedKey{}, fmt.Errorf("gitprov: SSH public key: an RSA key of %d bits is under OpenSSH's minimum", rk.N.BitLen())
		}
	}
	return PinnedKey{kind: SSH, fingerprint: ssh.FingerprintSHA256(pk), ssh: pk}, nil
}

// sshRSAMinimumBits is the RSA modulus size OpenSSH refuses below.
const sshRSAMinimumBits = 1024

// VerifiedKey is the proven outcome of a pinned-key verification: the
// kind and fingerprint of the pinned key that verified the signature,
// in place of a Fulcio identity. It carries no signed time, no
// transparency proof binding one to the signature.
type VerifiedKey struct {
	Kind        SignatureKind
	Fingerprint string
}

// VerifyPinned verifies a git object's OpenPGP or SSH signature against
// the pinned keys and no other, offline and without transparency —
// none can be asked for (REQ-verify-pinned-key): the signature at the
// object form's location (REQ-verify-signature-extraction) is of the
// kind its label states (REQ-verify-signature-kind), the signing key
// is found among the pinned keys of that kind by fingerprint, and the
// pinned key — never the key the signature carries — verifies the
// signature over the raw payload bytes (REQ-verify-raw-bytes). Every
// failure — a sigstore signature (ErrSignatureKind), no pinned key of
// the signature's kind, a signature by an unpinned key, one that does
// not verify — returns an error and no VerifiedKey
// (REQ-verify-fail-closed).
func VerifyPinned(obj Object, keys []PinnedKey) (*VerifiedKey, error) {
	if err := obj.validate(); err != nil {
		return nil, err
	}
	payload, sig, err := splitSignature(obj)
	if err != nil {
		return nil, err
	}
	kind, err := signatureFrame(sig)
	if err != nil {
		return nil, err
	}
	switch kind {
	case SSH:
		return verifySSH(payload, sig, keys)
	case OpenPGP:
		// The OpenPGP arm is not built
		// (docs/issues/pinned-key-signatures.md).
		return nil, fmt.Errorf("gitprov: no verifier for a %s signature", kind)
	}
	return nil, fmt.Errorf("%w: a %s signature, verified against a trusted root", ErrSignatureKind, kind)
}

// The SSH signature envelope (OpenSSH's PROTOCOL.sshsig): a preamble,
// the format version, the signer's public key, the namespace the
// signature was made in, a reserved string, the hash algorithm the
// message was hashed with, and the signature over the signed blob —
// the preamble followed by the namespace, the reserved string, the
// algorithm and the message hash as SSH strings. The envelope's
// reserved field goes unread, as the protocol asks of verifiers: the
// blob carries it empty whatever the envelope spells, as OpenSSH's
// signer writes it and its verifier rebuilds it. Decoding is strict
// where OpenSSH's is and stricter in one place, failing closed: a
// FIDO key's signature must assert user presence, which x/crypto
// requires and OpenSSH's verifier does not.
type sshEnvelope struct {
	Preamble  [6]byte
	Version   uint32
	PublicKey string
	Namespace string
	Reserved  string
	HashAlg   string
	Signature string
}

type sshSignedBlob struct {
	Namespace string
	Reserved  string
	HashAlg   string
	Hash      string
}

const (
	sshPreamble  = "SSHSIG"
	sshVersion   = 1
	sshNamespace = "git" // the namespace git signs in
)

// sshHashes are the hash algorithms the envelope may name.
var sshHashes = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha512": sha512.New,
}

// verifySSH verifies an SSH signature over the payload against the
// pinned SSH keys.
func verifySSH(payload, sig []byte, keys []PinnedKey) (*VerifiedKey, error) {
	var pinned []PinnedKey
	for _, k := range keys {
		if k.kind == SSH {
			pinned = append(pinned, k)
		}
	}
	if len(pinned) == 0 {
		return nil, errors.New("gitprov: no pinned key of the signature's kind (ssh)")
	}
	blk, _ := pem.Decode(sig)
	if blk == nil {
		return nil, errors.New("gitprov: the SSH signature's body does not decode as a PEM block")
	}
	// The armor is base64 between the frame lines and nothing else:
	// a header line within it is no armor OpenSSH writes or reads.
	if len(blk.Headers) != 0 {
		return nil, errors.New("gitprov: the SSH signature's armor carries header lines")
	}
	var env sshEnvelope
	if err := ssh.Unmarshal(blk.Bytes, &env); err != nil {
		return nil, fmt.Errorf("gitprov: SSH signature envelope: %w", err)
	}
	if string(env.Preamble[:]) != sshPreamble {
		return nil, fmt.Errorf("gitprov: SSH signature envelope: preamble %q", env.Preamble[:])
	}
	if env.Version != sshVersion {
		return nil, fmt.Errorf("gitprov: SSH signature envelope: version %d", env.Version)
	}
	if env.Namespace != sshNamespace {
		return nil, fmt.Errorf("gitprov: SSH signature made in namespace %q, not git's", env.Namespace)
	}
	newHash, ok := sshHashes[env.HashAlg]
	if !ok {
		return nil, fmt.Errorf("gitprov: SSH signature envelope: hash algorithm %q", env.HashAlg)
	}
	embedded, err := ssh.ParsePublicKey([]byte(env.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("gitprov: SSH signature's key: %w", err)
	}
	// The carried key names the signer and nothing more: the pinned
	// key of its fingerprint is the one that verifies.
	fp := ssh.FingerprintSHA256(embedded)
	var key *PinnedKey
	for i := range pinned {
		if pinned[i].fingerprint == fp {
			key = &pinned[i]
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("gitprov: SSH signature by an unpinned key %s", fp)
	}
	var sshSig ssh.Signature
	if err := ssh.Unmarshal([]byte(env.Signature), &sshSig); err != nil {
		return nil, fmt.Errorf("gitprov: SSH signature: %w", err)
	}
	// OpenSSH refuses the SHA-1 RSA signature form for signatures of
	// this kind; so does this verifier.
	if sshSig.Format == ssh.KeyAlgoRSA {
		return nil, errors.New("gitprov: SSH signature in the ssh-rsa (SHA-1) form is refused")
	}
	// Bytes after the signature blob are what a FIDO key's signature
	// carries — its flags and counter, which the verifier reads — and
	// nothing else's: for every other key they are decoded by no one,
	// and OpenSSH refuses them.
	if len(sshSig.Rest) != 0 && !sshFIDOKey(key.ssh.Type()) {
		return nil, errors.New("gitprov: SSH signature carries bytes after its blob")
	}
	h := newHash()
	h.Write(payload)
	// The blob's reserved field is empty whatever the envelope
	// carries: OpenSSH signs and verifies it so.
	blob := append([]byte(sshPreamble), ssh.Marshal(sshSignedBlob{
		Namespace: env.Namespace,
		Reserved:  "",
		HashAlg:   env.HashAlg,
		Hash:      string(h.Sum(nil)),
	})...)
	if err := key.ssh.Verify(blob, &sshSig); err != nil {
		return nil, fmt.Errorf("gitprov: SSH signature does not verify against the pinned key %s: %w", fp, err)
	}
	return &VerifiedKey{Kind: SSH, Fingerprint: key.fingerprint}, nil
}

// sshFIDOKey reports whether the key type is a FIDO (sk-) one, whose
// signatures carry their flags and counter after the blob.
func sshFIDOKey(keyType string) bool {
	return keyType == ssh.KeyAlgoSKED25519 || keyType == ssh.KeyAlgoSKECDSA256
}
