package gitprov

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"golang.org/x/crypto/ssh"
)

// PinnedKey is a public key the caller hands in for a verification —
// an OpenPGP public key, or an SSH one — verified against directly,
// never looked up (REQ-verify-pinned-key). It is made by ParsePinnedKey
// alone: its fingerprint is derived from the parsed key there, so a
// key and a fingerprint that disagree cannot be built.
type PinnedKey struct {
	kind        SignatureKind
	fingerprint string
	ssh         ssh.PublicKey
	pgp         *openpgp.Entity
}

// Kind is the signature kind the key verifies: OpenPGP or SSH.
func (k PinnedKey) Kind() SignatureKind { return k.kind }

// Fingerprint is the key's fingerprint as its kind spells it: for an
// OpenPGP key, the primary key's fingerprint as uppercase hex; for an
// SSH key, OpenSSH's SHA-256 form ("SHA256:" and the unpadded base64
// of the hash of the key's wire form).
func (k PinnedKey) Fingerprint() string { return k.fingerprint }

// ParsePinnedKey reads a public key of the kind. For OpenPGP, one
// armored public key block — a primary key with its subkeys and
// signatures, as gpg exports it — and no other: a block holding
// several keys, or a private key, is refused. For SSH, one OpenSSH
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
		return parseOpenPGPKey(key)
	}
	return PinnedKey{}, fmt.Errorf("gitprov: %q is no pinned key kind", kind)
}

func parseOpenPGPKey(armored string) (PinnedKey, error) {
	const what = "the OpenPGP public key"
	// A key is configuration, pasted from wherever the export went:
	// CRLF line ends are admitted, as gpg admits them on import.
	text := []byte(strings.ReplaceAll(strings.TrimLeft(armored, asciiSpace), "\r\n", "\n"))
	label, err := armorLabel(text, what)
	if err != nil {
		return PinnedKey{}, err
	}
	switch label {
	case openpgp.PublicKeyType:
	case openpgp.PrivateKeyType:
		return PinnedKey{}, errors.New("gitprov: OpenPGP public key: a private key is no pinned key")
	default:
		return PinnedKey{}, fmt.Errorf("gitprov: OpenPGP public key: a block labelled %q", label)
	}
	if err := oneArmoredBlock(text, label, what); err != nil {
		return PinnedKey{}, err
	}
	body, err := armorBody(text)
	if err != nil {
		return PinnedKey{}, fmt.Errorf("gitprov: OpenPGP public key: %w", err)
	}
	// Every packet of the block is read, and read strictly but for a
	// third party's certification: the library's keyring reader passes
	// over a key it cannot read, which would let a block of two keys
	// pin the readable one alone.
	ps, err := readPackets(body, true)
	if err != nil {
		return PinnedKey{}, fmt.Errorf("gitprov: OpenPGP public key: %w", err)
	}
	primaries := 0
	for _, p := range ps {
		switch p := p.(type) {
		case *packet.PublicKey:
			if !p.IsSubkey {
				primaries++
			}
		case *packet.PrivateKey:
			// Private material under a public block's label is private
			// still, the primary's or a subkey's.
			if p.IsSubkey {
				return PinnedKey{}, errors.New("gitprov: OpenPGP public key: a private subkey is no pinned key's")
			}
			return PinnedKey{}, errors.New("gitprov: OpenPGP public key: a private key is no pinned key")
		}
	}
	if len(ps) == 0 {
		return PinnedKey{}, errors.New("gitprov: OpenPGP public key: the block holds no packet")
	}
	if pk, ok := ps[0].(*packet.PublicKey); !ok || pk.IsSubkey {
		return PinnedKey{}, errors.New("gitprov: OpenPGP public key: the first packet is no primary key")
	}
	if primaries != 1 {
		return PinnedKey{}, fmt.Errorf("gitprov: OpenPGP public key: %d keys in the block, want one", primaries)
	}
	e, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(body)))
	if err != nil {
		return PinnedKey{}, fmt.Errorf("gitprov: OpenPGP public key: %w", err)
	}
	return PinnedKey{kind: OpenPGP, fingerprint: openPGPFingerprint(e.PrimaryKey), pgp: e}, nil
}

// readPackets reads every packet of a body, refusing one the library
// cannot read rather than passing it over as its packet reader does.
// For a key block, a third party's certification — a signature of a
// certification type — in a form the library does not carry (a
// non-exportable one, one under an algorithm or of a version it
// lacks) is someone else's statement about the key, and a key is not
// made unpinnable by it: passOverCertifications passes such a packet
// over, every other unreadable packet refused still. A signature body
// passes nothing over: its one packet is the whole of it. Each
// packet's extent and, for a signature, its type are read from the
// bytes here, so a packet the library reads part of and refuses is
// still stepped over whole and judged by what it is.
func readPackets(body []byte, passOverCertifications bool) ([]packet.Packet, error) {
	var ps []packet.Packet
	for i := 0; i < len(body); {
		tag, header, length, err := packetExtent(body[i:])
		if err != nil {
			return nil, err
		}
		raw := body[i : i+header+length]
		i += header + length
		p, err := packet.Read(bytes.NewReader(raw))
		if err != nil {
			if _, unsupported := err.(pgperrors.UnsupportedError); unsupported && passOverCertifications && tag == packetTagSignature {
				if t, ok := signatureTypeOf(raw[header:]); ok && isCertification(t) {
					continue
				}
			}
			return nil, err
		}
		ps = append(ps, p)
	}
	return ps, nil
}

// packetTagSignature is the packet tag of a signature (RFC 9580 §5.2).
const packetTagSignature = 2

// packetExtent reads a packet header at the start of the bytes: the
// tag, the header's length and the body's, in the old and the new
// format alike (RFC 9580 §4.2); a partial-body length, which no key
// block or signature carries, is refused. The body's length is read
// as an unsigned 64-bit number and held to what the bytes hold before
// it is an int: on a 32-bit build a five-byte length would wrap
// negative and pass the check.
func packetExtent(b []byte) (tag byte, header, length int, err error) {
	if len(b) == 0 || b[0]&0x80 == 0 {
		return 0, 0, 0, errors.New("gitprov: OpenPGP packet header malformed")
	}
	var bodyLen uint64
	be := func(bs []byte) uint64 {
		var n uint64
		for _, c := range bs {
			n = n<<8 | uint64(c)
		}
		return n
	}
	if b[0]&0x40 == 0 {
		// The old format: the tag in bits 2–5, the length's own length
		// in the low two bits.
		tag = (b[0] >> 2) & 0x0f
		switch b[0] & 0x03 {
		case 0:
			header = 2
		case 1:
			header = 3
		case 2:
			header = 5
		default:
			return 0, 0, 0, errors.New("gitprov: OpenPGP packet of indeterminate length")
		}
		if len(b) < header {
			return 0, 0, 0, errors.New("gitprov: OpenPGP packet truncated")
		}
		bodyLen = be(b[1:header])
	} else {
		tag = b[0] & 0x3f
		if len(b) < 2 {
			return 0, 0, 0, errors.New("gitprov: OpenPGP packet truncated")
		}
		switch {
		case b[1] < 192:
			header, bodyLen = 2, uint64(b[1])
		case b[1] < 224:
			if len(b) < 3 {
				return 0, 0, 0, errors.New("gitprov: OpenPGP packet truncated")
			}
			header, bodyLen = 3, (uint64(b[1])-192)<<8+uint64(b[2])+192
		case b[1] == 255:
			if len(b) < 6 {
				return 0, 0, 0, errors.New("gitprov: OpenPGP packet truncated")
			}
			header, bodyLen = 6, be(b[2:6])
		default:
			return 0, 0, 0, errors.New("gitprov: OpenPGP packet of partial length")
		}
	}
	if bodyLen > uint64(len(b)-header) {
		return 0, 0, 0, errors.New("gitprov: OpenPGP packet truncated")
	}
	return tag, header, int(bodyLen), nil
}

// signatureTypeOf reads a signature packet body's type by its version:
// the second byte from version 4 on, the third in version 3, after
// the hashed material's length.
func signatureTypeOf(body []byte) (packet.SignatureType, bool) {
	if len(body) == 0 {
		return 0, false
	}
	at := 1
	if body[0] == 3 {
		at = 2
	}
	if len(body) <= at {
		return 0, false
	}
	return packet.SignatureType(body[at]), true
}

// isCertification reports whether a signature type certifies an
// identity: generic, persona, casual, positive.
func isCertification(t packet.SignatureType) bool {
	return t >= packet.SigTypeGenericCert && t <= packet.SigTypePositiveCert
}

// armorBody is the decoded body of an armored block whose frame
// passed. The armor checksum, optional under RFC 9580 and not judged
// by the library, is not judged here: a receiver must not reject on
// it.
func armorBody(text []byte) ([]byte, error) {
	blk, err := armor.Decode(bytes.NewReader(text))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(blk.Body)
}

// openPGPFingerprint spells a key's fingerprint as gpg does in full:
// uppercase hex, no spaces.
func openPGPFingerprint(pk *packet.PublicKey) string {
	return strings.ToUpper(hex.EncodeToString(pk.Fingerprint))
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
		return verifyOpenPGP(payload, sig, keys)
	}
	return nil, fmt.Errorf("%w: a %s signature, verified against a trusted root", ErrSignatureKind, kind)
}

// verifyOpenPGP verifies an OpenPGP detached signature over the
// payload against the pinned OpenPGP keys: the keyring is the pinned
// keys and nothing else, the signer — a primary key or a signing
// subkey — resolved to the pinned key it belongs to by the primary
// key's fingerprint. The body is exactly one signature packet, read
// strictly. The signature is a binary-mode one, as gpg makes for git:
// a text-mode signature is verified over a canonical form of the
// payload, not the raw bytes REQ-verify-raw-bytes names, and is
// refused. Hashes the library refuses for messages — SHA-1 among
// them — are refused. The library does the cryptography; the time is
// judged here, at the signature's own creation time, a time nothing
// attests: the signing key created by then and not expired at it by
// its latest self-signature, the key, the signing subkey and the
// primary identity not revoked at it — a hard revocation (no reason,
// compromise, a reason unknown) against every signature, a soft one
// (superseded, retired) from its time, as RFC 9580 reads them — so
// the verdict of given bytes under given keys never changes with the
// clock, and expiry and revocation reach a caller through unpinning,
// as the tier's contract says. The library's own time judgment is
// not used: it refuses a signature older than the key's latest
// self-signature, which every expiry extension makes.
func verifyOpenPGP(payload, sig []byte, keys []PinnedKey) (*VerifiedKey, error) {
	var ring openpgp.EntityList
	var pinned []PinnedKey
	for _, k := range keys {
		if k.kind == OpenPGP {
			ring = append(ring, k.pgp)
			pinned = append(pinned, k)
		}
	}
	if len(pinned) == 0 {
		return nil, errors.New("gitprov: no pinned key of the signature's kind (openpgp)")
	}
	// The frame passed: the one block here is labelled a signature.
	body, err := armorBody(sig)
	if err != nil {
		return nil, fmt.Errorf("gitprov: OpenPGP signature armor: %w", err)
	}
	ps, err := readPackets(body, false)
	if err != nil {
		return nil, fmt.Errorf("gitprov: OpenPGP signature packet: %w", err)
	}
	if len(ps) != 1 {
		return nil, fmt.Errorf("gitprov: OpenPGP signature body holds %d packets, not one", len(ps))
	}
	pgpSig, ok := ps[0].(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("gitprov: OpenPGP signature body holds a %T, not a signature packet", ps[0])
	}
	if pgpSig.SigType != packet.SigTypeBinary {
		return nil, fmt.Errorf("gitprov: OpenPGP signature of type %#x, not a binary-mode one", int(pgpSig.SigType))
	}
	if (&packet.Config{}).RejectMessageHashAlgorithm(pgpSig.Hash) {
		return nil, fmt.Errorf("gitprov: OpenPGP signature under hash %v, which is refused", pgpSig.Hash)
	}
	if pgpSig.IssuerKeyId == nil {
		return nil, errors.New("gitprov: OpenPGP signature names no issuer")
	}
	// A key signs by what its self-signature's key flags state: a key
	// stating none, as keys from before key flags do, signs nothing
	// here, where gpg infers a use from the algorithm.
	candidates := ring.KeysByIdUsage(*pgpSig.IssuerKeyId, packet.KeyFlagSign)
	if len(candidates) == 0 {
		if len(ring.KeysById(*pgpSig.IssuerKeyId)) != 0 {
			return nil, fmt.Errorf("gitprov: OpenPGP signature by the pinned key %016X, whose key flags do not admit signing", *pgpSig.IssuerKeyId)
		}
		return nil, fmt.Errorf("gitprov: OpenPGP signature by an unpinned key %016X", *pgpSig.IssuerKeyId)
	}
	var key *openpgp.Key
	for i := range candidates {
		// A fresh hash per candidate: verifying consumes the one it is
		// handed, so two keys of one id would judge the second on a
		// spent digest.
		h, err := pgpSig.PrepareVerify()
		if err != nil {
			return nil, fmt.Errorf("gitprov: OpenPGP signature: %w", err)
		}
		h.Write(payload)
		if candidates[i].PublicKey.VerifySignature(h, pgpSig) == nil {
			key = &candidates[i]
			break
		}
	}
	if key == nil {
		return nil, errors.New("gitprov: OpenPGP signature does not verify against the pinned keys")
	}
	if err := openPGPValidAt(key, pgpSig, pgpSig.CreationTime); err != nil {
		return nil, fmt.Errorf("gitprov: OpenPGP signature does not verify against the pinned keys: %w", err)
	}
	fp := openPGPFingerprint(key.Entity.PrimaryKey)
	for i := range pinned {
		if pinned[i].fingerprint == fp {
			return &VerifiedKey{Kind: OpenPGP, Fingerprint: pinned[i].fingerprint}, nil
		}
	}
	// The keyring holds the pinned keys alone, so the signer is one of
	// them by construction.
	return nil, fmt.Errorf("gitprov: OpenPGP signature by an unpinned key %s", fp)
}

// openPGPValidAt judges the signature's signing key at the time: the
// key created by then and not expired at it by its latest
// self-signature — the primary's for a primary key, the binding's and
// the primary's for a subkey — those self-signatures' own lifetimes
// not lapsed by then, neither the key, the primary key, the signing
// subkey nor the primary identity revoked at it, and no critical
// notation this verifier does not know on the signature, the
// self-signature, the binding or its back-signature (RFC 9580: a
// critical subpacket unknown to the verifier fails the signature).
func openPGPValidAt(key *openpgp.Key, sig *packet.Signature, at time.Time) error {
	e := key.Entity
	primarySig, primaryID := e.PrimarySelfSignature()
	if primarySig == nil {
		return errors.New("the key carries no self-signature")
	}
	for _, s := range []*packet.Signature{sig, primarySig, key.SelfSignature, key.SelfSignature.EmbeddedSignature} {
		if err := noCriticalNotation(s); err != nil {
			return err
		}
	}
	if e.PrimaryKey.CreationTime.After(at) {
		return errors.New("the key was not yet created at the signature's time")
	}
	if e.PrimaryKey.KeyExpired(primarySig, at) {
		return errors.New("the key was expired at the signature's time")
	}
	if sigLapsedAt(primarySig, at) {
		return errors.New("the key's self-signature had lapsed at the signature's time")
	}
	if key.PublicKey.IsSubkey {
		if key.PublicKey.CreationTime.After(at) {
			return errors.New("the signing subkey was not yet created at the signature's time")
		}
		if key.PublicKey.KeyExpired(key.SelfSignature, at) {
			return errors.New("the signing subkey was expired at the signature's time")
		}
		if sigLapsedAt(key.SelfSignature, at) {
			return errors.New("the signing subkey's binding had lapsed at the signature's time")
		}
	}
	if openPGPRevokedAt(e.Revocations, at) {
		return errors.New("the key was revoked at the signature's time")
	}
	if key.PublicKey.IsSubkey && openPGPRevokedAt(key.Revocations, at) {
		return errors.New("the signing subkey was revoked at the signature's time")
	}
	if primaryID != nil && openPGPRevokedAt(primaryID.Revocations, at) {
		return errors.New("the key's identity was revoked at the signature's time")
	}
	return nil
}

// noCriticalNotation refuses a signature carrying a critical notation:
// this verifier knows none, so a critical one is a condition it cannot
// honor. A nil signature carries none.
func noCriticalNotation(sig *packet.Signature) error {
	if sig == nil {
		return nil
	}
	for _, n := range sig.Notations {
		if n.IsCritical {
			return fmt.Errorf("a signature carries the critical notation %q, which this verifier does not know", n.Name)
		}
	}
	return nil
}

// sigLapsedAt reports whether a signature's own lifetime had run out
// by the time — its creation and lifetime, never its creation alone:
// a self-signature made after the time is no bound.
func sigLapsedAt(sig *packet.Signature, at time.Time) bool {
	if sig == nil || sig.SigLifetimeSecs == nil || *sig.SigLifetimeSecs == 0 {
		return false
	}
	return sig.CreationTime.Add(time.Duration(*sig.SigLifetimeSecs) * time.Second).Before(at)
}

// openPGPRevokedAt reads revocations as RFC 9580 does: a hard one — no
// reason, compromise, a reason it does not know — counts against
// every signature, a soft one — superseded, retired, an identity no
// longer valid — from its own time on.
func openPGPRevokedAt(revocations []*packet.Signature, at time.Time) bool {
	for _, r := range revocations {
		if r.RevocationReason == nil {
			return true
		}
		switch *r.RevocationReason {
		case packet.KeySuperseded, packet.KeyRetired, packet.UserIDNotValid:
			if !r.CreationTime.After(at) {
				return true
			}
		default:
			return true
		}
	}
	return false
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
