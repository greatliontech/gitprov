package sigstoretest

import (
	"bytes"
	"crypto"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/greatliontech/gitprov"
	gitsign "github.com/sigstore/gitsign/pkg/git"
)

// OpenPGPKey is a key that signs git objects as gpg does for git: a
// binary-mode detached signature, armored under the label git stores
// it by. Its armor is written by the OpenPGP library, its markers no
// verifier's; the options let a test shape what the verifier judges.
type OpenPGPKey struct {
	entity *openpgp.Entity
}

// OpenPGPKeyOptions shape a key away from gpg's quick-generated
// signing key; each zero value is that key's.
type OpenPGPKeyOptions struct {
	Created  time.Time     // the key's creation time; zero is now
	Lifetime time.Duration // the key's validity from its creation; zero is no expiry
}

// NewOpenPGPKey makes an EdDSA key with one identity: the primary key
// signs, as gpg's quick-generated signing keys do.
func NewOpenPGPKey(t testing.TB) *OpenPGPKey {
	t.Helper()
	return NewOpenPGPKeyWith(t, OpenPGPKeyOptions{})
}

// NewOpenPGPKeyWith makes the key the options shape.
func NewOpenPGPKeyWith(t testing.TB, o OpenPGPKeyOptions) *OpenPGPKey {
	t.Helper()
	config := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: uint32(o.Lifetime / time.Second)}
	if !o.Created.IsZero() {
		config.Time = func() time.Time { return o.Created }
	}
	e, err := openpgp.NewEntity("sigstoretest", "", "key@sigstoretest.invalid", config)
	if err != nil {
		t.Fatal(err)
	}
	return &OpenPGPKey{entity: e}
}

// Revoke adds a revocation of the key made at the time, the key
// superseded — a revocation that counts from its time; a public block
// exported after carries it.
func (k *OpenPGPKey) Revoke(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	return k.revoke(t, at, packet.KeySuperseded)
}

// RevokeCompromised adds a revocation of the key for compromise made
// at the time — a revocation that counts against every signature,
// whenever made.
func (k *OpenPGPKey) RevokeCompromised(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	return k.revoke(t, at, packet.KeyCompromised)
}

// RevokeNoReason adds a revocation stating no reason — a hard one
// under RFC 9580, gpg's default.
func (k *OpenPGPKey) RevokeNoReason(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	return k.revoke(t, at, packet.NoReason)
}

// RevokeRetired adds a revocation for retirement — a soft one,
// counting from its time.
func (k *OpenPGPKey) RevokeRetired(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	return k.revoke(t, at, packet.KeyRetired)
}

// ReSign adds a fresh self-signature of the key's identity made at
// the time, as gpg does when an owner extends a key's expiry or
// changes its preferences; a block exported after carries it, and
// readers take the newest self-signature as the key's.
func (k *OpenPGPKey) ReSign(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	return k.reSign(t, at, 0)
}

// ReSignWithoutFlags adds a fresh self-signature of the key's
// identity stating no key flags, as keys from before key flags do.
func (k *OpenPGPKey) ReSignWithoutFlags(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	e := k.entity
	for name, id := range e.Identities {
		sig := k.signatureAt(packet.SigTypePositiveCert, at)
		sig.IsPrimaryId = id.SelfSignature.IsPrimaryId
		if err := sig.SignUserId(name, e.PrimaryKey, e.PrivateKey, k.configAt(at)); err != nil {
			t.Fatal(err)
		}
		id.Signatures = append(id.Signatures, sig)
		id.SelfSignature = sig
	}
	return k
}

// ReSignWithCriticalNotation adds a fresh self-signature of the key's
// identity made at the time carrying a critical notation no verifier
// knows: the key's own statement a verifier cannot honor.
func (k *OpenPGPKey) ReSignWithCriticalNotation(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	e := k.entity
	for name, id := range e.Identities {
		sig := k.signatureAt(packet.SigTypePositiveCert, at)
		sig.KeyLifetimeSecs = id.SelfSignature.KeyLifetimeSecs
		sig.FlagsValid = id.SelfSignature.FlagsValid
		sig.FlagSign = id.SelfSignature.FlagSign
		sig.FlagCertify = id.SelfSignature.FlagCertify
		sig.IsPrimaryId = id.SelfSignature.IsPrimaryId
		sig.Notations = []*packet.Notation{{Name: "crit@sigstoretest.invalid", Value: []byte("1"), IsCritical: true, IsHumanReadable: true}}
		if err := sig.SignUserId(name, e.PrimaryKey, e.PrivateKey, k.configAt(at)); err != nil {
			t.Fatal(err)
		}
		id.Signatures = append(id.Signatures, sig)
		id.SelfSignature = sig
	}
	return k
}

// ReSignForA adds a fresh self-signature of the key's identity made
// at the time and valid for the duration — a self-signature with a
// lifetime of its own.
func (k *OpenPGPKey) ReSignForA(t testing.TB, at time.Time, lifetime time.Duration) *OpenPGPKey {
	t.Helper()
	return k.reSign(t, at, lifetime)
}

func (k *OpenPGPKey) reSign(t testing.TB, at time.Time, lifetime time.Duration) *OpenPGPKey {
	t.Helper()
	e := k.entity
	for name, id := range e.Identities {
		sig := k.signatureAt(packet.SigTypePositiveCert, at)
		sig.KeyLifetimeSecs = id.SelfSignature.KeyLifetimeSecs
		sig.FlagsValid = id.SelfSignature.FlagsValid
		sig.FlagSign = id.SelfSignature.FlagSign
		sig.FlagCertify = id.SelfSignature.FlagCertify
		sig.IsPrimaryId = id.SelfSignature.IsPrimaryId
		if lifetime != 0 {
			secs := uint32(lifetime / time.Second)
			sig.SigLifetimeSecs = &secs
		}
		if err := sig.SignUserId(name, e.PrimaryKey, e.PrivateKey, k.configAt(at)); err != nil {
			t.Fatal(err)
		}
		id.Signatures = append(id.Signatures, sig)
		id.SelfSignature = sig
	}
	return k
}

func (k *OpenPGPKey) revoke(t testing.TB, at time.Time, reason packet.ReasonForRevocation) *OpenPGPKey {
	t.Helper()
	if err := k.entity.RevokeKey(reason, "sigstoretest", &packet.Config{Time: func() time.Time { return at }}); err != nil {
		t.Fatal(err)
	}
	return k
}

// SecretSubkeysUnderPublicLabel is a block labelled public holding
// the primary key's public half with its identity and, for each
// subkey, the private half with its binding signature.
func (k *OpenPGPKey) SecretSubkeysUnderPublicLabel(t testing.TB) string {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := k.entity
	if err := e.PrimaryKey.Serialize(w); err != nil {
		t.Fatal(err)
	}
	for _, id := range e.Identities {
		if err := id.UserId.Serialize(w); err != nil {
			t.Fatal(err)
		}
		if err := id.SelfSignature.Serialize(w); err != nil {
			t.Fatal(err)
		}
	}
	for _, sk := range e.Subkeys {
		if err := sk.PrivateKey.Serialize(w); err != nil {
			t.Fatal(err)
		}
		if err := sk.Sig.Serialize(w); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String() + "\n"
}

// BarePrimaryThen is a block labelled public holding this key's
// primary key packet alone — no identity, which no reader reads as a
// key — followed by the other key whole.
func (k *OpenPGPKey) BarePrimaryThen(t testing.TB, other *OpenPGPKey) string {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.entity.PrimaryKey.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := other.entity.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String() + "\n"
}

// WithUnreadableBinding is the key's public block with its signing
// subkey's binding signature under an algorithm no library knows: the
// key's own statement in a form the reader cannot carry.
func (k *OpenPGPKey) WithUnreadableBinding(t testing.TB) string {
	t.Helper()
	e := k.entity
	sk := signingSubkey(e)
	if sk == nil {
		t.Fatal("sigstoretest: the key has no signing subkey")
	}
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.PrimaryKey.Serialize(w); err != nil {
		t.Fatal(err)
	}
	for _, id := range e.Identities {
		if err := id.UserId.Serialize(w); err != nil {
			t.Fatal(err)
		}
		if err := id.SelfSignature.Serialize(w); err != nil {
			t.Fatal(err)
		}
	}
	if err := sk.PublicKey.Serialize(w); err != nil {
		t.Fatal(err)
	}
	var sb bytes.Buffer
	if err := sk.Sig.Serialize(&sb); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(patchedAlgorithm(t, sb.Bytes())); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String() + "\n"
}

// ThenBarePrimary is a block labelled public holding this key whole
// followed by the other key's primary key packet alone.
func (k *OpenPGPKey) ThenBarePrimary(t testing.TB, other *OpenPGPKey) string {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.entity.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := other.entity.PrimaryKey.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String() + "\n"
}

// SubkeyFirst is a block labelled public opening with the key's first
// subkey packet, the primary key after it.
func (k *OpenPGPKey) SubkeyFirst(t testing.TB) string {
	t.Helper()
	if len(k.entity.Subkeys) == 0 {
		t.Fatal("sigstoretest: the key has no subkey")
	}
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.entity.Subkeys[0].PublicKey.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := k.entity.Serialize(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String() + "\n"
}

// WithBadChecksum is the armored text with its checksum line — the
// "=" and four base64 digits before the footer — replaced by one
// that is no checksum of the body.
func WithBadChecksum(t testing.TB, armored string) string {
	t.Helper()
	i := strings.LastIndex(armored, "\n=")
	if i < 0 || len(armored) < i+6 {
		t.Fatal("sigstoretest: the armor carries no checksum line")
	}
	return armored[:i+2] + "AAAA" + armored[i+6:]
}

// WithSigningSubkey adds a signing subkey to the key; signatures
// made after are the subkey's, as gpg signs with a signing subkey
// when a key has one.
func (k *OpenPGPKey) WithSigningSubkey(t testing.TB) *OpenPGPKey {
	t.Helper()
	return k.WithSigningSubkeyWith(t, SubkeyOptions{})
}

// SubkeyOptions shape a signing subkey; each zero value is gpg's.
type SubkeyOptions struct {
	Created         time.Time     // the subkey's creation time; zero is now
	Lifetime        time.Duration // the subkey's validity from its creation; zero is no expiry
	BindingLifetime time.Duration // the binding signature's own validity; zero is no expiry
}

// WithSigningSubkeyWith adds the signing subkey the options shape.
func (k *OpenPGPKey) WithSigningSubkeyWith(t testing.TB, o SubkeyOptions) *OpenPGPKey {
	t.Helper()
	config := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: uint32(o.Lifetime / time.Second), SigLifetimeSecs: uint32(o.BindingLifetime / time.Second)}
	if !o.Created.IsZero() {
		config.Time = func() time.Time { return o.Created }
	}
	if err := k.entity.AddSigningSubkey(config); err != nil {
		t.Fatal(err)
	}
	return k
}

// RevokeSubkey adds a revocation of the key's first subkey made at
// the time, the subkey superseded — a soft revocation.
func (k *OpenPGPKey) RevokeSubkey(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	return k.revokeSubkey(t, at, packet.KeySuperseded)
}

// RevokeSubkeyCompromised adds a revocation of the key's first subkey
// for compromise — a hard one.
func (k *OpenPGPKey) RevokeSubkeyCompromised(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	return k.revokeSubkey(t, at, packet.KeyCompromised)
}

func (k *OpenPGPKey) revokeSubkey(t testing.TB, at time.Time, reason packet.ReasonForRevocation) *OpenPGPKey {
	t.Helper()
	sk := signingSubkey(k.entity)
	if sk == nil {
		t.Fatal("sigstoretest: the key has no signing subkey")
	}
	if err := k.entity.RevokeSubkey(sk, reason, "sigstoretest", &packet.Config{Time: func() time.Time { return at }}); err != nil {
		t.Fatal(err)
	}
	return k
}

// signingSubkey is the entity's first subkey bound for signing, or
// nil; the library makes an encryption subkey with every key, which
// is not it.
func signingSubkey(e *openpgp.Entity) *openpgp.Subkey {
	for i := range e.Subkeys {
		if e.Subkeys[i].Sig != nil && e.Subkeys[i].Sig.FlagsValid && e.Subkeys[i].Sig.FlagSign {
			return &e.Subkeys[i]
		}
	}
	return nil
}

// RevokeIdentity adds a revocation of the key's identity made at the
// time, stating no reason — a hard one.
func (k *OpenPGPKey) RevokeIdentity(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	e := k.entity
	for name, id := range e.Identities {
		sig := k.signatureAt(packet.SigTypeCertificationRevocation, at)
		if err := sig.SignUserId(name, e.PrimaryKey, e.PrivateKey, k.configAt(at)); err != nil {
			t.Fatal(err)
		}
		id.Signatures = append(id.Signatures, sig)
	}
	return k
}

// RevokeWithoutReason adds a revocation of the key that carries no
// reason subpacket at all — which RFC 9580 reads as a hard one.
func (k *OpenPGPKey) RevokeWithoutReason(t testing.TB, at time.Time) *OpenPGPKey {
	t.Helper()
	e := k.entity
	sig := k.signatureAt(packet.SigTypeKeyRevocation, at)
	if err := sig.RevokeKey(e.PrimaryKey, e.PrivateKey, k.configAt(at)); err != nil {
		t.Fatal(err)
	}
	e.Revocations = append(e.Revocations, sig)
	return k
}

// CertifiedByUnknownAlgorithm is the key's public block carrying a
// certification of its identity by the other key, its algorithm byte
// set to one no library knows: a third party's statement in a form
// the reader cannot carry.
func (k *OpenPGPKey) CertifiedByUnknownAlgorithm(t testing.TB, other *OpenPGPKey) string {
	t.Helper()
	return k.certifiedBy(t, other, patchedAlgorithm)
}

// CertifiedByUnknownVersion is the key's public block carrying a
// certification of its identity by the other key, its version byte
// set to one the reader does not carry.
func (k *OpenPGPKey) CertifiedByUnknownVersion(t testing.TB, other *OpenPGPKey) string {
	t.Helper()
	return k.certifiedBy(t, other, patchedVersion)
}

func (k *OpenPGPKey) certifiedBy(t testing.TB, other *OpenPGPKey, patch func(testing.TB, []byte) []byte) string {
	t.Helper()
	e := k.entity
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.PrimaryKey.Serialize(w); err != nil {
		t.Fatal(err)
	}
	for name, id := range e.Identities {
		if err := id.UserId.Serialize(w); err != nil {
			t.Fatal(err)
		}
		if err := id.SelfSignature.Serialize(w); err != nil {
			t.Fatal(err)
		}
		cert := other.signatureAt(packet.SigTypeGenericCert, time.Now())
		if err := cert.SignUserId(name, e.PrimaryKey, other.entity.PrivateKey, other.configAt(time.Now())); err != nil {
			t.Fatal(err)
		}
		var cb bytes.Buffer
		if err := cert.Serialize(&cb); err != nil {
			t.Fatal(err)
		}
		raw := patch(t, cb.Bytes())
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, sk := range e.Subkeys {
		if err := sk.PublicKey.Serialize(w); err != nil {
			t.Fatal(err)
		}
		if err := sk.Sig.Serialize(w); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String() + "\n"
}

// patchedAlgorithm is the serialized signature packet with its
// public-key algorithm byte set to one no library knows: a
// new-format header — one length byte under 192 bytes of body, two
// under 8384, which the helper asserts — precedes the body, whose
// third byte is the algorithm.
func patchedAlgorithm(t testing.TB, raw []byte) []byte {
	t.Helper()
	if raw[0] != 0xC2 {
		t.Fatalf("sigstoretest: the packet's header byte is %x, not a new-format signature's", raw[0])
	}
	body := 2
	switch {
	case raw[1] < 192:
	case raw[1] < 224:
		body = 3
	default:
		t.Fatalf("sigstoretest: the packet's length byte %x names a length form the helper does not read", raw[1])
	}
	out := append([]byte(nil), raw...)
	out[body+2] = 100
	return out
}

// patchedVersion is the serialized signature packet with its version
// byte — the body's first — set to 5, which the reader does not
// carry.
func patchedVersion(t testing.TB, raw []byte) []byte {
	t.Helper()
	body := 2
	if raw[1] >= 192 {
		body = 3
	}
	out := append([]byte(nil), raw...)
	out[body] = 5
	return out
}

// patchedType is the serialized signature packet with its type byte
// — the body's second — set to the type.
func patchedType(t testing.TB, raw []byte, sigType packet.SignatureType) []byte {
	t.Helper()
	body := 2
	if raw[1] >= 192 {
		body = 3
	}
	out := append([]byte(nil), raw...)
	out[body+1] = byte(sigType)
	return out
}

// signatureAt is a signature packet of the type by the primary key,
// made at the time, its subpackets left to the signing call.
func (k *OpenPGPKey) signatureAt(sigType packet.SignatureType, at time.Time) *packet.Signature {
	pk := k.entity.PrimaryKey
	return &packet.Signature{
		Version:           pk.Version,
		SigType:           sigType,
		PubKeyAlgo:        pk.PubKeyAlgo,
		Hash:              crypto.SHA256,
		CreationTime:      at,
		IssuerKeyId:       &pk.KeyId,
		IssuerFingerprint: pk.Fingerprint,
	}
}

func (k *OpenPGPKey) configAt(at time.Time) *packet.Config {
	return &packet.Config{Time: func() time.Time { return at }}
}

// Public is the key's armored public key block, the spelling a caller
// pins: the primary key, its identity and subkeys with their
// signatures, and no private material.
func (k *OpenPGPKey) Public(t testing.TB) string {
	t.Helper()
	return PublicKeyBlock(t, k)
}

// PublicKeyBlock is one armored block holding the public halves of
// the keys, as gpg exports several keys at once.
func PublicKeyBlock(t testing.TB, keys ...*OpenPGPKey) string {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if err := k.entity.Serialize(w); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String() + "\n"
}

// Private is the key's armored private key block, which no caller
// may pin.
func (k *OpenPGPKey) Private(t testing.TB) string {
	t.Helper()
	return k.privateUnder(t, openpgp.PrivateKeyType)
}

// PrivateUnderPublicLabel is the key's private material armored under
// a public key block's label: what the label says and what the
// packets hold disagree.
func (k *OpenPGPKey) PrivateUnderPublicLabel(t testing.TB) string {
	t.Helper()
	return k.privateUnder(t, openpgp.PublicKeyType)
}

func (k *OpenPGPKey) privateUnder(t testing.TB, label string) string {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, label, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.entity.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String() + "\n"
}

// Fingerprint is the primary key's fingerprint as gpg spells it in
// full: uppercase hex.
func (k *OpenPGPKey) Fingerprint() string {
	return strings.ToUpper(strings.TrimSpace(fingerprintHex(k.entity.PrimaryKey.Fingerprint)))
}

func fingerprintHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// OpenPGPOptions shape a signature away from what gpg writes for git;
// each zero value is gpg's own.
type OpenPGPOptions struct {
	Hash                         crypto.Hash       // the signature's hash; 0 is the library's default
	Text                         bool              // a text-mode signature, over the canonical text form
	Headers                      map[string]string // armor header lines
	SignedAt                     time.Time         // the signature's creation time; zero is now
	SigLifetime                  time.Duration     // the signature's validity from its creation; zero is no expiry
	Trailing                     []byte            // bytes appended to the body after the signature packet
	Second                       *OpenPGPKey       // a second key whose signature packet follows the first in the body
	Forced                       bool              // the primary key signs whatever its validity at SignedAt, as no honest signer does
	ForcedSubkey                 bool              // the first subkey signs so
	Critical                     bool              // the signature carries a critical notation no verifier knows
	UnreadableBefore             bool              // a copy of the signature under an algorithm no library knows precedes it in the body
	UnreadableAfter              bool              // such a copy follows it
	UnreadableCertificationAfter bool              // such a copy, its type a certification\'s, follows it
}

// SignatureOver is the armored detached signature over the payload
// bytes, shaped by the options.
func (k *OpenPGPKey) SignatureOver(t testing.TB, payload []byte, o OpenPGPOptions) []byte {
	t.Helper()
	config := &packet.Config{DefaultHash: o.Hash, SigLifetimeSecs: uint32(o.SigLifetime / time.Second)}
	if !o.SignedAt.IsZero() {
		config.Time = func() time.Time { return o.SignedAt }
	}
	if o.Critical {
		config.SignatureNotations = []*packet.Notation{{Name: "crit@sigstoretest.invalid", Value: []byte("1"), IsCritical: true, IsHumanReadable: true}}
	}
	var b bytes.Buffer
	w, err := armor.Encode(&b, openpgp.SignatureType, o.Headers)
	if err != nil {
		t.Fatal(err)
	}
	sign := openpgp.DetachSign
	if o.Text {
		sign = openpgp.DetachSignText
	}
	if o.Forced {
		sign = forcedDetachSign(false)
	}
	if o.ForcedSubkey {
		sign = forcedDetachSign(true)
	}
	var packetBytes bytes.Buffer
	if err := sign(&packetBytes, k.entity, bytes.NewReader(payload), config); err != nil {
		t.Fatalf("sigstoretest: sign: %v", err)
	}
	if o.UnreadableBefore {
		w.Write(patchedAlgorithm(t, packetBytes.Bytes()))
	}
	w.Write(packetBytes.Bytes())
	if o.UnreadableAfter {
		w.Write(patchedAlgorithm(t, packetBytes.Bytes()))
	}
	if o.UnreadableCertificationAfter {
		w.Write(patchedType(t, patchedAlgorithm(t, packetBytes.Bytes()), packet.SigTypeGenericCert))
	}
	if o.Second != nil {
		if err := sign(w, o.Second.entity, bytes.NewReader(payload), config); err != nil {
			t.Fatalf("sigstoretest: sign: %v", err)
		}
	}
	if _, err := w.Write(o.Trailing); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// The library's armor ends at its footer line; gpg's, and git's
	// object, end with a newline.
	return append(b.Bytes(), '\n')
}

// SignedTag is the raw tag object: the payload with the signature
// over it appended in-body, as git writes a gpg-signed tag.
func (k *OpenPGPKey) SignedTag(t testing.TB, payload []byte, o OpenPGPOptions) []byte {
	t.Helper()
	raw, err := gitsign.JoinTag(&gitsign.TagSig{Payload: payload, InBody: k.SignatureOver(t, payload, o)})
	if err != nil {
		t.Fatalf("sigstoretest: join the tag: %v", err)
	}
	return raw
}

// SignedCommit is the raw commit object: the payload with the
// signature over it in the header of the form.
func (k *OpenPGPKey) SignedCommit(t testing.TB, payload []byte, format gitprov.ObjectFormat, o OpenPGPOptions) []byte {
	t.Helper()
	cs := &gitsign.CommitSig{Payload: payload}
	if format == gitprov.SHA256 {
		cs.GpgsigSha256 = k.SignatureOver(t, payload, o)
	} else {
		cs.Gpgsig = k.SignatureOver(t, payload, o)
	}
	raw, err := gitsign.JoinCommit(cs)
	if err != nil {
		t.Fatalf("sigstoretest: join the commit: %v", err)
	}
	return raw
}

// forcedDetachSign signs with the entity's primary key — or its first
// subkey — at the config's time, judging nothing of the key's validity
// then: what an attacker holding the key, or a broken signer, could
// write.
func forcedDetachSign(subkey bool) func(w io.Writer, e *openpgp.Entity, message io.Reader, config *packet.Config) error {
	return func(w io.Writer, e *openpgp.Entity, message io.Reader, config *packet.Config) error {
		pk, priv := e.PrimaryKey, e.PrivateKey
		if subkey {
			sk := signingSubkey(e)
			if sk == nil {
				return errors.New("sigstoretest: the key has no signing subkey")
			}
			pk, priv = sk.PublicKey, sk.PrivateKey
		}
		sig := &packet.Signature{
			Version:           pk.Version,
			SigType:           packet.SigTypeBinary,
			PubKeyAlgo:        pk.PubKeyAlgo,
			Hash:              crypto.SHA256,
			CreationTime:      config.Now(),
			IssuerKeyId:       &pk.KeyId,
			IssuerFingerprint: pk.Fingerprint,
			Notations:         config.Notations(),
		}
		h, err := sig.PrepareSign(config)
		if err != nil {
			return err
		}
		if _, err := io.Copy(h, message); err != nil {
			return err
		}
		if err := sig.Sign(h, priv, config); err != nil {
			return err
		}
		return sig.Serialize(w)
	}
}
