package sigstoretest

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/greatliontech/gitprov"
	gitsign "github.com/sigstore/gitsign/pkg/git"
	"golang.org/x/crypto/ssh"
)

// SSHKey is a key pair that signs git objects as OpenSSH does for git:
// the SSH signature envelope (PROTOCOL.sshsig) in the git namespace,
// armored under the label git stores it by. Its markers are spelled
// here on their own, so a test of the verifier's checks shares none
// of its constants; the options let a test shape every field the
// verifier judges.
type SSHKey struct {
	signer ssh.AlgorithmSigner
	pub    ssh.PublicKey
	fido   *fidoKey // set for a FIDO key, which signs on its own
}

// fidoKey is an sk-ssh-ed25519 key: an Ed25519 key bound to an
// application, whose signature covers the application's hash, the
// authenticator's flags and counter, and the message hash.
type fidoKey struct {
	priv        ed25519.PrivateKey
	application string
}

// NewSSHKey makes an Ed25519 key pair.
func NewSSHKey(t testing.TB) *SSHKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sshKeyFrom(t, priv)
}

// NewSSHRSAKey makes a 2048-bit RSA key pair, which signs in the
// rsa-sha2-512 form as ssh-keygen does unless an option says
// otherwise.
func NewSSHRSAKey(t testing.TB) *SSHKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return sshKeyFrom(t, priv)
}

// NewSSHFIDOKey makes an sk-ssh-ed25519 key pair bound to the ssh:
// application, signing as an authenticator does: flags and counter
// after the signature blob.
func NewSSHFIDOKey(t testing.TB) *SSHKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const application = "ssh:"
	wire := ssh.Marshal(struct {
		Type        string
		Key         string
		Application string
	}{"sk-ssh-ed25519@openssh.com", string(pub), application})
	pk, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return &SSHKey{pub: pk, fido: &fidoKey{priv: priv, application: application}}
}

func sshKeyFrom(t testing.TB, priv crypto.PrivateKey) *SSHKey {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	as, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatalf("sigstoretest: %T is no algorithm signer", signer)
	}
	return &SSHKey{signer: as, pub: signer.PublicKey()}
}

// Public is the key's one-line OpenSSH public key form, the spelling
// a caller pins.
func (k *SSHKey) Public() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.pub)))
}

// PublicKey is the key's public half.
func (k *SSHKey) PublicKey() ssh.PublicKey { return k.pub }

// Fingerprint is the key's SHA-256 fingerprint as OpenSSH spells it.
func (k *SSHKey) Fingerprint() string { return ssh.FingerprintSHA256(k.pub) }

// SSHOptions shape a signature away from what OpenSSH writes for git;
// each zero value is OpenSSH's own.
type SSHOptions struct {
	Namespace      string            // the namespace signed in; "" is git's
	NoNamespace    bool              // an empty namespace, which "" cannot spell
	HashAlg        string            // the hash named in the envelope; "" is sha512
	Reserved       string            // the envelope's reserved field; "" as OpenSSH writes it, and the blob carries it empty whatever it is
	SignedReserved string            // the blob's reserved field, which OpenSSH signs empty; set, the signature is over a blob OpenSSH never signs
	Version        uint32            // the envelope version; 0 is 1
	Preamble       string            // the envelope preamble; "" is SSHSIG
	Algorithm      string            // the signing algorithm; "" is the key's default (rsa-sha2-512 for RSA)
	Embed          ssh.PublicKey     // the key the envelope carries; nil is the signer's
	CarriedKey     []byte            // the raw bytes carried as the key, whatever they are; nil is Embed's wire form, and set it takes precedence over Embed
	Trailing       []byte            // bytes appended to the envelope
	SigTrailing    []byte            // bytes appended to the signature blob within the envelope, after a FIDO key's flags and counter
	Headers        map[string]string // header lines written into the armor
	NoPresence     bool              // a FIDO key's flags without the user-presence bit
}

// SignatureOver is the armored SSH signature over the payload bytes,
// shaped by the options.
func (k *SSHKey) SignatureOver(t testing.TB, payload []byte, o SSHOptions) []byte {
	t.Helper()
	namespace, hashAlg, preamble := o.Namespace, o.HashAlg, o.Preamble
	if namespace == "" && !o.NoNamespace {
		namespace = "git"
	}
	if hashAlg == "" {
		hashAlg = "sha512"
	}
	if preamble == "" {
		preamble = "SSHSIG"
	}
	version := o.Version
	if version == 0 {
		version = 1
	}
	var sum []byte
	switch hashAlg {
	case "sha512":
		h := sha512.Sum512(payload)
		sum = h[:]
	case "sha256":
		h := sha256.Sum256(payload)
		sum = h[:]
	default:
		// An algorithm the protocol does not name: the blob carries
		// the sha512 hash under the name, which the verifier must
		// refuse by name before hashing.
		h := sha512.Sum512(payload)
		sum = h[:]
	}
	blob := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      string
	}{namespace, o.SignedReserved, hashAlg, string(sum)})...)
	var sig *ssh.Signature
	if k.fido != nil {
		sig = k.fido.sign(blob, !o.NoPresence)
	} else {
		algorithm := o.Algorithm
		if algorithm == "" && k.pub.Type() == ssh.KeyAlgoRSA {
			algorithm = ssh.KeyAlgoRSASHA512
		}
		var err error
		if sig, err = k.signer.SignWithAlgorithm(rand.Reader, blob, algorithm); err != nil {
			t.Fatalf("sigstoretest: sign: %v", err)
		}
	}
	carried := o.CarriedKey
	if carried == nil {
		embed := o.Embed
		if embed == nil {
			embed = k.pub
		}
		carried = embed.Marshal()
	}
	var pre [6]byte
	copy(pre[:], preamble)
	sigBytes := append(ssh.Marshal(sig), o.SigTrailing...)
	env := ssh.Marshal(struct {
		Preamble  [6]byte
		Version   uint32
		PublicKey string
		Namespace string
		Reserved  string
		HashAlg   string
		Signature string
	}{pre, version, string(carried), namespace, o.Reserved, hashAlg, string(sigBytes)})
	env = append(env, o.Trailing...)
	return pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Headers: o.Headers, Bytes: env})
}

// SignedTag is the raw tag object: the payload with the signature
// over it appended in-body, as git writes an SSH-signed tag.
func (k *SSHKey) SignedTag(t testing.TB, payload []byte, o SSHOptions) []byte {
	t.Helper()
	raw, err := gitsign.JoinTag(&gitsign.TagSig{Payload: payload, InBody: k.SignatureOver(t, payload, o)})
	if err != nil {
		t.Fatalf("sigstoretest: join the tag: %v", err)
	}
	return raw
}

// SignedCommit is the raw commit object: the payload with the
// signature over it in the header of the form — gpgsig for the SHA-1
// form, gpgsig-sha256 for the SHA-256 one.
func (k *SSHKey) SignedCommit(t testing.TB, payload []byte, format gitprov.ObjectFormat, o SSHOptions) []byte {
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

// sign is the authenticator's signature over the blob: Ed25519 over
// the application's hash, the flags, a counter and the blob's hash,
// the flags and counter carried after the signature.
func (f *fidoKey) sign(blob []byte, presence bool) *ssh.Signature {
	app := sha256.Sum256([]byte(f.application))
	data := sha256.Sum256(blob)
	var flags byte
	if presence {
		flags = 0x01
	}
	const counter uint32 = 7
	signed := append(append(append(append([]byte(nil), app[:]...), flags), byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter)), data[:]...)
	return &ssh.Signature{
		Format: "sk-ssh-ed25519@openssh.com",
		Blob:   ed25519.Sign(f.priv, signed),
		Rest:   []byte{flags, byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)},
	}
}
