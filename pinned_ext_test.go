package gitprov_test

import (
	"bytes"
	"crypto/dsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/greatliontech/gitprov"
	"github.com/greatliontech/gitprov/sigstoretest"
	"golang.org/x/crypto/ssh"
	"pgregory.net/rapid"
)

// Every field of the envelope the verifier judges is judged
// (REQ-verify-pinned-key, REQ-verify-fail-closed): the namespace git
// signs in, the preamble, the version, the reserved field, the hash
// algorithm, the carried key naming a pinned one, the signature's
// form, bytes beside the envelope; and what verifies is the pinned
// key over the raw payload, in both object forms.
func TestVerifyPinnedSSHShapes(t *testing.T) {
	key := sigstoretest.NewSSHKey(t)
	other := sigstoretest.NewSSHKey(t)
	rsa := sigstoretest.NewSSHRSAKey(t)
	pinned := gitprov.PinnedSSH(t, key.Public())
	tagPayload := gitprov.MinimalTagPayload()
	commitPayload := gitprov.MinimalCommitPayload()

	t.Run("a tag verifies", func(t *testing.T) {
		vk, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: key.SignedTag(t, tagPayload, sigstoretest.SSHOptions{})}, pinned)
		if err != nil || vk.Fingerprint != key.Fingerprint() {
			t.Fatalf("VerifyPinned = %+v, %v; want %s", vk, err, key.Fingerprint())
		}
	})
	for _, format := range []gitprov.ObjectFormat{gitprov.SHA1, gitprov.SHA256} {
		t.Run("a commit verifies in the "+string(format)+" form", func(t *testing.T) {
			raw := key.SignedCommit(t, commitPayload, format, sigstoretest.SSHOptions{})
			if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Commit, Format: format, Raw: raw}, pinned); err != nil {
				t.Fatalf("VerifyPinned = %v, want nil", err)
			}
			otherForm := gitprov.SHA256
			if format == gitprov.SHA256 {
				otherForm = gitprov.SHA1
			}
			if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Commit, Format: otherForm, Raw: raw}, pinned); err == nil ||
				!strings.Contains(err.Error(), "not signed") {
				t.Fatalf("VerifyPinned(other form) = %v, want not-signed", err)
			}
		})
	}
	t.Run("sha256 as the envelope's hash verifies", func(t *testing.T) {
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: key.SignedTag(t, tagPayload, sigstoretest.SSHOptions{HashAlg: "sha256"})}, pinned); err != nil {
			t.Fatalf("VerifyPinned = %v, want nil", err)
		}
	})
	t.Run("the envelope's reserved value is ignored, the blob's empty", func(t *testing.T) {
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: key.SignedTag(t, tagPayload, sigstoretest.SSHOptions{Reserved: "x"})}, pinned); err != nil {
			t.Fatalf("VerifyPinned(reserved in the envelope) = %v, want nil", err)
		}
		// A blob signed with the value in it is one OpenSSH never signs
		// and its verifier, rebuilding the blob empty, refuses.
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: key.SignedTag(t, tagPayload, sigstoretest.SSHOptions{Reserved: "x", SignedReserved: "x"})}, pinned); err == nil ||
			!strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("VerifyPinned(reserved signed) = %v, want does-not-verify", err)
		}
	})
	t.Run("a FIDO key's signature verifies, its flags and counter after the blob", func(t *testing.T) {
		fido := sigstoretest.NewSSHFIDOKey(t)
		fpinned := gitprov.PinnedSSH(t, fido.Public())
		vk, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: fido.SignedTag(t, tagPayload, sigstoretest.SSHOptions{})}, fpinned)
		if err != nil || vk.Fingerprint != fido.Fingerprint() {
			t.Fatalf("VerifyPinned(fido) = %+v, %v; want %s", vk, err, fido.Fingerprint())
		}
		for _, tt := range []struct {
			name string
			o    sigstoretest.SSHOptions
			want string
		}{
			{"bytes after its flags and counter", sigstoretest.SSHOptions{SigTrailing: []byte("JUNK")}, "does not verify"},
			{"no user presence asserted", sigstoretest.SSHOptions{NoPresence: true}, "user presence"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: fido.SignedTag(t, tagPayload, tt.o)}, fpinned); err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("VerifyPinned = %v, want %q", err, tt.want)
				}
			})
		}
	})
	t.Run("an RSA key in the rsa-sha2-256 form verifies", func(t *testing.T) {
		raw := rsa.SignedTag(t, tagPayload, sigstoretest.SSHOptions{Algorithm: ssh.KeyAlgoRSASHA256})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: raw}, gitprov.PinnedSSH(t, rsa.Public())); err != nil {
			t.Fatalf("VerifyPinned = %v, want nil", err)
		}
	})
	for _, tt := range []struct {
		name string
		key  *sigstoretest.SSHKey
		keys []gitprov.PinnedKey
		o    sigstoretest.SSHOptions
		want string
	}{
		{"the file namespace", key, pinned, sigstoretest.SSHOptions{Namespace: "file"}, `namespace "file"`},
		{"an empty namespace", key, pinned, sigstoretest.SSHOptions{NoNamespace: true}, `namespace ""`},
		{"a NUL namespace", key, pinned, sigstoretest.SSHOptions{Namespace: "\x00"}, "namespace"},
		{"another preamble", key, pinned, sigstoretest.SSHOptions{Preamble: "SSHSIX"}, "preamble"},
		{"version 2", key, pinned, sigstoretest.SSHOptions{Version: 2}, "version 2"},
		{"an unnamed hash", key, pinned, sigstoretest.SSHOptions{HashAlg: "sha1"}, `hash algorithm "sha1"`},
		{"signed by an unpinned key", other, pinned, sigstoretest.SSHOptions{}, "unpinned key " + other.Fingerprint()},
		{"the pinned key carried, another key signing", other, pinned, sigstoretest.SSHOptions{Embed: key.PublicKey()}, "does not verify"},
		{"the ssh-rsa (SHA-1) form", rsa, gitprov.PinnedSSH(t, rsa.Public()), sigstoretest.SSHOptions{Algorithm: ssh.KeyAlgoRSA}, "ssh-rsa (SHA-1) form is refused"},
		{"bytes after the envelope", key, pinned, sigstoretest.SSHOptions{Trailing: []byte{0}}, "envelope"},
		{"bytes after the signature blob", key, pinned, sigstoretest.SSHOptions{SigTrailing: []byte("JUNKJUNK")}, "bytes after its blob"},
		{"header lines in the armor", key, pinned, sigstoretest.SSHOptions{Headers: map[string]string{"Foo": "bar"}}, "armor carries header lines"},
		{"the carried key that is no key", key, pinned, sigstoretest.SSHOptions{CarriedKey: []byte("junk")}, "signature's key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.key.SignedTag(t, tagPayload, tt.o)
			if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: raw}, tt.keys); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("VerifyPinned = %v, want %q", err, tt.want)
			}
		})
	}
	t.Run("a body that is no envelope", func(t *testing.T) {
		raw := gitprov.CommitSignedWith(t, pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: []byte("opaque")}))
		if _, err := gitprov.VerifyPinned(raw, pinned); err == nil || !strings.Contains(err.Error(), "envelope") {
			t.Fatalf("VerifyPinned(opaque) = %v, want envelope error", err)
		}
	})
}

// The signature verifies the raw payload and nothing near it: any
// object whose payload differs from the signed one by one byte fails
// (REQ-verify-pinned-key, REQ-verify-raw-bytes).
func TestVerifyPinnedSSHProperty(t *testing.T) {
	key := sigstoretest.NewSSHKey(t)
	pinned := gitprov.PinnedSSH(t, key.Public())
	rapid.Check(t, func(rt *rapid.T) {
		var b bytes.Buffer
		b.WriteString("object " + rapid.StringMatching(`[0-9a-f]{40}`).Draw(rt, "object") + "\n")
		b.WriteString("type commit\ntag v" + rapid.StringMatching(`[0-9]{1,3}`).Draw(rt, "v") + "\n")
		b.WriteString("tagger T <t@x.invalid> 1700000000 +0000\n\n")
		for i, n := 0, rapid.IntRange(1, 3).Draw(rt, "lines"); i < n; i++ {
			b.WriteString(rapid.StringMatching(`[A-Za-z0-9 ]{0,40}`).Draw(rt, "msg") + "\n")
		}
		payload := b.Bytes()
		raw := key.SignedTag(t, payload, sigstoretest.SSHOptions{})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: raw}, pinned); err != nil {
			t.Fatalf("VerifyPinned = %v, want nil\n%s", err, raw)
		}
		// One byte of the message flipped: a printable byte to another,
		// so the object stays a tag the split reads.
		i := bytes.Index(payload, []byte("\n\n")) + 2
		if i >= len(payload)-1 {
			return
		}
		at := rapid.IntRange(i, len(payload)-2).Draw(rt, "at")
		if payload[at] == '\n' {
			return
		}
		flipped := append([]byte(nil), raw...)
		flipped[at] = 'A' + byte((int(payload[at])-'A'+1)%26)
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: flipped}, pinned); err == nil ||
			!strings.Contains(err.Error(), "does not verify") {
			t.Fatalf("VerifyPinned(flipped) = %v, want does-not-verify", err)
		}
	})
}

// A pinned gitprov.SSH key is one OpenSSH public key line (REQ-verify-pinned-key).
func TestParsePinnedKeySSH(t *testing.T) {
	key := sigstoretest.NewSSHKey(t)
	rsa := sigstoretest.NewSSHRSAKey(t)
	for _, tt := range []struct {
		name string
		line string
		want string
	}{
		{"a key line", key.Public(), ""},
		{"a key line with a comment", key.Public() + " someone@host", ""},
		{"a key line with a trailing newline", key.Public() + "\n", ""},
		{"an RSA key line", rsa.Public(), ""},
		{"an authorized_keys line with options", `no-pty ` + key.Public(), "options"},
		{"two lines", key.Public() + "\n" + rsa.Public() + "\n", "more than one line"},
		{"a line the reader would pass over before the key", "garbage line here\n" + key.Public(), "more than one line"},
		{"a comment line before the key", "# c\n\n" + key.Public(), "more than one line"},
		{"a corrupt key line before the key", "ssh-ed25519 notbase64\n" + key.Public(), "more than one line"},
		{"a comment line", "# " + key.Public(), "not a public key line"},
		{"leading whitespace", "  " + key.Public(), "not a public key line"},
		{"a leading vertical tab", "\v" + key.Public(), "not a public key line"},
		{"text", "not a key", "SSH public key"},
		{"empty", "", "not a public key line"},
		{"a certificate", certLine(t, key), "certificate"},
		{"a DSA key", dsaLine(t), "DSA"},
		{"an RSA key under OpenSSH's minimum", smallRSALine(t), "under OpenSSH's minimum"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			k, err := gitprov.ParsePinnedKey(gitprov.SSH, tt.line)
			if tt.want != "" {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("ParsePinnedKey = %v, want %q", err, tt.want)
				}
				return
			}
			if err != nil || k.Kind() != gitprov.SSH || !strings.HasPrefix(k.Fingerprint(), "SHA256:") {
				t.Fatalf("ParsePinnedKey = %+v, %v", k, err)
			}
		})
	}
	t.Run("a sigstore kind pins no key", func(t *testing.T) {
		if _, err := gitprov.ParsePinnedKey(gitprov.Sigstore, key.Public()); err == nil || !strings.Contains(err.Error(), "no pinned key kind") {
			t.Fatalf("ParsePinnedKey(sigstore) = %v", err)
		}
	})
	t.Run("an OpenPGP key has no parser yet", func(t *testing.T) {
		if _, err := gitprov.ParsePinnedKey(gitprov.OpenPGP, "-----BEGIN PGP PUBLIC KEY BLOCK-----"); err == nil || !strings.Contains(err.Error(), "no verifier for a openpgp key") {
			t.Fatalf("ParsePinnedKey(openpgp) = %v", err)
		}
	})
}

// certLine is an OpenSSH certificate for the key, signed by a fresh
// authority, in its one-line form.
func certLine(t *testing.T, key *sigstoretest.SSHKey) string {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: key.PublicKey(), CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

// dsaLine is a DSA public key in its one-line form.
func dsaLine(t *testing.T) string {
	t.Helper()
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	priv := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(priv, rand.Reader); err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// smallRSALine is a 768-bit RSA public key in its one-line form: a
// modulus of that size with the usual exponent, no private half
// needed to spell it.
func smallRSALine(t *testing.T) string {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 768))
	if err != nil {
		t.Fatal(err)
	}
	n.SetBit(n, 767, 1)
	n.SetBit(n, 0, 1)
	pk, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}
