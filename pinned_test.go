package gitprov

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

const (
	sshFixtureFP    = "SHA256:cuQ/ZG8mqAef7X0GZ19RH5baTiwTVg76NePyXAKPBfM"
	sshFixtureRSAFP = "SHA256:qJf90eocttnD82cEmd3HjozFS3VFv2VfFEZPKsGOxRc"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The real objects git wrote and OpenSSH signed verify against their
// pinned keys and no other (REQ-verify-pinned-key): the tag and the
// commit under the Ed25519 key, the tag under the RSA key in the
// rsa-sha2-512 form; the outcome names the key that verified.
func TestVerifyPinnedSSHFixtures(t *testing.T) {
	ed := string(readFixture(t, "ssh-fixture-key.pub"))
	rsa := string(readFixture(t, "ssh-fixture-rsa-key.pub"))
	tag := Object{Kind: Tag, Format: SHA1, Raw: readFixture(t, "ssh-fixture-tag.txt")}
	rsaTag := Object{Kind: Tag, Format: SHA1, Raw: readFixture(t, "ssh-fixture-rsa-tag.txt")}
	commit := Object{Kind: Commit, Format: SHA1, Raw: readFixture(t, "ssh-fixture-commit.txt")}

	for _, tt := range []struct {
		name string
		obj  Object
		keys []PinnedKey
		want string
	}{
		{"the tag under its key", tag, PinnedSSH(t, ed), sshFixtureFP},
		{"the commit under its key", commit, PinnedSSH(t, ed), sshFixtureFP},
		{"the RSA tag under its key", rsaTag, PinnedSSH(t, rsa), sshFixtureRSAFP},
		{"the tag among both keys", tag, PinnedSSH(t, rsa, ed), sshFixtureFP},
	} {
		t.Run(tt.name, func(t *testing.T) {
			vk, err := VerifyPinned(tt.obj, tt.keys)
			if err != nil {
				t.Fatalf("VerifyPinned = %v, want nil", err)
			}
			if vk.Kind != SSH || vk.Fingerprint != tt.want {
				t.Fatalf("VerifyPinned = %+v, want ssh %s", vk, tt.want)
			}
		})
	}
	t.Run("the fingerprints are the keys'", func(t *testing.T) {
		if got := PinnedSSH(t, ed)[0].Fingerprint(); got != sshFixtureFP {
			t.Fatalf("Fingerprint = %s, want %s", got, sshFixtureFP)
		}
		if got := PinnedSSH(t, rsa)[0].Kind(); got != SSH {
			t.Fatalf("Kind = %s, want ssh", got)
		}
	})
	for _, tt := range []struct {
		name string
		obj  Object
		keys []PinnedKey
		want string
	}{
		{"the tag under the other key alone", tag, PinnedSSH(t, rsa), "unpinned key " + sshFixtureFP},
		{"the tag under no key", tag, nil, "no pinned key of the signature's kind"},
		{"the tag under no SSH key", tag, []PinnedKey{{kind: OpenPGP, fingerprint: "x"}}, "no pinned key of the signature's kind"},
		{"the tag's message changed", Object{Kind: Tag, Format: SHA1, Raw: bytes.Replace(tag.Raw, []byte("fixture tag"), []byte("fixture TAG"), 1)}, PinnedSSH(t, ed), "does not verify"},
		{"the commit in the other form", Object{Kind: Commit, Format: SHA256, Raw: commit.Raw}, PinnedSSH(t, ed), "not signed"},
		{"the tag by the RSA key's signature transplanted", Object{Kind: Tag, Format: SHA1, Raw: transplant(t, tag.Raw, rsaTag.Raw)}, PinnedSSH(t, ed, rsa), "does not verify"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := VerifyPinned(tt.obj, tt.keys); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("VerifyPinned = %v, want %q", err, tt.want)
			}
		})
	}
	t.Run("a sigstore signature is not this verifier's", func(t *testing.T) {
		raw, _ := loadEmbeddedFixture(t)
		if _, err := VerifyPinned(Object{Kind: Commit, Format: SHA1, Raw: raw}, PinnedSSH(t, ed)); !errors.Is(err, ErrSignatureKind) {
			t.Fatalf("VerifyPinned(sigstore) = %v, want ErrSignatureKind", err)
		}
	})
	t.Run("an OpenPGP signature has no verifier yet", func(t *testing.T) {
		if _, err := VerifyPinned(commitSignedWith(t, []byte(pgpArmor)), PinnedSSH(t, ed)); err == nil ||
			!strings.Contains(err.Error(), "no verifier for a openpgp signature") {
			t.Fatalf("VerifyPinned(openpgp) = %v, want no-verifier error", err)
		}
	})
	t.Run("an invalid descriptor fails closed", func(t *testing.T) {
		if _, err := VerifyPinned(Object{Kind: "blob", Format: SHA1, Raw: tag.Raw}, PinnedSSH(t, ed)); err == nil ||
			!strings.Contains(err.Error(), "unknown object kind") {
			t.Fatalf("VerifyPinned(blob) = %v, want unknown-kind error", err)
		}
	})
}

// transplant puts the second tag's in-body signature on the first
// tag's payload.
func transplant(t *testing.T, onto, from []byte) []byte {
	t.Helper()
	cut := func(raw []byte) (payload, sig []byte) {
		i := bytes.LastIndex(raw, []byte("\n-----BEGIN "))
		if i < 0 {
			t.Fatal("no in-body signature")
		}
		return raw[:i+1], raw[i+1:]
	}
	payload, _ := cut(onto)
	_, sig := cut(from)
	return append(append([]byte(nil), payload...), sig...)
}
