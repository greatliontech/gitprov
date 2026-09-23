package gitprov

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	openPGPFixtureFP       = "91EDFEA1C6643EA64EC693516EA5914F2DADE816"
	openPGPFixtureSubkeyFP = "225F3F5BE4F54F0A97C90D557D51FFB6BCF54190"
)

func pinnedOpenPGP(t *testing.T, blocks ...string) []PinnedKey {
	t.Helper()
	keys := make([]PinnedKey, 0, len(blocks))
	for _, b := range blocks {
		k, err := ParsePinnedKey(OpenPGP, b)
		if err != nil {
			t.Fatalf("ParsePinnedKey: %v", err)
		}
		keys = append(keys, k)
	}
	return keys
}

// The real objects git wrote and gpg signed verify against their
// pinned keys and no other (REQ-verify-pinned-key): the commit and
// the tag under the key whose primary key signs, the tag signed by a
// signing subkey under the key it belongs to; the outcome names the
// primary key's fingerprint.
func TestVerifyPinnedOpenPGPFixtures(t *testing.T) {
	keyA := string(readFixture(t, "openpgp-fixture-key.asc"))
	keyB := string(readFixture(t, "openpgp-fixture-subkey-key.asc"))
	tag := Object{Kind: Tag, Format: SHA1, Raw: readFixture(t, "openpgp-fixture-tag.txt")}
	subkeyTag := Object{Kind: Tag, Format: SHA1, Raw: readFixture(t, "openpgp-fixture-subkey-tag.txt")}
	commit := Object{Kind: Commit, Format: SHA1, Raw: readFixture(t, "openpgp-fixture-commit.txt")}
	sshKey := string(readFixture(t, "ssh-fixture-key.pub"))

	for _, tt := range []struct {
		name string
		obj  Object
		keys []PinnedKey
		want string
	}{
		{"the tag under its key", tag, pinnedOpenPGP(t, keyA), openPGPFixtureFP},
		{"the commit under its key", commit, pinnedOpenPGP(t, keyA), openPGPFixtureFP},
		{"the subkey-signed tag under its key", subkeyTag, pinnedOpenPGP(t, keyB), openPGPFixtureSubkeyFP},
		{"the tag among both keys", tag, pinnedOpenPGP(t, keyB, keyA), openPGPFixtureFP},
		{"the tag among keys of both kinds", tag, append(PinnedSSH(t, sshKey), pinnedOpenPGP(t, keyA)...), openPGPFixtureFP},
	} {
		t.Run(tt.name, func(t *testing.T) {
			vk, err := VerifyPinned(tt.obj, tt.keys)
			if err != nil {
				t.Fatalf("VerifyPinned = %v, want nil", err)
			}
			if vk.Kind != OpenPGP || vk.Fingerprint != tt.want {
				t.Fatalf("VerifyPinned = %+v, want openpgp %s", vk, tt.want)
			}
		})
	}
	t.Run("the fingerprints are the primary keys'", func(t *testing.T) {
		if got := pinnedOpenPGP(t, keyB)[0].Fingerprint(); got != openPGPFixtureSubkeyFP {
			t.Fatalf("Fingerprint = %s, want %s", got, openPGPFixtureSubkeyFP)
		}
		if got := pinnedOpenPGP(t, keyA)[0].Kind(); got != OpenPGP {
			t.Fatalf("Kind = %s, want openpgp", got)
		}
	})
	for _, tt := range []struct {
		name     string
		obj      Object
		keys     []PinnedKey
		want     string
		unpinned bool // the failure is ErrUnpinnedKey: no pinned key vouches
	}{
		{"the tag under the other key alone", tag, pinnedOpenPGP(t, keyB), "unpinned key", true},
		{"the tag under no key", tag, nil, "no pinned key of the signature's kind", true},
		{"the tag under SSH keys alone", tag, PinnedSSH(t, sshKey), "no pinned key of the signature's kind (openpgp)", true},
		{"the tag's message changed", Object{Kind: Tag, Format: SHA1, Raw: bytes.Replace(tag.Raw, []byte("fixture tag"), []byte("fixture TAG"), 1)}, pinnedOpenPGP(t, keyA), "does not verify", false},
		{"the commit in the other form", Object{Kind: Commit, Format: SHA256, Raw: commit.Raw}, pinnedOpenPGP(t, keyA), "not signed", false},
		{"the subkey tag's signature transplanted", Object{Kind: Tag, Format: SHA1, Raw: transplant(t, tag.Raw, subkeyTag.Raw)}, pinnedOpenPGP(t, keyA, keyB), "does not verify", false},
		{"a SHA-1-digest signature gpg still makes", Object{Kind: Tag, Format: SHA1, Raw: readFixture(t, "openpgp-fixture-sha1-tag.txt")}, pinnedOpenPGP(t, keyA), "which is refused", false},
		{"an SSH signature under OpenPGP keys alone", Object{Kind: Tag, Format: SHA1, Raw: readFixture(t, "ssh-fixture-tag.txt")}, pinnedOpenPGP(t, keyA), "no pinned key of the signature's kind (ssh)", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyPinned(tt.obj, tt.keys)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("VerifyPinned = %v, want %q", err, tt.want)
			}
			if errors.Is(err, ErrUnpinnedKey) != tt.unpinned {
				t.Fatalf("VerifyPinned = %v; ErrUnpinnedKey = %v, want %v", err, !tt.unpinned, tt.unpinned)
			}
		})
	}
	t.Run("two pinned keys of one key id each get a fresh digest", func(t *testing.T) {
		// A key id is the low bits of a fingerprint; two keys sharing
		// one are a collision no signer can make, spelled here by hand:
		// the unrelated key, first in the ring, claims the signer's id.
		// Verifying against it must not spend the digest the signer's
		// own key then reads.
		keys := pinnedOpenPGP(t, keyB, keyA)
		aliased := false
		for i := range keys[0].pgp.Subkeys {
			// The other key's signing subkey, so the usage filter keeps
			// it as a candidate.
			if sk := &keys[0].pgp.Subkeys[i]; sk.Sig.FlagsValid && sk.Sig.FlagSign {
				sk.PublicKey.KeyId = keys[1].pgp.PrimaryKey.KeyId
				aliased = true
			}
		}
		if !aliased {
			t.Fatal("the other key has no signing subkey to alias")
		}
		vk, err := VerifyPinned(tag, keys)
		if err != nil || vk.Fingerprint != openPGPFixtureFP {
			t.Fatalf("VerifyPinned = %+v, %v; want %s", vk, err, openPGPFixtureFP)
		}
	})
	t.Run("a sigstore signature is not this verifier's", func(t *testing.T) {
		raw, _ := loadEmbeddedFixture(t)
		if _, err := VerifyPinned(Object{Kind: Commit, Format: SHA1, Raw: raw}, pinnedOpenPGP(t, keyA)); !errors.Is(err, ErrSignatureKind) {
			t.Fatalf("VerifyPinned(sigstore) = %v, want ErrSignatureKind", err)
		}
	})
}
