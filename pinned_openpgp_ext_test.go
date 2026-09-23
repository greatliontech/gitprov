package gitprov_test

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gitprov"
	"github.com/greatliontech/gitprov/sigstoretest"
	"pgregory.net/rapid"
)

func pinnedOpenPGP(t *testing.T, blocks ...string) []gitprov.PinnedKey {
	t.Helper()
	keys := make([]gitprov.PinnedKey, 0, len(blocks))
	for _, b := range blocks {
		k, err := gitprov.ParsePinnedKey(gitprov.OpenPGP, b)
		if err != nil {
			t.Fatalf("ParsePinnedKey: %v", err)
		}
		keys = append(keys, k)
	}
	return keys
}

// What the verifier judges of an OpenPGP signature is judged
// (REQ-verify-pinned-key, REQ-verify-fail-closed): the signer among
// the pinned keys, a subkey resolved to its primary, the signature's
// mode and hash; and what verifies is a pinned key over the raw
// payload, in both object forms, whatever armor headers the block
// carries.
func TestVerifyPinnedOpenPGPShapes(t *testing.T) {
	key := sigstoretest.NewOpenPGPKey(t)
	other := sigstoretest.NewOpenPGPKey(t)
	sub := sigstoretest.NewOpenPGPKey(t).WithSigningSubkey(t)
	pinned := pinnedOpenPGP(t, key.Public(t))
	tagPayload := gitprov.MinimalTagPayload()
	commitPayload := gitprov.MinimalCommitPayload()
	tagOf := func(t *testing.T, k *sigstoretest.OpenPGPKey, o sigstoretest.OpenPGPOptions) gitprov.Object {
		t.Helper()
		return gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: k.SignedTag(t, tagPayload, o)}
	}

	t.Run("a tag verifies", func(t *testing.T) {
		vk, err := gitprov.VerifyPinned(tagOf(t, key, sigstoretest.OpenPGPOptions{}), pinned)
		if err != nil || vk.Kind != gitprov.OpenPGP || vk.Fingerprint != key.Fingerprint() {
			t.Fatalf("VerifyPinned = %+v, %v; want openpgp %s", vk, err, key.Fingerprint())
		}
	})
	for _, format := range []gitprov.ObjectFormat{gitprov.SHA1, gitprov.SHA256} {
		t.Run("a commit verifies in the "+string(format)+" form", func(t *testing.T) {
			raw := key.SignedCommit(t, commitPayload, format, sigstoretest.OpenPGPOptions{})
			if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Commit, Format: format, Raw: raw}, pinned); err != nil {
				t.Fatalf("VerifyPinned = %v, want nil", err)
			}
		})
	}
	t.Run("a signing subkey's signature names its primary key", func(t *testing.T) {
		vk, err := gitprov.VerifyPinned(tagOf(t, sub, sigstoretest.OpenPGPOptions{}), pinnedOpenPGP(t, sub.Public(t)))
		if err != nil || vk.Fingerprint != sub.Fingerprint() {
			t.Fatalf("VerifyPinned(subkey) = %+v, %v; want %s", vk, err, sub.Fingerprint())
		}
	})
	t.Run("armor header lines are the armor's", func(t *testing.T) {
		if _, err := gitprov.VerifyPinned(tagOf(t, key, sigstoretest.OpenPGPOptions{Headers: map[string]string{"Comment": "see -----BEGIN x-----"}}), pinned); err != nil {
			t.Fatalf("VerifyPinned(headers) = %v, want nil", err)
		}
	})
	t.Run("sha512 verifies", func(t *testing.T) {
		if _, err := gitprov.VerifyPinned(tagOf(t, key, sigstoretest.OpenPGPOptions{Hash: crypto.SHA512}), pinned); err != nil {
			t.Fatalf("VerifyPinned(sha512) = %v, want nil", err)
		}
	})
	for _, tt := range []struct {
		name     string
		key      *sigstoretest.OpenPGPKey
		keys     []gitprov.PinnedKey
		o        sigstoretest.OpenPGPOptions
		want     string
		unpinned bool // the failure is ErrUnpinnedKey: the pinned keys do not vouch
	}{
		{"signed by an unpinned key", other, pinned, sigstoretest.OpenPGPOptions{}, "unpinned key", true},
		{"a text-mode signature", key, pinned, sigstoretest.OpenPGPOptions{Text: true}, "not a binary-mode one", false},
		{"a subkey's signature under another key", sub, pinned, sigstoretest.OpenPGPOptions{}, "unpinned key", true},
		{"a critical notation", key, pinned, sigstoretest.OpenPGPOptions{Critical: true}, "critical notation", false},
		{"bytes after the signature packet", key, pinned, sigstoretest.OpenPGPOptions{Trailing: []byte("JUNKJUNKJUNK")}, "signature packet", false},
		{"a second signature packet", key, pinned, sigstoretest.OpenPGPOptions{Second: other}, "holds 2 packets", false},
		{"an unreadable packet before the signature", key, pinned, sigstoretest.OpenPGPOptions{UnreadableBefore: true}, "signature packet", false},
		{"an unreadable packet after the signature", key, pinned, sigstoretest.OpenPGPOptions{UnreadableAfter: true}, "signature packet", false},
		{"an unreadable certification-typed packet after the signature", key, pinned, sigstoretest.OpenPGPOptions{UnreadableCertificationAfter: true}, "signature packet", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := gitprov.VerifyPinned(tagOf(t, tt.key, tt.o), tt.keys)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("VerifyPinned = %v, want %q", err, tt.want)
			}
			if errors.Is(err, gitprov.ErrUnpinnedKey) != tt.unpinned {
				t.Fatalf("VerifyPinned = %v; ErrUnpinnedKey = %v, want %v", err, !tt.unpinned, tt.unpinned)
			}
		})
	}
	t.Run("the signature is judged at its own creation time", func(t *testing.T) {
		// A key made two years ago and valid for one, expired today: a
		// signature claiming a time within the year verifies today and
		// always — expiry counts by the signature's claim, never by the
		// clock. No signer makes a signature claiming a time past its
		// key's expiry, so that refusal has no witness.
		now := time.Now()
		expiring := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-2 * 365 * 24 * time.Hour), Lifetime: 365 * 24 * time.Hour})
		epinned := pinnedOpenPGP(t, expiring.Public(t))
		within := sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2*365*24*time.Hour + 24*time.Hour)}
		if _, err := gitprov.VerifyPinned(tagOf(t, expiring, within), epinned); err != nil {
			t.Fatalf("VerifyPinned(signed within the key's validity) = %v, want nil", err)
		}
		// A signature valid for a second, made an hour ago by a key
		// made before it: never expired at its own creation.
		old := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
		if _, err := gitprov.VerifyPinned(tagOf(t, old, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-time.Hour), SigLifetime: time.Second}), pinnedOpenPGP(t, old.Public(t))); err != nil {
			t.Fatalf("VerifyPinned(an expiring signature) = %v, want nil", err)
		}
		// The refusals the rule makes, from a signer judging nothing:
		// a signature claiming a time before the key's creation, one
		// claiming a time past its expiry.
		if _, err := gitprov.VerifyPinned(tagOf(t, old, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-4 * time.Hour), Forced: true}), pinnedOpenPGP(t, old.Public(t))); err == nil || !strings.Contains(err.Error(), "not yet created") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(signed before the key's creation) = %v, want refusal", err)
		}
		if _, err := gitprov.VerifyPinned(tagOf(t, expiring, sigstoretest.OpenPGPOptions{Forced: true}), epinned); err == nil || !strings.Contains(err.Error(), "key was expired") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(signed after the key's expiry) = %v, want expired", err)
		}
		// The subkey likewise: its own expiry, its binding's own
		// lifetime, its creation — and its revocations, soft from their
		// time and hard against every signature.
		subExpiring := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)}).
			WithSigningSubkeyWith(t, sigstoretest.SubkeyOptions{Created: now.Add(-2 * time.Hour), Lifetime: 30 * time.Minute})
		sePinned := pinnedOpenPGP(t, subExpiring.Public(t))
		if _, err := gitprov.VerifyPinned(tagOf(t, subExpiring, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2*time.Hour + 10*time.Minute)}), sePinned); err != nil {
			t.Fatalf("VerifyPinned(subkey signed within its validity) = %v, want nil", err)
		}
		if _, err := gitprov.VerifyPinned(tagOf(t, subExpiring, sigstoretest.OpenPGPOptions{ForcedSubkey: true}), sePinned); err == nil || !strings.Contains(err.Error(), "subkey was expired") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(subkey signed after its expiry) = %v, want subkey expired", err)
		}
		if _, err := gitprov.VerifyPinned(tagOf(t, subExpiring, sigstoretest.OpenPGPOptions{ForcedSubkey: true, SignedAt: now.Add(-150 * time.Minute)}), sePinned); err == nil || !strings.Contains(err.Error(), "subkey was not yet created") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(subkey signed before its creation) = %v, want refusal", err)
		}
		bindingLapsed := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)}).
			WithSigningSubkeyWith(t, sigstoretest.SubkeyOptions{Created: now.Add(-2 * time.Hour), BindingLifetime: 30 * time.Minute})
		if _, err := gitprov.VerifyPinned(tagOf(t, bindingLapsed, sigstoretest.OpenPGPOptions{ForcedSubkey: true}), pinnedOpenPGP(t, bindingLapsed.Public(t))); err == nil || !strings.Contains(err.Error(), "binding had lapsed") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(subkey signed after its binding lapsed) = %v, want refusal", err)
		}
		selfLapsed := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)}).ReSignForA(t, now.Add(-2*time.Hour), 30*time.Minute)
		if _, err := gitprov.VerifyPinned(tagOf(t, selfLapsed, sigstoretest.OpenPGPOptions{Forced: true}), pinnedOpenPGP(t, selfLapsed.Public(t))); err == nil || !strings.Contains(err.Error(), "self-signature had lapsed") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(signed after the self-signature lapsed) = %v, want refusal", err)
		}
		subRevoked := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)}).WithSigningSubkeyWith(t, sigstoretest.SubkeyOptions{Created: now.Add(-3 * time.Hour)})
		subBefore := subRevoked.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		subAfter := subRevoked.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{})
		srPinned := pinnedOpenPGP(t, subRevoked.RevokeSubkey(t, now.Add(-time.Hour)).Public(t))
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: subBefore}, srPinned); err != nil {
			t.Fatalf("VerifyPinned(subkey signed before its revocation) = %v, want nil", err)
		}
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: subAfter}, srPinned); err == nil || !strings.Contains(err.Error(), "subkey was revoked") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(subkey signed after its revocation) = %v, want subkey revoked", err)
		}
		subCompromised := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)}).WithSigningSubkeyWith(t, sigstoretest.SubkeyOptions{Created: now.Add(-3 * time.Hour)})
		subEarly := subCompromised.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: subEarly}, pinnedOpenPGP(t, subCompromised.RevokeSubkeyCompromised(t, now.Add(-time.Hour)).Public(t))); err == nil || !strings.Contains(err.Error(), "subkey was revoked") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(subkey signed before its compromise revocation) = %v, want subkey revoked", err)
		}
		// The primary identity revoked: refused whenever the signature
		// claims, the revocation stating no reason.
		idRevoked := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
		idEarly := idRevoked.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: idEarly}, pinnedOpenPGP(t, idRevoked.RevokeIdentity(t, now.Add(-time.Hour)).Public(t))); err == nil || !strings.Contains(err.Error(), "identity was revoked") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(signed before the identity's revocation) = %v, want identity revoked", err)
		}
		// A key whose self-signature states no key flags signs nothing,
		// and the refusal says so rather than naming an unpinned key.
		flagless := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
		flaglessSig := flagless.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: flaglessSig}, pinnedOpenPGP(t, flagless.ReSignWithoutFlags(t, now.Add(-time.Hour)).Public(t))); err == nil || !strings.Contains(err.Error(), "key flags do not admit signing") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(a key without key flags) = %v, want the flags named", err)
		}
		// A self-signature carrying a critical notation no verifier
		// knows: the key's own statement, so the key does not vouch.
		notated := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
		notatedSig := notated.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: notatedSig}, pinnedOpenPGP(t, notated.ReSignWithCriticalNotation(t, now.Add(-time.Hour)).Public(t))); err == nil || !strings.Contains(err.Error(), "critical notation") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(a self-signature with a critical notation) = %v, want the key not vouching", err)
		}
		// A revocation carrying no reason subpacket at all is hard.
		noReason := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
		nrEarly := noReason.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: nrEarly}, pinnedOpenPGP(t, noReason.RevokeWithoutReason(t, now.Add(-time.Hour)).Public(t))); err == nil || !strings.Contains(err.Error(), "key was revoked") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(signed before a revocation without a reason) = %v, want revoked", err)
		}
		// A key re-signed after the signature — its expiry extended, a
		// preference changed — still verifies it: the self-signature's
		// own time is no bound.
		resigned := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
		earlier := resigned.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: earlier}, pinnedOpenPGP(t, resigned.ReSign(t, now.Add(-time.Hour)).Public(t))); err != nil {
			t.Fatalf("VerifyPinned(signed before the key's re-signing) = %v, want nil", err)
		}
		// A key superseded an hour ago, a soft revocation: a signature
		// claiming a time before it verifies, one after it is refused; so
		// for retirement. A hard revocation — no reason, compromise —
		// refuses every signature, whenever made.
		revoked := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
		before := revoked.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		after := revoked.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{})
		rpinned := pinnedOpenPGP(t, revoked.Revoke(t, now.Add(-time.Hour)).Public(t))
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: before}, rpinned); err != nil {
			t.Fatalf("VerifyPinned(signed before the revocation) = %v, want nil", err)
		}
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: after}, rpinned); err == nil || !strings.Contains(err.Error(), "revoked") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
			t.Fatalf("VerifyPinned(signed after the revocation) = %v, want revoked", err)
		}
		retired := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
		beforeRetired := retired.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: beforeRetired}, pinnedOpenPGP(t, retired.RevokeRetired(t, now.Add(-time.Hour)).Public(t))); err != nil {
			t.Fatalf("VerifyPinned(signed before retirement) = %v, want nil", err)
		}
		for name, revoke := range map[string]func(*sigstoretest.OpenPGPKey) *sigstoretest.OpenPGPKey{
			"compromise": func(k *sigstoretest.OpenPGPKey) *sigstoretest.OpenPGPKey {
				return k.RevokeCompromised(t, now.Add(-time.Hour))
			},
			"no reason": func(k *sigstoretest.OpenPGPKey) *sigstoretest.OpenPGPKey {
				return k.RevokeNoReason(t, now.Add(-time.Hour))
			},
		} {
			hard := sigstoretest.NewOpenPGPKeyWith(t, sigstoretest.OpenPGPKeyOptions{Created: now.Add(-3 * time.Hour)})
			early := hard.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{SignedAt: now.Add(-2 * time.Hour)})
			if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: early}, pinnedOpenPGP(t, revoke(hard).Public(t))); err == nil || !strings.Contains(err.Error(), "revoked") || !errors.Is(err, gitprov.ErrUnpinnedKey) {
				t.Fatalf("VerifyPinned(signed before a %s revocation) = %v, want revoked", name, err)
			}
		}
	})
	t.Run("the armor checksum is not judged", func(t *testing.T) {
		raw := []byte(sigstoretest.WithBadChecksum(t, string(key.SignedTag(t, tagPayload, sigstoretest.OpenPGPOptions{}))))
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: raw}, pinned); err != nil {
			t.Fatalf("VerifyPinned(bad checksum) = %v, want nil", err)
		}
	})
	t.Run("a five-byte length past the body", func(t *testing.T) {
		// A length near 2^32 with a few bytes behind it: truncated on
		// every build, never a wrapped length on a 32-bit one.
		for name, body := range map[string][]byte{
			"old format": append([]byte{0x8a, 0xff, 0xff, 0xff, 0xf0}, make([]byte, 32)...),
			"new format": append([]byte{0xc2, 0xff, 0xff, 0xff, 0xff, 0xf0}, make([]byte, 32)...),
		} {
			var b bytes.Buffer
			b.WriteString("-----BEGIN PGP SIGNATURE-----\n\n")
			b.WriteString(base64.StdEncoding.EncodeToString(body))
			b.WriteString("\n-----END PGP SIGNATURE-----\n")
			raw := gitprov.CommitSignedWith(t, b.Bytes())
			if _, err := gitprov.VerifyPinned(raw, pinned); err == nil || !strings.Contains(err.Error(), "truncated") {
				t.Fatalf("VerifyPinned(%s, five-byte length) = %v, want truncated", name, err)
			}
		}
	})
	t.Run("an empty body", func(t *testing.T) {
		raw := gitprov.CommitSignedWith(t, []byte("-----BEGIN PGP SIGNATURE-----\n\n-----END PGP SIGNATURE-----\n"))
		if _, err := gitprov.VerifyPinned(raw, pinned); err == nil || !strings.Contains(err.Error(), "holds 0 packets") {
			t.Fatalf("VerifyPinned(empty body) = %v, want packet error", err)
		}
	})
	t.Run("a body that is no armor", func(t *testing.T) {
		raw := gitprov.CommitSignedWith(t, []byte("-----BEGIN PGP SIGNATURE-----\n\nnot base64!\n-----END PGP SIGNATURE-----\n"))
		if _, err := gitprov.VerifyPinned(raw, pinned); err == nil || !strings.Contains(err.Error(), "OpenPGP signature") || strings.Contains(err.Error(), "unpinned") {
			t.Fatalf("VerifyPinned(no armor) = %v, want a decode failure", err)
		}
	})
	t.Run("a body that is armor of no signature", func(t *testing.T) {
		raw := gitprov.CommitSignedWith(t, []byte(gitprov.PGPArmor))
		if _, err := gitprov.VerifyPinned(raw, pinned); err == nil || strings.Contains(err.Error(), "unpinned") {
			t.Fatalf("VerifyPinned(junk packets) = %v, want a parse failure", err)
		}
	})
}

// The signature verifies the raw payload and nothing near it: any
// object whose payload differs from the signed one by one byte fails
// (REQ-verify-pinned-key, REQ-verify-raw-bytes).
func TestVerifyPinnedOpenPGPProperty(t *testing.T) {
	key := sigstoretest.NewOpenPGPKey(t)
	pinned := pinnedOpenPGP(t, key.Public(t))
	rapid.Check(t, func(rt *rapid.T) {
		var b bytes.Buffer
		b.WriteString("object " + rapid.StringMatching(`[0-9a-f]{40}`).Draw(rt, "object") + "\n")
		b.WriteString("type commit\ntag v" + rapid.StringMatching(`[0-9]{1,3}`).Draw(rt, "v") + "\n")
		b.WriteString("tagger T <t@x.invalid> 1700000000 +0000\n\n")
		for i, n := 0, rapid.IntRange(1, 3).Draw(rt, "lines"); i < n; i++ {
			b.WriteString(rapid.StringMatching(`[A-Za-z0-9 ]{0,40}`).Draw(rt, "msg") + "\n")
		}
		payload := b.Bytes()
		raw := key.SignedTag(t, payload, sigstoretest.OpenPGPOptions{})
		if _, err := gitprov.VerifyPinned(gitprov.Object{Kind: gitprov.Tag, Format: gitprov.SHA1, Raw: raw}, pinned); err != nil {
			t.Fatalf("VerifyPinned = %v, want nil\n%s", err, raw)
		}
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

// A pinned OpenPGP key is one armored public key block
// (REQ-verify-pinned-key).
func TestParsePinnedKeyOpenPGP(t *testing.T) {
	key := sigstoretest.NewOpenPGPKey(t)
	sub := sigstoretest.NewOpenPGPKey(t).WithSigningSubkey(t)
	for _, tt := range []struct {
		name  string
		block string
		want  string
	}{
		{"a public key block", key.Public(t), ""},
		{"a key with a signing subkey", sub.Public(t), ""},
		{"a block with a trailing newline", key.Public(t) + "\n", ""},
		{"two keys in one block", sigstoretest.PublicKeyBlock(t, key, sub), "2 keys in the block"},
		{"two blocks", key.Public(t) + sub.Public(t), "more than one armor header line"},
		{"a block with a leading newline", "\n" + key.Public(t), ""},
		{"bytes after the block", key.Public(t) + "x\n", "beside its armored block"},
		{"a private key", key.Private(t), "private key"},
		{"a private key under a public block's label", key.PrivateUnderPublicLabel(t), "private key"},
		{"private subkeys under a public block's label", sub.SecretSubkeysUnderPublicLabel(t), "private subkey"},
		{"a bare primary packet before a key", key.BarePrimaryThen(t, sub), "2 keys in the block"},
		{"a bare primary packet after a key", key.ThenBarePrimary(t, sub), "2 keys in the block"},
		{"a block opening with a subkey", sub.SubkeyFirst(t), "first packet is no primary key"},
		{"a block with CRLF line ends", strings.ReplaceAll(key.Public(t), "\n", "\r\n"), ""},
		{"a certification by a third party under an algorithm the reader lacks", key.CertifiedByUnknownAlgorithm(t, sub), ""},
		{"a certification by a third party of a version the reader lacks", key.CertifiedByUnknownVersion(t, sub), ""},
		{"a subkey binding in a form the reader lacks", sub.WithUnreadableBinding(t), "unsupported"},
		{"a block with a bad checksum", sigstoretest.WithBadChecksum(t, key.Public(t)), ""},
		{"a signature block", string(key.SignatureOver(t, []byte("x"), sigstoretest.OpenPGPOptions{})), `labelled "PGP SIGNATURE"`},
		{"text", "not a key", "does not begin with an armor header line"},
		{"empty", "", "does not begin with an armor header line"},
		{"an SSH key line", sigstoretest.NewSSHKey(t).Public(), "does not begin with an armor header line"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			k, err := gitprov.ParsePinnedKey(gitprov.OpenPGP, tt.block)
			if tt.want != "" {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("ParsePinnedKey = %v, want %q", err, tt.want)
				}
				return
			}
			if err != nil || k.Kind() != gitprov.OpenPGP || len(k.Fingerprint()) != 40 || strings.ToUpper(k.Fingerprint()) != k.Fingerprint() {
				t.Fatalf("ParsePinnedKey = %+v, %v", k, err)
			}
		})
	}
}
