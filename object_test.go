package gitprov

import (
	"bytes"
	"encoding/pem"
	"strings"
	"testing"

	gitsign "github.com/sigstore/gitsign/pkg/git"
	"pgregory.net/rapid"
)

func minimalCommitPayload() []byte {
	return []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Test User <t@example.com> 1700000000 +0000\n" +
		"committer Test User <t@example.com> 1700000000 +0000\n" +
		"\n" +
		"test: provenance fixture commit\n")
}

func minimalTagPayload() []byte {
	return []byte("object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"type commit\n" +
		"tag v0.0.0\n" +
		"tagger Test User <t@example.com> 1700000000 +0000\n" +
		"\n" +
		"test tag\n")
}

func TestObjectValidate(t *testing.T) {
	raw := minimalCommitPayload()
	cases := []struct {
		name    string
		obj     Object
		wantErr string
	}{
		{"commit sha1", Object{Commit, SHA1, raw}, ""},
		{"tag sha256", Object{Tag, SHA256, raw}, ""},
		{"unknown kind", Object{ObjectKind("blob"), SHA1, raw}, "unknown object kind"},
		{"unknown format", Object{Commit, ObjectFormat("sha512"), raw}, "unknown object format"},
		{"empty raw", Object{Commit, SHA1, nil}, "empty object"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.obj.validate()
			if c.wantErr == "" && err != nil {
				t.Fatalf("validate() = %v, want nil", err)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("validate() = %v, want error containing %q", err, c.wantErr)
			}
		})
	}
}

// splitSignature selects the location that signs the form in hand
// (REQ-verify-signature-extraction): commit headers are form-matched,
// a tag's own-form signature is only ever the in-body trailer, and an
// object with no signature at its form's location is unsigned.
func TestSplitSignature(t *testing.T) {
	fakePEM := pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: []byte("fakesig")})
	fake256 := pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: []byte("fakesig-sha256")})

	commit := minimalCommitPayload()
	tag := minimalTagPayload()

	join := func(t *testing.T, cs *gitsign.CommitSig) []byte {
		t.Helper()
		raw, err := gitsign.JoinCommit(cs)
		if err != nil {
			t.Fatalf("JoinCommit: %v", err)
		}
		return raw
	}
	joinTag := func(t *testing.T, ts *gitsign.TagSig) []byte {
		t.Helper()
		raw, err := gitsign.JoinTag(ts)
		if err != nil {
			t.Fatalf("JoinTag: %v", err)
		}
		return raw
	}

	bothHeaders := join(t, &gitsign.CommitSig{Payload: commit, Gpgsig: fakePEM, GpgsigSha256: fake256})

	tests := []struct {
		name    string
		obj     Object
		wantErr string
		wantSig []byte
		wantPfx string
	}{
		{"commit sha1 form selects gpgsig",
			Object{Commit, SHA1, join(t, &gitsign.CommitSig{Payload: commit, Gpgsig: fakePEM})}, "", fakePEM, "tree "},
		{"commit sha256 form selects gpgsig-sha256",
			Object{Commit, SHA256, join(t, &gitsign.CommitSig{Payload: commit, GpgsigSha256: fake256})}, "", fake256, "tree "},
		{"dual-header commit: sha1 form picks gpgsig",
			Object{Commit, SHA1, bothHeaders}, "", fakePEM, "tree "},
		{"dual-header commit: sha256 form picks gpgsig-sha256",
			Object{Commit, SHA256, bothHeaders}, "", fake256, "tree "},
		{"commit sha1 form with only the alternate-form header is unsigned",
			Object{Commit, SHA1, join(t, &gitsign.CommitSig{Payload: commit, GpgsigSha256: fake256})}, "commit is not signed", nil, ""},
		{"commit sha256 form with only the alternate-form header is unsigned",
			Object{Commit, SHA256, join(t, &gitsign.CommitSig{Payload: commit, Gpgsig: fakePEM})}, "commit is not signed", nil, ""},
		{"commit unsigned", Object{Commit, SHA1, commit}, "commit is not signed", nil, ""},
		{"tag in-body signature, sha1 form",
			Object{Tag, SHA1, joinTag(t, &gitsign.TagSig{Payload: tag, InBody: fakePEM})}, "", fakePEM, "object "},
		{"tag in-body signature, sha256 form",
			Object{Tag, SHA256, joinTag(t, &gitsign.TagSig{Payload: tag, InBody: fakePEM})}, "", fakePEM, "object "},
		// A tag header signature signs the ALTERNATE-form bytes; it is
		// never the signature of the form in hand and must not be
		// selected.
		{"tag with only a gpgsig header is unsigned",
			Object{Tag, SHA256, joinTag(t, &gitsign.TagSig{Payload: tag, Gpgsig: fakePEM})}, "tag is not signed", nil, ""},
		{"tag with only a gpgsig-sha256 header is unsigned",
			Object{Tag, SHA1, joinTag(t, &gitsign.TagSig{Payload: tag, GpgsigSha256: fake256})}, "tag is not signed", nil, ""},
		{"tag unsigned", Object{Tag, SHA1, tag}, "tag is not signed", nil, ""},
		// Split CAN fail on malformed objects — a duplicate signature
		// header and an over-long header line (bufio token limit) are
		// both reachable caller inputs and must surface the split error,
		// not a downstream misdiagnosis.
		{"malformed commit: duplicate gpgsig header",
			Object{Commit, SHA1, []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"gpgsig line\ngpgsig line\n" +
				"author Test User <t@example.com> 1700000000 +0000\n" +
				"committer Test User <t@example.com> 1700000000 +0000\n" +
				"\nx\n")}, "split commit", nil, ""},
		{"malformed tag: header line beyond the scanner token limit",
			Object{Tag, SHA1, []byte("object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"type commit\ntag v1\n" + strings.Repeat("a", 70*1024) + "\n\nx\n")},
			"split tag", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, sig, err := splitSignature(tt.obj)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("splitSignature err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitSignature = %v, want nil", err)
			}
			if !bytes.HasPrefix(payload, []byte(tt.wantPfx)) {
				t.Fatalf("payload prefix = %q, want %q", firstLine(payload), tt.wantPfx)
			}
			if bytes.Contains(payload, []byte("\ngpgsig ")) || bytes.Contains(payload, []byte("\ngpgsig-sha256 ")) {
				t.Fatalf("payload still carries a signature header: %q", payload)
			}
			if !bytes.Equal(sig, tt.wantSig) {
				t.Fatalf("sig = %q, want %q", sig, tt.wantSig)
			}
		})
	}
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

// TestSplitSignatureRoundTripsRawBytes proves REQ-verify-raw-bytes as a
// for-all property: for arbitrary well-formed commit/tag payloads —
// including message lines that mimic signature headers — and arbitrary
// signature bytes, splitting the joined object returns the payload and
// signature byte-for-byte. Any normalization anywhere in the split path
// (re-encoded headers, trimmed whitespace, reordered fields) breaks the
// exact equality and would verify bytes the origin never signed.
func TestSplitSignatureRoundTripsRawBytes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		format := rapid.SampledFrom([]ObjectFormat{SHA1, SHA256}).Draw(rt, "format")
		sigDER := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(rt, "sigDER")
		sig := pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: sigDER})

		hex40 := rapid.StringMatching(`[0-9a-f]{40}`)
		person := rapid.StringMatching(`[A-Za-z][A-Za-z ]{0,12}[A-Za-z] <[a-z]{1,8}@[a-z]{1,8}\.com> 17[0-9]{8} \+0000`)

		var payload, raw []byte
		var obj Object
		if rapid.Bool().Draw(rt, "isCommit") {
			var b bytes.Buffer
			b.WriteString("tree " + hex40.Draw(rt, "tree") + "\n")
			for i, n := 0, rapid.IntRange(0, 2).Draw(rt, "parents"); i < n; i++ {
				b.WriteString("parent " + hex40.Draw(rt, "parent") + "\n")
			}
			b.WriteString("author " + person.Draw(rt, "author") + "\n")
			b.WriteString("committer " + person.Draw(rt, "committer") + "\n")
			b.WriteString("\n")
			// Message lines are arbitrary printable ASCII: lines shaped
			// exactly like "gpgsig ..." headers MUST survive as message
			// content, never be mistaken for signature locations.
			for i, n := 0, rapid.IntRange(1, 4).Draw(rt, "msglines"); i < n; i++ {
				b.WriteString(rapid.StringMatching(`[ -~]{0,60}`).Draw(rt, "msg") + "\n")
			}
			payload = b.Bytes()
			cs := &gitsign.CommitSig{Payload: payload}
			if format == SHA256 {
				cs.GpgsigSha256 = sig
			} else {
				cs.Gpgsig = sig
			}
			joined, err := gitsign.JoinCommit(cs)
			if err != nil {
				t.Fatalf("JoinCommit: %v", err)
			}
			raw, obj = joined, Object{Commit, format, joined}
		} else {
			var b bytes.Buffer
			b.WriteString("object " + hex40.Draw(rt, "object") + "\n")
			b.WriteString("type commit\n")
			b.WriteString("tag v" + rapid.StringMatching(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`).Draw(rt, "tagname") + "\n")
			b.WriteString("tagger " + person.Draw(rt, "tagger") + "\n")
			b.WriteString("\n")
			// No '-' in tag messages: the in-body trailer is delimited by
			// the PEM armor, so a message embedding armor markers is
			// inherently ambiguous in git's own tag format.
			for i, n := 0, rapid.IntRange(1, 4).Draw(rt, "msglines"); i < n; i++ {
				b.WriteString(rapid.StringMatching(`[A-Za-z0-9 :@.gpsi]{0,60}`).Draw(rt, "msg") + "\n")
			}
			payload = b.Bytes()
			joined, err := gitsign.JoinTag(&gitsign.TagSig{Payload: payload, InBody: sig})
			if err != nil {
				t.Fatalf("JoinTag: %v", err)
			}
			raw, obj = joined, Object{Tag, format, joined}
		}

		gotPayload, gotSig, err := splitSignature(obj)
		if err != nil {
			t.Fatalf("splitSignature(%s) = %v, want nil\nraw:\n%s", obj.Kind, err, raw)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Fatalf("payload not byte-identical\ngot:\n%q\nwant:\n%q", gotPayload, payload)
		}
		if !bytes.Equal(gotSig, sig) {
			t.Fatalf("signature not byte-identical\ngot:\n%q\nwant:\n%q", gotSig, sig)
		}
	})
}
