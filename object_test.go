package gitprov

import (
	"bytes"
	"context"
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
		// wantPayload, when set, is the whole payload: the cases
		// pinning which bytes git's rules leave in and cut out.
		wantPayload []byte
	}{
		{"commit sha1 form selects gpgsig",
			Object{Commit, SHA1, join(t, &gitsign.CommitSig{Payload: commit, Gpgsig: fakePEM})}, "", fakePEM, "tree ", nil},
		{"commit sha256 form selects gpgsig-sha256",
			Object{Commit, SHA256, join(t, &gitsign.CommitSig{Payload: commit, GpgsigSha256: fake256})}, "", fake256, "tree ", nil},
		{"dual-header commit: sha1 form picks gpgsig",
			Object{Commit, SHA1, bothHeaders}, "", fakePEM, "tree ", nil},
		{"dual-header commit: sha256 form picks gpgsig-sha256",
			Object{Commit, SHA256, bothHeaders}, "", fake256, "tree ", nil},
		{"commit sha1 form with only the alternate-form header is unsigned",
			Object{Commit, SHA1, join(t, &gitsign.CommitSig{Payload: commit, GpgsigSha256: fake256})}, "commit is not signed", nil, "", nil},
		{"commit sha256 form with only the alternate-form header is unsigned",
			Object{Commit, SHA256, join(t, &gitsign.CommitSig{Payload: commit, Gpgsig: fakePEM})}, "commit is not signed", nil, "", nil},
		{"commit unsigned", Object{Commit, SHA1, commit}, "commit is not signed", nil, "", nil},
		{"tag in-body signature, sha1 form",
			Object{Tag, SHA1, joinTag(t, &gitsign.TagSig{Payload: tag, InBody: fakePEM})}, "", fakePEM, "object ", nil},
		{"tag in-body signature, sha256 form",
			Object{Tag, SHA256, joinTag(t, &gitsign.TagSig{Payload: tag, InBody: fakePEM})}, "", fakePEM, "object ", nil},
		// A tag header signature signs the ALTERNATE-form bytes; it is
		// never the signature of the form in hand and must not be
		// selected.
		{"tag with only a gpgsig header is unsigned",
			Object{Tag, SHA256, joinTag(t, &gitsign.TagSig{Payload: tag, Gpgsig: fakePEM})}, "tag is not signed", nil, "", nil},
		{"tag with only a gpgsig-sha256 header is unsigned",
			Object{Tag, SHA1, joinTag(t, &gitsign.TagSig{Payload: tag, GpgsigSha256: fake256})}, "tag is not signed", nil, "", nil},
		{"tag unsigned", Object{Tag, SHA1, tag}, "tag is not signed", nil, "", nil},
		// A second header of the form's name is gathered into the same
		// signature, as git gathers it; what that holds is the
		// signature's own rules' to judge.
		{"commit: a second gpgsig header joins the signature",
			Object{Commit, SHA1, []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"gpgsig line\nauthor Test User <t@example.com> 1700000000 +0000\n" +
				"gpgsig \n" +
				"committer Test User <t@example.com> 1700000000 +0000\n" +
				"\nx\n")}, "", []byte("line\n\n"), "tree ",
			[]byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"author Test User <t@example.com> 1700000000 +0000\n" +
				"committer Test User <t@example.com> 1700000000 +0000\n" +
				"\nx\n")},
		// git reads lines of any length; a tag no line of which opens a
		// signature is unsigned, not malformed.
		{"tag with a header line of any length is unsigned",
			Object{Tag, SHA1, []byte("object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"type commit\ntag v1\n" + strings.Repeat("a", 70*1024) + "\n\nx\n")},
			"tag is not signed", nil, "", nil},
		// git's rules over the bytes, pinned whole: a header opening
		// with "gpgsig" that is neither signature header leaves the
		// commit payload with its continuation lines; a header
		// continued over lines (mergetag) stays; the message is
		// payload whole, header-shaped lines, returns and a missing
		// final newline included.
		{"commit: an unknown gpgsig-prefixed header is cut out with its continuation",
			Object{Commit, SHA1, []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"gpgsigfoo bar\n baz\n" +
				"mergetag object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n type commit\n" +
				sigBlock("gpgsig", fakePEM) +
				"gpgsig-sha256 x\n y\n" +
				"\ngpgsig not a header\r\n\nno final newline")}, "", fakePEM, "tree ",
			[]byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"mergetag object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n type commit\n" +
				"\ngpgsig not a header\r\n\nno final newline")},
		// A tag's signature opens at the LAST line opening with a
		// marker git knows, whatever the message holds before it; the
		// payload keeps every byte before it but the header block.
		{"tag: the last opening line is the signature, the header block cut out",
			Object{Tag, SHA1, []byte("object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"gpgsig-sha256 x\n y\n" +
				"type commit\ntag v1\n" +
				"\n-----BEGIN PGP SIGNATURE-----\r\nnot the signature\n" +
				string(fakePEM))}, "", fakePEM, "object ",
			[]byte("object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"type commit\ntag v1\n" +
				"\n-----BEGIN PGP SIGNATURE-----\r\nnot the signature\n")},
		// A third header block after two closed ones is where git's
		// reading is undefined: refused.
		{"tag: a third signature-header block is refused",
			Object{Tag, SHA1, []byte("object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"gpgsig a\ntype commit\ngpgsig-sha256 b\ntag v1\ngpgsig c\n\n" + string(fakePEM))},
			"split tag: a third signature header", nil, "", nil},
		{"tag: a signature line not opening the line is no signature",
			Object{Tag, SHA1, []byte("object 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
				"type commit\ntag v1\n\nmessage " + string(fakePEM))},
			"tag is not signed", nil, "", nil},
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
			if !bytes.Equal(sig, tt.wantSig) {
				t.Fatalf("sig = %q, want %q", sig, tt.wantSig)
			}
			if tt.wantPayload != nil {
				if !bytes.Equal(payload, tt.wantPayload) {
					t.Fatalf("payload = %q, want %q", payload, tt.wantPayload)
				}
				return
			}
			if bytes.Contains(payload, []byte("\ngpgsig ")) || bytes.Contains(payload, []byte("\ngpgsig-sha256 ")) {
				t.Fatalf("payload still carries a signature header: %q", payload)
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

// signedCommit writes a commit as git does (add_header_signature):
// the signature's lines become a header block — the header and a
// space before the first, a space before each other — inserted among
// the payload's header lines at the given line index (git inserts at
// the header end), the payload otherwise untouched. An independent
// encoding of git's rules, against which the split's reading is held.
func signedCommit(payload []byte, header string, sig []byte, at int) []byte {
	pos := headerLineStarts(payload)[at]
	return append(append(append([]byte(nil), payload[:pos]...), sigBlock(header, sig)...), payload[pos:]...)
}

// sigBlock is a signature as a commit header block: the header and a
// space before its first line, a space before each other.
func sigBlock(header string, sig []byte) string {
	var block bytes.Buffer
	for i, line := range bytes.SplitAfter(sig, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if i == 0 {
			block.WriteString(header)
		}
		block.WriteByte(' ')
		block.Write(line)
	}
	return block.String()
}

// headerLineStarts are the offsets a header block may be inserted at:
// the start of every header line that is no continuation, and the
// header end (the empty line, or the object's end without one).
func headerLineStarts(payload []byte) []int {
	var at []int
	for i := 0; i < len(payload); {
		if payload[i] == '\n' {
			return append(at, i)
		}
		if payload[i] != ' ' {
			at = append(at, i)
		}
		j := bytes.IndexByte(payload[i:], '\n')
		if j < 0 {
			break
		}
		i += j + 1
	}
	return append(at, len(payload))
}

// gitMessage draws message bytes shaped to mislead a reader: lines
// shaped like signature headers and continuations, signature
// openings, carriage returns, a NUL, non-ASCII bytes, empty lines, a
// final line with or without its newline.
func gitMessage(rt *rapid.T, label string) []byte {
	tokens := []string{"gpgsig ", "gpgsig-sha256 ", " ", "\r", "\n", "\n\n", "x", "tree ", "\x00", "\u00a0", "é",
		"-----BEGIN PGP SIGNATURE-----", "-----BEGIN SSH SIGNATURE-----", "-----END PGP SIGNATURE-----"}
	var b bytes.Buffer
	for _, tok := range rapid.SliceOfN(rapid.SampledFrom(tokens), 0, 12).Draw(rt, label) {
		b.WriteString(tok)
	}
	return b.Bytes()
}

// TestSplitSignatureRoundTripsRawBytes proves REQ-verify-raw-bytes as a
// for-all property: for a commit or tag written as git writes one —
// headers continued over lines, a signature header block anywhere
// among the headers, the alternate form's block beside it, a message
// of lines shaped like headers and signature openings, carriage
// returns, and a final line with or without its newline — the split
// returns exactly the bytes git verifies: the object less the
// signature blocks, and the signature's lines as git hands them on.
// Any reading that normalizes — a dropped return, a completed line,
// a trimmed continuation — breaks the equality and would verify
// bytes the origin never signed.
func TestSplitSignatureRoundTripsRawBytes(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		format := rapid.SampledFrom([]ObjectFormat{SHA1, SHA256}).Draw(rt, "format")
		hex40 := rapid.StringMatching(`[0-9a-f]{40}`)
		person := rapid.StringMatching(`[A-Za-z][A-Za-z ]{0,12}[A-Za-z] <[a-z]{1,8}@[a-z]{1,8}\.com> 17[0-9]{8} \+0000`)
		// A signature's lines: an opening git knows, lines of any
		// bytes but a newline — a space-led or empty line among them,
		// which the header block carries as its own continuation, a
		// carriage return, a NUL, non-ASCII bytes — and a closing;
		// every line newline-terminated, as armor is.
		sigLine := rapid.SliceOfN(rapid.SampledFrom([]byte(" \r\x00\xc3\xa9-=+/ABCabc019")), 0, 40)
		signature := func(opening string) []byte {
			var b bytes.Buffer
			b.WriteString(opening + "\n")
			for i, n := 0, rapid.IntRange(0, 4).Draw(rt, "siglines"); i < n; i++ {
				b.Write(sigLine.Draw(rt, "sigline"))
				b.WriteByte('\n')
			}
			b.WriteString("-----END SIGNATURE-----\n")
			return b.Bytes()
		}
		other := map[ObjectFormat]ObjectFormat{SHA1: SHA256, SHA256: SHA1}[format]

		if rapid.Bool().Draw(rt, "isCommit") {
			var b bytes.Buffer
			b.WriteString("tree " + hex40.Draw(rt, "tree") + "\n")
			for i, n := 0, rapid.IntRange(0, 2).Draw(rt, "parents"); i < n; i++ {
				b.WriteString("parent " + hex40.Draw(rt, "parent") + "\n")
			}
			b.WriteString("author " + person.Draw(rt, "author") + "\n")
			b.WriteString("committer " + person.Draw(rt, "committer") + "\n")
			if rapid.Bool().Draw(rt, "mergetag") {
				b.WriteString("mergetag object " + hex40.Draw(rt, "merged") + "\n type commit\n tag v1\n")
			}
			if rapid.Bool().Draw(rt, "terminated") {
				b.WriteString("\n")
				b.Write(gitMessage(rt, "message"))
			}
			payload := b.Bytes()
			sig := signature("-----BEGIN SIGNED MESSAGE-----")
			starts := headerLineStarts(payload)
			// The block anywhere among the headers, the first line
			// included: git inserts at the header end, and reads it
			// wherever it stands.
			raw := signedCommit(payload, signatureHeaders[format], sig, rapid.IntRange(0, len(starts)-1).Draw(rt, "at"))
			if rapid.Bool().Draw(rt, "dual") {
				// The alternate form's block, anywhere among the headers
				// — beside the selected one included — is cut out of the
				// payload and never selected.
				starts = headerLineStarts(raw)
				raw = signedCommit(raw, signatureHeaders[other], signature("-----BEGIN SIGNED MESSAGE-----"), rapid.IntRange(0, len(starts)-1).Draw(rt, "otherAt"))
			}
			gotPayload, gotSig, err := splitSignature(Object{Commit, format, raw})
			if err != nil {
				t.Fatalf("splitSignature(commit) = %v, want nil\nraw:\n%q", err, raw)
			}
			if !bytes.Equal(gotPayload, payload) {
				t.Fatalf("payload not byte-identical\ngot:\n%q\nwant:\n%q\nraw:\n%q", gotPayload, payload, raw)
			}
			if !bytes.Equal(gotSig, sig) {
				t.Fatalf("signature not byte-identical\ngot:\n%q\nwant:\n%q", gotSig, sig)
			}
			return
		}

		var b bytes.Buffer
		b.WriteString("object " + hex40.Draw(rt, "object") + "\n")
		b.WriteString("type commit\n")
		b.WriteString("tag v" + rapid.StringMatching(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`).Draw(rt, "tagname") + "\n")
		b.WriteString("tagger " + person.Draw(rt, "tagger") + "\n")
		b.WriteString("\n")
		// The signature must open a line: a message ends with its
		// newline, or is empty.
		if msg := gitMessage(rt, "message"); len(msg) > 0 {
			b.Write(msg)
			b.WriteString("\n")
		}
		payload := b.Bytes()
		sig := signature(rapid.SampledFrom([]string{
			"-----BEGIN PGP SIGNATURE-----", "-----BEGIN PGP MESSAGE-----",
			"-----BEGIN SIGNED MESSAGE-----", "-----BEGIN SSH SIGNATURE-----"}).Draw(rt, "opening"))
		if rapid.Bool().Draw(rt, "unterminated") {
			sig = bytes.TrimSuffix(sig, []byte("\n"))
		}
		raw := append(append([]byte(nil), payload...), sig...)
		if rapid.Bool().Draw(rt, "alternate") {
			// An alternate-form header block anywhere among the headers
			// is cut out of the payload and never selected.
			starts := headerLineStarts(raw)
			raw = signedCommit(raw, signatureHeaders[rapid.SampledFrom([]ObjectFormat{SHA1, SHA256}).Draw(rt, "alternateForm")],
				signature("-----BEGIN SIGNED MESSAGE-----"), rapid.IntRange(0, len(starts)-1).Draw(rt, "alternateAt"))
		}
		gotPayload, gotSig, err := splitSignature(Object{Tag, format, raw})
		if err != nil {
			t.Fatalf("splitSignature(tag) = %v, want nil\nraw:\n%q", err, raw)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Fatalf("payload not byte-identical\ngot:\n%q\nwant:\n%q\nraw:\n%q", gotPayload, payload, raw)
		}
		if !bytes.Equal(gotSig, sig) {
			t.Fatalf("signature not byte-identical\ngot:\n%q\nwant:\n%q", gotSig, sig)
		}
	})
}

// The split keeps every byte, so what git verifies verifies
// (REQ-verify-raw-bytes): the objects git wrote and signed verbatim
// — a commit and a tag whose messages carry carriage returns, a
// commit whose final line has no newline — verify under their key as
// `git verify-commit` and `git verify-tag` verify them, the payload
// the object less its signature block; and a byte inserted into a
// signed object stays, so the signature no longer verifies — a split
// dropping it would verify the changed object as the signed one.
func TestSplitKeepsEveryByte(t *testing.T) {
	keys := PinnedSSH(t, string(readFixture(t, "ssh-verbatim-key.pub")))
	returnCommit := readFixture(t, "ssh-verbatim-return-commit.txt")
	unterminated := readFixture(t, "ssh-verbatim-unterminated-commit.txt")
	returnTag := readFixture(t, "ssh-verbatim-return-tag.txt")
	if !bytes.Contains(returnCommit, []byte("\r\n")) || !bytes.Contains(returnTag, []byte("\r\n")) || bytes.HasSuffix(unterminated, []byte("\n")) {
		t.Fatal("the fixtures do not carry the bytes they are named for")
	}
	// cut is the fixture's payload by another reading: the gpgsig
	// header line and the lines opening with a space after it removed
	// by offset.
	cut := func(raw []byte) []byte {
		start := bytes.Index(raw, []byte("\ngpgsig ")) + 1
		end := start
		for {
			end += bytes.IndexByte(raw[end:], '\n') + 1
			if raw[end] != ' ' {
				break
			}
		}
		return append(append([]byte(nil), raw[:start]...), raw[end:]...)
	}
	for _, tt := range []struct {
		name    string
		obj     Object
		payload []byte
	}{
		{"a commit whose message carries carriage returns", Object{Commit, SHA1, returnCommit}, cut(returnCommit)},
		{"a commit whose final line has no newline", Object{Commit, SHA1, unterminated}, cut(unterminated)},
		{"a tag whose message carries carriage returns", Object{Tag, SHA1, returnTag}, returnTag[:bytes.Index(returnTag, []byte("-----BEGIN SSH SIGNATURE-----"))]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			payload, _, err := splitSignature(tt.obj)
			if err != nil {
				t.Fatalf("splitSignature = %v, want nil", err)
			}
			if !bytes.Equal(payload, tt.payload) {
				t.Fatalf("payload = %q, want %q", payload, tt.payload)
			}
			vk, err := VerifyPinned(tt.obj, keys)
			if err != nil {
				t.Fatalf("VerifyPinned = %v, want nil: git verifies this object", err)
			}
			if vk.Fingerprint != keys[0].Fingerprint() {
				t.Fatalf("VerifyPinned = %+v, want the fixture key", vk)
			}
		})
	}
	// A byte inserted in the payload where a reader might drop it —
	// before a newline, at the end — stays: the signature no longer
	// verifies.
	crAt := func(b []byte, i int) []byte {
		return append(append(append([]byte(nil), b[:i]...), '\r'), b[i:]...)
	}
	crBefore := func(b []byte, marker string) []byte {
		i := bytes.Index(b, []byte(marker))
		if i < 0 {
			t.Fatalf("no %q in the object", marker)
		}
		return crAt(b, i)
	}
	sshCommit := readFixture(t, "ssh-fixture-commit.txt")
	sshTag := readFixture(t, "ssh-fixture-tag.txt")
	sshKeys := PinnedSSH(t, string(readFixture(t, "ssh-fixture-key.pub")))
	for _, tt := range []struct {
		name string
		obj  Object
	}{
		{"commit, a carriage return before its first newline", Object{Commit, SHA1, crBefore(sshCommit, "\n")}},
		{"commit, a carriage return in its message", Object{Commit, SHA1, crAt(sshCommit, len(sshCommit)-1)}},
		{"commit, its final newline dropped", Object{Commit, SHA1, bytes.TrimSuffix(sshCommit, []byte("\n"))}},
		{"commit, a newline appended", Object{Commit, SHA1, append(append([]byte(nil), sshCommit...), '\n')}},
		{"tag, a carriage return after its last header", Object{Tag, SHA1, crBefore(sshTag, "\n\n")}},
		{"tag, a carriage return in its message", Object{Tag, SHA1, crBefore(sshTag, "\n-----BEGIN")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := splitSignature(tt.obj); err != nil {
				t.Fatalf("splitSignature = %v, want nil: the object splits, and its bytes are what is verified", err)
			}
			if _, err := VerifyPinned(tt.obj, sshKeys); err == nil || !strings.Contains(err.Error(), "does not verify") {
				t.Fatalf("VerifyPinned(changed object) = %v, want a signature that does not verify", err)
			}
		})
	}
	// A byte inserted within the signature's armor — a carriage return,
	// a second indent on a continuation line, which git hands on with
	// one space cut — leaves the payload as signed: git reports a good
	// signature (git 2.55, ssh-keygen), and so does the verifier.
	indented := func(b []byte) []byte {
		i := bytes.Index(b, []byte("\n "))
		return append(append(append([]byte(nil), b[:i+1]...), ' '), b[i+1:]...)
	}
	for _, tt := range []struct {
		name string
		obj  Object
		sig  string // a fragment the signature must carry as handed on
	}{
		{"commit, a carriage return within its signature", Object{Commit, SHA1, crBefore(sshCommit, "\n -----END")}, "\r\n-----END"},
		{"commit, its signature's second line indented twice", Object{Commit, SHA1, indented(sshCommit)}, "\n U1NIU0lH"},
		{"tag, a carriage return within its signature", Object{Tag, SHA1, crBefore(sshTag, "\n-----END")}, "\r\n-----END"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, sig, err := splitSignature(tt.obj)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(sig, []byte(tt.sig)) {
				t.Fatalf("sig = %q, want %q kept", sig, tt.sig)
			}
			if _, err := VerifyPinned(tt.obj, sshKeys); err != nil {
				t.Fatalf("VerifyPinned = %v, want nil: git verifies this object", err)
			}
		})
	}
	t.Run("a gitsign commit with a carriage return in its message verifies nowhere", func(t *testing.T) {
		raw, tr := loadEmbeddedFixture(t)
		body := bytes.Index(raw, []byte("\n\n")) + 2
		obj := Object{Commit, SHA1, crAt(raw, body+bytes.IndexByte(raw[body:], '\n'))}
		id := Identity{Subject: fixtureSubject, Issuer: fixtureIssuer}
		if _, err := Verify(context.Background(), obj, id, tr, true); err == nil || !strings.Contains(err.Error(), "invalid message digest") {
			t.Fatalf("Verify(carriage-returned fixture) = %v, want the signature over other bytes", err)
		}
	})
	// A second gpgsig header is gathered into the signature as git
	// gathers it, and the signature's rules judge the whole: a second
	// header carrying only whitespace verifies, as git's ssh path
	// verifies it (git 2.55, ssh-keygen); a second block is refused as
	// a signature holding another header line, where git's ssh path
	// verifies by the first block alone.
	secondHeader := func(b []byte, block string) []byte {
		i := bytes.Index(b, []byte("\n\n")) + 1
		return append(append(append([]byte(nil), b[:i]...), block...), b[i:]...)
	}
	t.Run("commit, a second gpgsig header of whitespace", func(t *testing.T) {
		obj := Object{Commit, SHA1, secondHeader(sshCommit, "gpgsig \n")}
		if _, err := VerifyPinned(obj, sshKeys); err != nil {
			t.Fatalf("VerifyPinned = %v, want nil: git verifies this object", err)
		}
	})
	t.Run("commit, its signature block twice", func(t *testing.T) {
		i := bytes.Index(sshCommit, []byte("gpgsig "))
		j := bytes.Index(sshCommit, []byte("\n\n")) + 1
		obj := Object{Commit, SHA1, secondHeader(sshCommit, string(sshCommit[i:j]))}
		if _, err := VerifyPinned(obj, sshKeys); err == nil || !strings.Contains(err.Error(), "more than one armor header line") {
			t.Fatalf("VerifyPinned = %v, want the second block refused", err)
		}
	})
}

// git's remove_signature over a tag's headers, its edges pinned as
// git 2.55 reads them: a header read while a block is open takes the
// block's place and the lines before it stay; a gpgsig-prefixed line
// that is neither header leaves the open block open, so a
// continuation after it extends the block over it; a third block,
// which git writes past what it holds, is refused.
func TestRemoveSignatureHeadersAsGit(t *testing.T) {
	for _, tt := range []struct {
		name, in, want, err string
	}{
		{"one block", "object x\ngpgsig A\n B\ntype commit\n", "object x\ntype commit\n", ""},
		{"two blocks apart", "gpgsig A\n B\ntype commit\ngpgsig-sha256 C\n D\ntag v\n", "type commit\ntag v\n", ""},
		{"a header while a block is open takes its place", "gpgsig A\n B\ngpgsig-sha256 C\n D\ntag v\n", "gpgsig A\n B\ntag v\n", ""},
		{"a gpgsig-prefixed line that is no header leaves the block open", "gpgsig A\ngpgsigfoo B\n C\ntag v\n", "tag v\n", ""},
		{"a gpgsig-prefixed line that is no header outside a block stays", "tag v\ngpgsigfoo B\n C\n", "tag v\ngpgsigfoo B\n C\n", ""},
		{"the message is not read", "tag v\n\ngpgsig A\n B\n", "tag v\n\ngpgsig A\n B\n", ""},
		{"a header at the start", "gpgsig A\ntag v\n", "tag v\n", ""},
		{"a header without a newline", "tag v\ngpgsig A", "tag v\n", ""},
		{"a third block is refused", "gpgsig A\nx\ngpgsig B\ny\ngpgsig C\nz\n", "", "a third signature header"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := removeSignatureHeaders([]byte(tt.in))
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("err = %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}
