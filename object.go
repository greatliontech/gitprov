package gitprov

import (
	"bytes"
	"fmt"
)

// ObjectKind names the two signable git object kinds.
type ObjectKind string

const (
	Commit ObjectKind = "commit"
	Tag    ObjectKind = "tag"
)

// ObjectFormat names a git object format — the hash algorithm whose
// form the raw bytes are in. It is caller-stated, never inferred from
// the bytes (REQ-verify-object-formats).
type ObjectFormat string

const (
	SHA1   ObjectFormat = "sha1"
	SHA256 ObjectFormat = "sha256"
)

// Object is a git object presented for verification: its kind, the
// object format its raw bytes are in, and the raw object bytes — the
// git-core content after the "<type> <len>\0" header, exactly as git
// hashes it. Any re-encode through an object parser is not raw and
// would verify bytes the origin never signed (REQ-verify-raw-bytes).
type Object struct {
	Kind   ObjectKind
	Format ObjectFormat
	Raw    []byte
}

func (o Object) validate() error {
	switch o.Kind {
	case Commit, Tag:
	default:
		return fmt.Errorf("gitprov: unknown object kind %q", o.Kind)
	}
	switch o.Format {
	case SHA1, SHA256:
	default:
		return fmt.Errorf("gitprov: unknown object format %q", o.Format)
	}
	if len(o.Raw) == 0 {
		return fmt.Errorf("gitprov: empty object")
	}
	return nil
}

// signatureHeaders are the commit headers carrying a signature, by the
// object format whose form each signs (git's hash-function-transition
// rules): gpgsig the SHA-1 form, gpgsig-sha256 the SHA-256 form.
var signatureHeaders = map[ObjectFormat]string{SHA1: "gpgsig", SHA256: "gpgsig-sha256"}

// signatureOpenings are the line openings git reads as the start of a
// tag's in-body signature: the begin markers of the signature formats
// git knows (git 2.55 gpg-interface.c, openpgp_sigs, x509_sigs and
// ssh_sigs). A line opening with one opens a signature.
var signatureOpenings = [][]byte{
	[]byte("-----BEGIN PGP SIGNATURE-----"),
	[]byte("-----BEGIN PGP MESSAGE-----"),
	[]byte("-----BEGIN SIGNED MESSAGE-----"),
	[]byte("-----BEGIN SSH SIGNATURE-----"),
}

// splitSignature extracts the payload the signature covers and the
// signature — the armored block as git stores it, its kind not yet
// read — from the location that signs the form in hand
// (REQ-verify-signature-extraction, git's hash-function-transition
// rules): a commit's gpgsig header signs its SHA-1 form and
// gpgsig-sha256 its SHA-256 form, so the header follows Format; a tag's
// own-form signature is always the in-body trailer, and its
// gpgsig/gpgsig-sha256 headers — alternate-form signatures — are never
// selected. An object with no signature at its form's location is
// unsigned and fails (REQ-verify-fail-closed).
//
// The split is git's own over the raw bytes (REQ-verify-raw-bytes):
// every payload and signature byte is a byte of the object, in the
// object's order, and only the signature's own lines are cut out —
// what git verifies, git's verdict on a commit whose message carries
// a carriage return or lacks its final newline included. A split
// that reads lines and rebuilds the payload verifies other bytes
// than the ones in hand wherever its reading normalizes, and an
// object differing from the signed one by such bytes, and so by its
// id, would verify as it.
func splitSignature(o Object) (payload, sig []byte, err error) {
	if o.Kind == Tag {
		return splitTag(o.Raw)
	}
	return splitCommit(o.Raw, o.Format)
}

// splitCommit is git's parse_buffer_signed_by_header (git 2.55
// commit.c) over the raw bytes, line by line through the headers — a
// line runs to and including its newline, or to the end of the
// object: the form's signature header opens the signature with its
// value after the header's space, and each following line opening
// with a space continues it from after that space; any other header
// opening with "gpgsig" is left out of the payload with the lines
// continuing it; the first empty line and everything after it is
// payload whole, whatever it holds. A second header of the form's
// name is gathered into the same signature, as git gathers it, and
// the signature's own rules judge what that holds
// (REQ-verify-signature-kind): a second block is refused there, a
// second header carrying only whitespace is not, and git's ssh path
// verifies both by the first block.
func splitCommit(raw []byte, format ObjectFormat) (payload, sig []byte, err error) {
	header := []byte(signatureHeaders[format] + " ")
	var inSignature, other, seen bool
	for rest := raw; len(rest) > 0; {
		next := len(rest)
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			next = i + 1
		}
		line := rest[:next]
		var part []byte
		signs := false
		switch {
		case inSignature && line[0] == ' ':
			part, signs = line[1:], true
		case bytes.HasPrefix(line, header):
			seen = true
			part, signs = line[len(header):], true
			other = false
		case bytes.HasPrefix(line, []byte("gpgsig")):
			other = true
		case other && line[0] != ' ':
			other = false
		}
		if signs {
			sig = append(sig, part...)
			inSignature = true
		} else {
			if line[0] == '\n' {
				line, next = rest, len(rest)
			}
			if !other {
				payload = append(payload, line...)
			}
			inSignature = false
		}
		rest = rest[next:]
	}
	if !seen {
		return nil, nil, fmt.Errorf("gitprov: commit is not signed (no %s-form signature)", format)
	}
	return payload, sig, nil
}

// splitTag is git's parse_signature (git 2.55 gpg-interface.c) over
// the raw bytes: the signature opens at the last line opening with a
// begin marker git knows and runs to the end of the object; the
// payload is every byte before it, less the signature headers git's
// remove_signature cuts out — the alternate-form signatures a tag's
// gpgsig and gpgsig-sha256 headers carry, never selected
// (REQ-verify-signature-extraction). No line opens a signature:
// unsigned.
func splitTag(raw []byte) (payload, sig []byte, err error) {
	match := len(raw)
	for i := 0; i < len(raw); {
		line := raw[i:]
		for _, opening := range signatureOpenings {
			if bytes.HasPrefix(line, opening) {
				match = i
				break
			}
		}
		if j := bytes.IndexByte(line, '\n'); j >= 0 {
			i += j + 1
		} else {
			i = len(raw)
		}
	}
	if match == len(raw) {
		return nil, nil, fmt.Errorf("gitprov: tag is not signed")
	}
	payload, err = removeSignatureHeaders(raw[:match])
	if err != nil {
		return nil, nil, fmt.Errorf("gitprov: split tag: %w", err)
	}
	return payload, raw[match:], nil
}

// removeSignatureHeaders is git's remove_signature (git 2.55
// commit.c) over the bytes, line by line through the headers: a
// gpgsig or gpgsig-sha256 header with the lines opening with a space
// after it is one block; git holds two blocks and cuts each out — a
// header read while a block is open takes the block's place, the
// lines read before it left in the payload, and a line opening with
// "gpgsig" that is neither header leaves the open block open. A third
// block is written past the two git holds, where its behavior is
// undefined, and is refused (REQ-verify-raw-bytes).
func removeSignatureHeaders(buf []byte) ([]byte, error) {
	type block struct {
		start, end int
		held       bool
	}
	var blocks [2]block
	current := 0
	inSignature := false
	for i := 0; i < len(buf); {
		next := len(buf)
		if j := bytes.IndexByte(buf[i:], '\n'); j >= 0 {
			next = i + j + 1
		}
		line := buf[i:next]
		switch {
		case inSignature && line[0] == ' ':
			blocks[current].end = next
		case bytes.HasPrefix(line, []byte("gpgsig")):
			for _, format := range []ObjectFormat{SHA1, SHA256} {
				if bytes.HasPrefix(line, []byte(signatureHeaders[format]+" ")) {
					if current == len(blocks) {
						return nil, fmt.Errorf("a third signature header, beyond the two git reads")
					}
					blocks[current] = block{start: i, end: next, held: true}
					inSignature = true
				}
			}
		default:
			if line[0] == '\n' {
				next = len(buf)
			}
			if inSignature && current != len(blocks) {
				current++
			}
			inSignature = false
		}
		i = next
	}
	payload := make([]byte, 0, len(buf))
	from := 0
	for _, b := range blocks {
		if !b.held {
			continue
		}
		payload = append(payload, buf[from:b.start]...)
		from = b.end
	}
	return append(payload, buf[from:]...), nil
}
