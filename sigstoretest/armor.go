package sigstoretest

import (
	"regexp"
	"strings"
	"testing"
)

// BlankEdge spells an armored block with one line the armor decoder
// would trim: a body line padded with a trailing blank, an indented
// copy of the footer line followed by a line of junk before the
// footer itself, or the checksum line indented and followed by junk
// — each read as written is unreadable.
func BlankEdge(t testing.TB, block, where string) string {
	t.Helper()
	footer := regexp.MustCompile(`(?m)^-----END [A-Z ]+-----`).FindString(block)
	if footer == "" {
		t.Fatal("no footer line in the block")
	}
	var re *regexp.Regexp
	var repl string
	switch where {
	case "trailing":
		re, repl = regexp.MustCompile(`(?m)^([A-Za-z0-9+/]{16,}=*)$`), "$1 "
	case "footer":
		re, repl = regexp.MustCompile(`(?m)^(-----END [A-Z ]+-----)`), "  $1\njunk\n$1"
	case "checksum":
		re, repl = regexp.MustCompile(`(?m)^(=[A-Za-z0-9+/]{4})$`), " $1\njunk"
	default:
		t.Fatalf("unknown edge %q", where)
	}
	loc := re.FindStringIndex(block)
	if loc == nil {
		t.Fatalf("no line to edge for %q", where)
	}
	return block[:loc[0]] + re.ReplaceAllString(block[loc[0]:loc[1]], repl) + block[loc[1]:]
}

// JunkHeader spells an armored block with a line of junk — no colon,
// so no armor header line — right after its header line, followed
// by an indented copy of the header line: the armor decoder would
// read the junk as the headers' end and seek the next header line,
// finding the indented one and passing the junk over.
func JunkHeader(t testing.TB, block string) string {
	t.Helper()
	return afterHeader(t, block, func(header string) string {
		return "JUNK no colon arbitrary bytes\n  " + header + "\n"
	})
}

// LateColonHeader spells an armored block with a header line whose
// colon sits past the decoder's hundred-byte first chunk, followed
// by an indented copy of the header line that carries a colon: the
// decoder, judging the first chunk alone, would read the long line
// as no header line and land on the indented one, passing the long
// line over.
func LateColonHeader(t testing.TB, block string) string {
	t.Helper()
	return afterHeader(t, block, func(header string) string {
		return strings.Repeat("J", 120) + ": colon past the chunk\n  " + header + ": x\n"
	})
}

// afterHeader inserts lines right after the block's header line,
// spelled from it.
func afterHeader(t testing.TB, block string, lines func(header string) string) string {
	t.Helper()
	i := strings.Index(block, "-----BEGIN ")
	if i < 0 {
		t.Fatal("no header line in the block")
	}
	end := strings.Index(block[i:], "\n")
	if end < 0 {
		t.Fatal("no line end after the header line")
	}
	return block[:i+end+1] + lines(block[i:i+end]) + block[i+end+1:]
}
