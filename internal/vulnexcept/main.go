// Command vulnexcept judges govulncheck's JSON stream against a file
// of standing exceptions, each an advisory id with an expiry date and
// a reason: an advisory that reaches the module's own code at call
// level fails the check unless an unexpired exception names it, an
// exception that has expired fails the check, and an exception naming
// an advisory the scan no longer reports fails it too, so a standing
// exception is re-examined when its date comes and removed when its
// advisory goes; nothing is ever silenced. Advisories the scan reports
// at package or module level only are not judged, as govulncheck's own
// verdict does not count them.
//
// The stream is govulncheck's `-format json` output on standard input;
// the exceptions file's lines are `<id> until <YYYY-MM-DD> <reason>`,
// blank lines and `#` comments skipped. Exit status 1 on a failing
// verdict, 2 on unreadable input.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

func main() {
	path := flag.String("exceptions", "vulncheck.exceptions", "the exceptions file")
	flag.Parse()
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vulnexcept:", err)
		os.Exit(2)
	}
	defer f.Close()
	ok, err := run(os.Stdin, f, time.Now(), os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vulnexcept:", err)
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}

// exception is one standing exception: the advisory it excuses, the
// last day (YYYY-MM-DD, UTC) it excuses it, and why it stands.
type exception struct {
	id     string
	until  string
	reason string
}

// parseExceptions reads the file's lines; a line that is not
// `<id> until <YYYY-MM-DD> <reason>`, or an id named twice, is an
// error, never a silent skip.
func parseExceptions(r io.Reader) ([]exception, error) {
	var out []exception
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != "until" {
			return nil, fmt.Errorf("exceptions line %d: want `<id> until <YYYY-MM-DD> <reason>`, got %q", n, line)
		}
		if _, err := time.Parse("2006-01-02", fields[2]); err != nil {
			return nil, fmt.Errorf("exceptions line %d: %w", n, err)
		}
		if seen[fields[0]] {
			return nil, fmt.Errorf("exceptions line %d: %s named twice", n, fields[0])
		}
		seen[fields[0]] = true
		out = append(out, exception{id: fields[0], until: fields[2], reason: strings.Join(fields[3:], " ")})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// message is the part of a govulncheck JSON message the judgement
// reads: the scan's configuration (its presence proves a scan ran,
// its level that symbols were judged), an advisory's summary, and a
// finding's advisory and trace.
type message struct {
	Config *struct {
		ScanLevel string `json:"scan_level"`
	} `json:"config"`
	OSV     *struct{ ID, Summary string } `json:"osv"`
	Finding *struct {
		OSV   string `json:"osv"`
		Trace []struct {
			Function string `json:"function"`
		} `json:"trace"`
	} `json:"finding"`
}

// called are the advisories the scan reports at call level — a
// finding whose trace opens at a function, govulncheck's own rule for
// an advisory that affects the code — with their summaries, in id
// order. A stream without a scan configuration, or one scanned below
// symbol level (where no finding could open at a function), is
// refused: it can judge nothing.
func called(stream io.Reader) (ids []string, summary map[string]string, err error) {
	summary = map[string]string{}
	reached := map[string]bool{}
	scanned := false
	dec := json.NewDecoder(stream)
	for {
		var m message
		if err := dec.Decode(&m); err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("govulncheck stream: %w", err)
		}
		switch {
		case m.Config != nil:
			if m.Config.ScanLevel != "symbol" {
				return nil, nil, fmt.Errorf("govulncheck stream: scan level %q, want symbol: no finding could name a called function", m.Config.ScanLevel)
			}
			scanned = true
		case m.OSV != nil:
			summary[m.OSV.ID] = m.OSV.Summary
		case m.Finding != nil && len(m.Finding.Trace) > 0 && m.Finding.Trace[0].Function != "":
			reached[m.Finding.OSV] = true
		}
	}
	if !scanned {
		return nil, nil, errors.New("govulncheck stream: no scan configuration; was govulncheck run with -format json?")
	}
	for id := range reached {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, summary, nil
}

// run judges the stream against the exceptions at the given day and
// reports every advisory and exception, returning whether the check
// passes: every called advisory excused by an unexpired exception, no
// exception expired, no exception without its advisory.
func run(stream, exceptions io.Reader, now time.Time, out io.Writer) (bool, error) {
	excs, err := parseExceptions(exceptions)
	if err != nil {
		return false, err
	}
	ids, summary, err := called(stream)
	if err != nil {
		return false, err
	}
	byID := map[string]exception{}
	for _, e := range excs {
		byID[e.id] = e
	}
	ok := true
	// Days compare as their spelling: an exception excuses through
	// its last day, UTC, and fails from the next.
	day := now.UTC().Format("2006-01-02")
	for _, id := range ids {
		e, excused := byID[id]
		switch {
		case !excused:
			ok = false
			fmt.Fprintf(out, "RED     %s: %s — reaches this module's code; no exception names it\n", id, summary[id])
		case day > e.until:
			ok = false
			fmt.Fprintf(out, "RED     %s: %s — exception expired %s (today %s): %s\n", id, summary[id], e.until, day, e.reason)
		default:
			fmt.Fprintf(out, "excused %s: %s — until %s: %s\n", id, summary[id], e.until, e.reason)
		}
	}
	for _, e := range excs {
		if !slices.Contains(ids, e.id) {
			ok = false
			fmt.Fprintf(out, "RED     %s: the scan no longer reports it at call level; remove the exception\n", e.id)
		}
	}
	if ok {
		fmt.Fprintf(out, "vulncheck: pass (advisories reached: %d, all excused)\n", len(ids))
	} else {
		fmt.Fprintln(out, "vulncheck: fail")
	}
	return ok, nil
}
