package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const (
	config  = `{"config":{"scanner_name":"govulncheck","scan_level":"symbol"}}` + "\n"
	osvA    = `{"osv":{"id":"GO-1","summary":"A is unsafe"}}` + "\n"
	osvB    = `{"osv":{"id":"GO-2","summary":"B overflows"}}` + "\n"
	calledA = `{"finding":{"osv":"GO-1","trace":[{"module":"m","package":"p","function":"F"}]}}` + "\n"
	calledB = `{"finding":{"osv":"GO-2","trace":[{"module":"m","package":"p","function":"G"}]}}` + "\n"
	// Findings govulncheck reports at module and package level only,
	// which its own verdict does not count.
	moduleB  = `{"finding":{"osv":"GO-2","trace":[{"module":"m","version":"v1"}]}}` + "\n"
	packageB = `{"finding":{"osv":"GO-2","trace":[{"module":"m","package":"p"}]}}` + "\n"
)

var day = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// The verdict: a called advisory needs an unexpired exception; an
// expired exception, an exception the scan no longer matches, and a
// called advisory without one each fail; package- and module-level
// findings are not judged; the exception's last day still excuses.
func TestVerdict(t *testing.T) {
	for _, tt := range []struct {
		name, stream, exceptions string
		now                      time.Time
		pass                     bool
		out                      []string // fragments the report must carry
	}{
		{"nothing reached, no exceptions", config + osvA, "", day, true, []string{"pass (advisories reached: 0"}},
		{"reached, excused", config + osvA + calledA, "GO-1 until 2026-12-31 vendored reach", day, true, []string{"excused GO-1: A is unsafe — until 2026-12-31: vendored reach", "pass (advisories reached: 1"}},
		{"reached, no exception", config + osvA + calledA, "", day, false, []string{"RED     GO-1: A is unsafe — reaches", "fail"}},
		{"reached, another advisory's exception", config + osvA + calledA, "GO-2 until 2026-12-31 x", day, false, []string{"RED     GO-1", "RED     GO-2: the scan no longer reports it", "fail"}},
		{"exception on its last day", config + osvA + calledA, "GO-1 until 2026-09-24 x", time.Date(2026, 9, 24, 23, 59, 59, 999999999, time.UTC), true, []string{"excused GO-1"}},
		{"the day is UTC's, not the clock's zone", config + osvA + calledA, "GO-1 until 2026-09-24 x", time.Date(2026, 9, 25, 1, 0, 0, 0, time.FixedZone("east", 3*3600)), true, []string{"excused GO-1"}},
		{"exception expired the day after", config + osvA + calledA, "GO-1 until 2026-09-24 x", time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC), false, []string{"RED     GO-1: A is unsafe — exception expired 2026-09-24 (today 2026-09-25): x", "fail"}},
		{"stale exception", config + osvA, "GO-1 until 2026-12-31 x", day, false, []string{"RED     GO-1: the scan no longer reports it at call level; remove the exception", "fail"}},
		{"module- and package-level findings are not judged", config + osvB + moduleB + packageB, "", day, true, []string{"pass (advisories reached: 0"}},
		{"two reached, one excused", config + osvA + osvB + calledA + calledB + moduleB, "GO-1 until 2026-12-31 x", day, false, []string{"excused GO-1", "RED     GO-2: B overflows — reaches", "fail"}},
		{"comments and blank lines", config + osvA + calledA, "# standing\n\nGO-1 until 2026-12-31 x\n", day, true, []string{"excused GO-1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			ok, err := run(strings.NewReader(tt.stream), strings.NewReader(tt.exceptions), tt.now, &out)
			if err != nil {
				t.Fatalf("run = %v", err)
			}
			if ok != tt.pass {
				t.Fatalf("pass = %v, want %v\n%s", ok, tt.pass, out.String())
			}
			for _, frag := range tt.out {
				if !strings.Contains(out.String(), frag) {
					t.Fatalf("report lacks %q:\n%s", frag, out.String())
				}
			}
		})
	}
}

// Unreadable input is an error, never a verdict: a stream without a
// scan, a broken stream, a malformed exceptions line, a bad date, an
// id named twice.
func TestUnreadableInput(t *testing.T) {
	for _, tt := range []struct {
		name, stream, exceptions, want string
	}{
		{"no scan in the stream", osvA + calledA, "", "no scan configuration"},
		{"empty stream", "", "", "no scan configuration"},
		{"a scan below symbol level", `{"config":{"scan_level":"package"}}` + "\n" + osvA + packageB, "", `scan level "package", want symbol`},
		{"broken stream", config + `{"osv":`, "", "govulncheck stream"},
		{"malformed line", config, "GO-1 2026-12-31 x", "line 1: want"},
		{"no reason", config, "GO-1 until 2026-12-31", "line 1: want"},
		{"bad date", config, "GO-1 until 2026-13-01 x", "line 1"},
		{"named twice", config, "GO-1 until 2026-12-31 x\nGO-1 until 2027-01-01 y", "line 2: GO-1 named twice"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(strings.NewReader(tt.stream), strings.NewReader(tt.exceptions), day, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run = %v, want %q", err, tt.want)
			}
		})
	}
}
