package gitprov

import (
	"flag"
	"os"
	"testing"
)

// TestMain pins rapid's PRNG seed (unless the caller set one
// explicitly) and disables its failure-file persistence. The property
// tests double as mutation-testing oracles, and an oracle must be
// deterministic and side-effect-free: with rapid's default per-run
// random seed, a property kills a mutant only when the draw happens to
// reach it, and a failing property would persist a fail file under
// testdata/rapid/ that later oracle runs replay — both make the
// run-to-run verdict flip. Reproduction is unaffected: the seed is
// fixed, so a failure replays by just re-running the test.
func TestMain(m *testing.M) {
	flag.Parse()
	if f := flag.Lookup("rapid.seed"); f != nil && f.Value.String() == "0" {
		if err := flag.Set("rapid.seed", "1"); err != nil {
			panic(err)
		}
	}
	if flag.Lookup("rapid.nofailfile") != nil {
		if err := flag.Set("rapid.nofailfile", "true"); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}
