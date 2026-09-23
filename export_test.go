package gitprov

import "testing"

// The internal test helpers the external test package shares, so the
// fixtures and object builders are spelled once.
var (
	MinimalTagPayload    = minimalTagPayload
	MinimalCommitPayload = minimalCommitPayload
	CommitSignedWith     = commitSignedWith
	ReadFixture          = readFixture
	PGPArmor             = pgpArmor
)

// PinnedSSH parses the lines as pinned SSH keys, failing the test on
// any it cannot.
func PinnedSSH(t *testing.T, lines ...string) []PinnedKey {
	t.Helper()
	keys := make([]PinnedKey, 0, len(lines))
	for _, l := range lines {
		k, err := ParsePinnedKey(SSH, l)
		if err != nil {
			t.Fatalf("ParsePinnedKey: %v", err)
		}
		keys = append(keys, k)
	}
	return keys
}
