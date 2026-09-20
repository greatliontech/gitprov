package gitprov

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The digest is compared as bytes, the algorithm as a string.
func TestParseDigest(t *testing.T) {
	alg, sum, err := parseDigest("sha256:" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	if err != nil || alg != "sha256" || len(sum) != 32 {
		t.Fatalf("parseDigest = %q %d %v", alg, len(sum), err)
	}
	for _, bad := range []string{"", "sha256", "sha256:", ":abcd", "sha256:zz"} {
		if _, _, err := parseDigest(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
