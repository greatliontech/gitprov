package gitprov

import (
	"bytes"
	"fmt"

	gitsign "github.com/sigstore/gitsign/pkg/git"
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

// splitSignature extracts the payload the signature covers and the PEM
// CMS signature, from the location that signs the form in hand
// (REQ-verify-signature-extraction, git's hash-function-transition
// rules): a commit's gpgsig header signs its SHA-1 form and
// gpgsig-sha256 its SHA-256 form, so the header follows Format; a tag's
// own-form signature is always the in-body trailer, and its
// gpgsig/gpgsig-sha256 headers — alternate-form signatures — are never
// selected. An object with no signature at its form's location is
// unsigned and fails (REQ-verify-fail-closed).
func splitSignature(o Object) (payload, sig []byte, err error) {
	if o.Kind == Tag {
		ts, err := gitsign.SplitTag(bytes.NewReader(o.Raw))
		if err != nil {
			return nil, nil, fmt.Errorf("gitprov: split tag: %w", err)
		}
		if ts.InBody == nil {
			return nil, nil, fmt.Errorf("gitprov: tag is not signed")
		}
		return ts.Payload, ts.InBody, nil
	}
	cs, err := gitsign.SplitCommit(bytes.NewReader(o.Raw))
	if err != nil {
		return nil, nil, fmt.Errorf("gitprov: split commit: %w", err)
	}
	sig = cs.Gpgsig
	if o.Format == SHA256 {
		sig = cs.GpgsigSha256
	}
	if sig == nil {
		return nil, nil, fmt.Errorf("gitprov: commit is not signed (no %s-form signature)", o.Format)
	}
	return cs.Payload, sig, nil
}
