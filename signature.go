package gitprov

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
)

// SignatureKind is what signed a git object, selected by the label of
// the signature's armor header line (REQ-verify-signature-kind):
// gitsign's CMS under SIGNED MESSAGE, an OpenPGP signature under PGP
// SIGNATURE, an SSH signature under SSH SIGNATURE. The kind selects the
// verifier and nothing else does: a verification of one kind handed a
// signature of another fails with ErrSignatureKind rather than reading
// the bytes as its own.
type SignatureKind string

const (
	// Sigstore is gitsign's CMS signature, verified by Verify against a
	// trusted root.
	Sigstore SignatureKind = "sigstore"
	// OpenPGP is an OpenPGP signature, verified against pinned keys.
	OpenPGP SignatureKind = "openpgp"
	// SSH is an SSH signature, verified against pinned keys.
	SSH SignatureKind = "ssh"
)

// ErrSignatureKind marks a signature of a kind other than the one the
// verification takes: the object is signed, and by a signature its
// header line states, but this verifier does not read that kind. A
// caller routing by kind selects the verifier with SignatureKindOf
// before verifying.
var ErrSignatureKind = errors.New("gitprov: the signature is not of the kind this verification takes")

// The armor frame every kind shares: a header line opening the block
// under a label, a footer line closing it under the same. The three
// armors differ between the lines — gitsign's and the SSH one are PEM,
// OpenPGP's carries armor headers and a checksum line no PEM decoder
// reads — so the frame is read here and the body by each kind's own
// decoder.
const (
	armorBegin = "-----BEGIN "
	armorEnd   = "-----END "
	armorClose = "-----"

	sigstoreLabel = "SIGNED MESSAGE"
	openPGPLabel  = "PGP SIGNATURE"
	sshLabel      = "SSH SIGNATURE"
)

// labelKinds maps a header line's label to the signature kind it states.
var labelKinds = map[string]SignatureKind{
	sigstoreLabel: Sigstore,
	openPGPLabel:  OpenPGP,
	sshLabel:      SSH,
}

// SignatureKindOf reports the kind of the object's signature at its
// form's location (REQ-verify-signature-kind), establishing no trust:
// it reads the armor frame alone, never the body — whether the body
// decodes as the kind states is the verifier's check. An unsigned or
// malformed object, a signature that is not exactly one armored block,
// and a label naming no kind each fail closed.
func SignatureKindOf(obj Object) (SignatureKind, error) {
	if err := obj.validate(); err != nil {
		return "", err
	}
	_, sig, err := splitSignature(obj)
	if err != nil {
		return "", err
	}
	return signatureFrame(sig)
}

// signatureFrame reads the armored block's frame and returns the kind
// its label states. The signature is exactly one block: it begins with
// its header line — git stores a signature from that line on, and
// bytes before one are no signature — ends with the matching footer
// line with nothing but whitespace after it, and holds no other header
// or footer line, so no decoder can find a block other than the one
// the label names. It is the one reader of the frame; each kind's
// decoder takes a signature whose frame passed.
func signatureFrame(sig []byte) (SignatureKind, error) {
	if !bytes.HasPrefix(sig, []byte(armorBegin)) {
		return "", errors.New("gitprov: the signature does not begin with an armor header line")
	}
	line, _, _ := bytes.Cut(sig, []byte("\n"))
	label, ok := bytes.CutSuffix(line[len(armorBegin):], []byte(armorClose))
	if !ok {
		return "", errors.New("gitprov: the signature's armor header line is malformed")
	}
	kind, ok := labelKinds[string(label)]
	if !ok {
		return "", fmt.Errorf("gitprov: signature label %q names no signature kind", label)
	}
	// A header or footer line opens a line: the marker text within a
	// line — an OpenPGP armor header may carry it — is no line.
	if bytes.Count(sig, []byte("\n"+armorBegin)) != 0 {
		return "", errors.New("gitprov: the signature holds more than one armor header line")
	}
	footer := []byte(armorEnd + string(label) + armorClose)
	i := bytes.LastIndex(sig, footer)
	if i < 0 || sig[i-1] != '\n' {
		return "", errors.New("gitprov: the signature has no armor footer line matching its header")
	}
	if len(bytes.Trim(sig[i+len(footer):], asciiSpace)) != 0 {
		return "", errors.New("gitprov: the signature carries bytes beside its armored block")
	}
	if bytes.Count(sig, []byte("\n"+armorEnd)) != 1 {
		return "", errors.New("gitprov: the signature holds more than one armor footer line")
	}
	return kind, nil
}

// asciiSpace is the whitespace admitted after the footer line: ASCII,
// as git and the PEM decoder read it, never Unicode's.
const asciiSpace = " \t\r\n\v\f"

// sigstoreSignature is the CMS DER of a signature whose label states
// gitsign's kind: the frame read, the one PEM block decoded. A
// signature of another kind is ErrSignatureKind; a body that is no
// PEM block fails closed.
func sigstoreSignature(sig []byte) ([]byte, error) {
	kind, err := signatureFrame(sig)
	if err != nil {
		return nil, err
	}
	if kind != Sigstore {
		return nil, fmt.Errorf("%w: a %s signature, not a sigstore one", ErrSignatureKind, kind)
	}
	// The frame admits one block beginning at the first byte, so the
	// first block the decoder finds is the labelled one or none.
	blk, _ := pem.Decode(sig)
	if blk == nil {
		return nil, errors.New("gitprov: the sigstore signature's body does not decode as a PEM block")
	}
	return blk.Bytes, nil
}

// armorSigstore renders CMS DER as the one PEM block gitsign's verifier
// is handed. That verifier decodes the first PEM block it finds
// anywhere in its input and reads bare bytes as DER otherwise, so DER
// carrying armor text within it — inside an unsigned attribute, say —
// would have it verify a block other than the signature in hand; a
// fresh armoring's base64 can hold no other block.
func armorSigstore(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: sigstoreLabel, Bytes: der})
}
