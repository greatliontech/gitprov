package gitprov

// HasEmbeddedRekor reports whether the object's signature carries an
// embedded Rekor TransparencyLogEntry in its CMS unsigned attributes —
// i.e. the signer used gitsign's offline Rekor mode
// (REQ-detect-embedded). Present means the proof is offline-verifiable
// via Verify with transparency required; absent means the signature is
// from gitsign's default online mode, whose legacy Rekor entry is not
// offline-verifiable, so a transparency-requiring caller must reject
// the object — and never query Rekor to recover it.
//
// It establishes NO trust and performs NO verification — it only
// inspects for the attribute's presence, so consumers can produce a
// precise unverifiable-versus-invalid diagnosis. An unsigned or
// structurally malformed object returns an error rather than answering
// false, so callers fail closed; so does an object signed by a
// signature of another kind (ErrSignatureKind), which carries no
// sigstore attribute to inspect.
func HasEmbeddedRekor(obj Object) (bool, error) {
	if err := obj.validate(); err != nil {
		return false, err
	}
	_, sig, err := splitSignature(obj)
	if err != nil {
		return false, err
	}
	// Only a sigstore signature can carry the attribute; a signature
	// of another kind is ErrSignatureKind, never false
	// (REQ-verify-signature-kind, REQ-detect-embedded).
	der, err := sigstoreSignature(sig)
	if err != nil {
		return false, err
	}
	si, err := parseCMS(der)
	if err != nil {
		return false, err
	}
	_, err = si.UnsignedAttrs.GetOnlyAttributeValueBytes(oidRekorTransparencyLogEntry)
	return err == nil, nil
}
