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
// false, so callers fail closed.
func HasEmbeddedRekor(obj Object) (bool, error) {
	if err := obj.validate(); err != nil {
		return false, err
	}
	_, sig, err := splitSignature(obj)
	if err != nil {
		return false, err
	}
	_, si, err := parseCMS(sig)
	if err != nil {
		return false, err
	}
	_, err = si.UnsignedAttrs.GetOnlyAttributeValueBytes(oidRekorTransparencyLogEntry)
	return err == nil, nil
}
