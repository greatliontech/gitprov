# The image verifier's Rekor v2 vector

Lands: when a capture signed against a Rekor v2 log lands under
testdata (scripts/capture-cosign.sh with SIGNING_CONFIG naming the
log) and its bundle verifies through the whole path

The captured cosign vectors (testdata/NOTICE.md) prove the two
carriers against bytes cosign itself wrote: a bundle referrer whose
entry is Rekor v1's `dsse` kind with a signed entry timestamp and an
inclusion proof, and a legacy envelope whose bundle annotation is a
v1 `hashedrekord` — the entry kinds cosign 3.1.3's default and legacy
signs log. One shape remains synthetic: a Rekor v2 entry — an
inclusion proof under a checkpoint whose origin is the log's host,
no signed entry timestamp, the time a timestamp's. The default
signing configuration sigstore's TUF served at the capture
(`signing_config.v0.2.json`) named only the v1 log
(`rekor.sigstore.dev`), though the trusted root of the day already
carried the v2 log's key (`log2025-1.rekor.sigstore.dev`) and TUF's
other target, `signing_config_rekor_v2.v0.2.json`, names the v2 log
with v1 as fallback; cosign 3 signs against a v2 log only under a
signing configuration naming it, which the capture script takes as
SIGNING_CONFIG — that TUF target is the one to give. The checkpoint
judgement covers a v2-shaped checkpoint on its own; a real v2 entry
through the whole path waits on that capture.
