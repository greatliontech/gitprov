# OpenPGP signatures against pinned keys

Lands: pb's pinned-key provenance plan

The verification spec states two arms beside gitsign's
(REQ-verify-pinned-key), selected by the signature's kind
(REQ-verify-signature-kind). The SSH arm is built: VerifyPinned
verifies the SSH signature envelope git writes against pinned SSH
keys over x/crypto's ssh package, and the synthetic sigstore signs
with SSH keys of its own. The OpenPGP arm is not: VerifyPinned
refuses an OpenPGP signature and ParsePinnedKey an OpenPGP key,
each naming no verifier. The arm verifies an OpenPGP signature
against pinned armored public keys, offline, reporting the key's
kind and fingerprint and no signed time, over the maintained
OpenPGP fork — x/crypto's being frozen and under the advisory
vulncheck-openpgp-advisory tracks — which enters the dependency
graph with the consumer's yes, given; the synthetic sigstore gains
an OpenPGP key pair and the builder to sign with it, so the arm is
proven the way the others are.
