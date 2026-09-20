# OpenPGP and SSH signatures against pinned keys

Lands: pb's pinned-key provenance plan

The verification spec states two arms beside gitsign's
(REQ-verify-signature-kind, REQ-verify-pinned-key) and the library
holds neither: the parser ignores the PEM block type and reads every
signature as CMS. The arms dispatch on the block type — `SIGNED
MESSAGE`, `PGP SIGNATURE`, `SSH SIGNATURE` — and verify the two new
kinds against keys the caller pins, offline, reporting the key's
kind and fingerprint and no signed time. Two verifiers enter the
dependency graph with the consumer's yes: the maintained OpenPGP
fork, x/crypto's being frozen and under the advisory
vulncheck-openpgp-advisory tracks, and x/crypto's ssh package, which
verifies the SSH signature format git writes. The synthetic sigstore
gains a key pair of each kind and the builders to sign with them, so
the arms are proven the way the CMS arm is.
