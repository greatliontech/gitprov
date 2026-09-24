# Issues

Tracked deferrals carrying a `Lands:` trigger. On resolution, the
load-bearing rationale is promoted into a kept-current artifact and the
issue file deleted — git holds history.

| Issue | Summary | Lands |
|---|---|---|
| [cosign-captured-vectors](cosign-captured-vectors.md) | the image verifier is proven on captured cosign carriers with Rekor v1 entries; a Rekor v2 entry waits on a capture under a signing configuration naming the v2 log | when a capture signed against a Rekor v2 log lands under testdata and its bundle verifies |
| [vulncheck-openpgp-advisory](vulncheck-openpgp-advisory.md) | a standing exception with an expiry excuses GO-2026-5932, x/crypto/openpgp reached through the sigstore modules with no fixed version; every other advisory is fixed | when govulncheck reports no GO-2026-5932 against the graph |
