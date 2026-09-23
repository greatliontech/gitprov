# Issues

Tracked deferrals carrying a `Lands:` trigger. On resolution, the
load-bearing rationale is promoted into a kept-current artifact and the
issue file deleted — git holds history.

| Issue | Summary | Lands |
|---|---|---|
| [cosign-captured-vectors](cosign-captured-vectors.md) | the image verifier is proven on synthetic fixtures; a carrier cosign wrote and a Rekor v2 entry (the checkpoint-origin rule) wait on real captures | when a cosign-signed image's carriers are captured under testdata with their trusted root |
| [vulncheck-openpgp-advisory](vulncheck-openpgp-advisory.md) | the vulnerability check stays red on GO-2026-5932, x/crypto/openpgp reached through the sigstore modules with no fixed version; every other advisory is fixed | when govulncheck reports no GO-2026-5932 against the graph |
| [split-refuses-git-valid-objects](split-refuses-git-valid-objects.md) | the line-reading split is held to the raw bytes by its join and refuses what it cannot reproduce, among them objects git verifies: a message with a carriage return, a commit with no final newline | when the split keeps every byte of such an object and it verifies |
