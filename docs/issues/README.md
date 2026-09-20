# Issues

Tracked deferrals carrying a `Lands:` trigger. On resolution, the
load-bearing rationale is promoted into a kept-current artifact and the
issue file deleted — git holds history.

| Issue | Summary | Lands |
|---|---|---|
| [cosign-captured-vectors](cosign-captured-vectors.md) | the image verifier is proven on synthetic fixtures; a carrier cosign wrote and a Rekor v2 entry (the checkpoint-origin rule) wait on real captures | when a cosign-signed image's carriers are captured under testdata with their trusted root |
| [vulncheck-openpgp-advisory](vulncheck-openpgp-advisory.md) | the vulnerability check stays red on GO-2026-5932, x/crypto/openpgp reached through the sigstore modules with no fixed version; every other advisory is fixed | when govulncheck reports no GO-2026-5932 against the graph |
| [git-path-checkpoint-unjudged](git-path-checkpoint-unjudged.md) | the git path anchors an embedded entry on its signed entry timestamp and walks the proof to the root hash the entry states, the checkpoint unjudged; the bundle path judges it | user decision |
