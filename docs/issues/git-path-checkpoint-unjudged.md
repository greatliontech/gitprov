# The git path does not judge the entry's checkpoint

Lands: user decision

A git object's embedded entry carries an inclusion proof under a
checkpoint. The git path verifies the signed entry timestamp against
the pinned log key and walks the inclusion proof to the root hash the
entry itself states; the checkpoint — the log's signature over that
root hash and the tree size — is never read (cosign's offline entry
verification, `VerifyTLogEntryOffline`, which the path runs). An
entry with a genuine signed entry timestamp verifies whatever its
checkpoint holds: an empty envelope, a signature by no pinned key, a
root hash or size that is not the proof's. The image bundle path
judges the checkpoint, through sigstore-go's verifier; the spec's
REQ-verify-embedded-rekor states the git path's contract as it is.

The fork:

- Judge the checkpoint on the git path as the bundle path does: its
  signature by the pinned log key, its root hash the proof's, its
  size the proof's tree size. What it adds over the signed entry
  timestamp is a signed tree state: the timestamp is the log's
  promise to include, the checkpoint its witness that it did. It
  flips the verdict on exactly the entries above — a checkpoint that
  does not verify, accepted today, refused then; the repository's
  captured gitsign entry carries a consistent, signed checkpoint and
  verifies under either arm, and no entry of the refused class has
  been shown in the wild. The synthetic fixtures' checkpoints are
  sigstore-go's virtual log's, signed over a tree size of 42 against
  proofs of size 2, so `sigstoretest` would issue its own checkpoints
  from a Rekor key of its own, as it issues its own leaves.
- Keep cosign's offline semantics: the signed entry timestamp the
  anchor, the inclusion proof a consistency check, the checkpoint
  carried but unjudged, as gitsign's own verifier and cosign's
  offline mode treat it.

The externally visible tradeoff is what a verified identity proves
about the log — a promise to include, or an inclusion witnessed under
a signed tree state — and, under the first arm, the refusal of
entries whose checkpoint does not verify, a class no capture shows
but the contract would newly name.
