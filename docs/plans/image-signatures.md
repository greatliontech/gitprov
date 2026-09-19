# Plan: image signatures

Spec: docs/specs/verification.md (the trusted root; offline
verification of a sigstore keyless signature against it, extended
from git objects to a signed OCI digest)

- [ ] 1. The contract: a sigstore bundle or cosign simple-signing
      envelope over an OCI manifest digest verified offline against
      the pinned trusted root — certificate chain, identity, and the
      embedded transparency proof — as the git-object verification
      is, the bytes signed being the envelope's payload
- [ ] 2. The verifier: VerifyEnvelope beside Verify, one identity
      model, one trusted root, with fixtures signed by cosign
