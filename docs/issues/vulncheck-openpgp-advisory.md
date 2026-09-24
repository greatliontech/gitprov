# The vulnerability check reports an unfixed advisory through sigstore

Lands: when govulncheck reports no GO-2026-5932 against this module's
graph (the sigstore modules no longer reaching x/crypto/openpgp)

GO-2026-5932 declares golang.org/x/crypto/openpgp unmaintained and
unsafe by design, with no fixed version. This module reaches it
through its dependencies, not its own use: rekor's entry
canonicalization and sigstore's PEM and signature helpers call the
armor encoder, and cosign's package initialization the package's.
Every other advisory the check raises, the verbose scan's included,
is fixed by the dependency versions pinned beside this record and
by the module's floor at the standard library's patched release;
the check runs on the current Go release so later patches reach it.

Until upstream drops the package, a standing exception names this
one advisory by id in `vulncheck.exceptions`, with an expiry date
that forces its re-examination; internal/vulnexcept judges the scan
against it. The exposure is stated, not silenced: the exception
excuses no other advisory, an expired exception fails the check, and
so does one whose advisory the scan no longer reports — the day
upstream drops the package, the check goes red until the exception
is removed and this issue closed.
