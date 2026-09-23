# The split refuses objects git verifies

Lands: when the split keeps every byte of an object — a commit or
tag whose message carries a carriage return, or a commit lacking
its final newline, verifying as git verifies it

The split reads an object line by line (gitsign's SplitCommit and
SplitTag) and rebuilds the payload: a carriage return before a
newline is dropped, a final line without its newline completed. The
verifier holds the split to the raw bytes by requiring its join to
reproduce them (REQ-verify-raw-bytes, object.go) and refuses the
object otherwise, so no object verifies over bytes other than its
own. The refusal fails closed on objects git itself verifies: git
keeps a return in a message as content, and `git verify-commit` and
`git verify-tag` report a good signature over one; a commit's
message may also lack its final newline and verify (a tag's may
not: its in-body signature must open a line, so git finds none
there, as the split does). Verifying them needs a split that keeps every
byte — git's own header and continuation rules over the raw bytes,
the signature's lines cut out and nothing else touched — which is
its own design against the raw-bytes contract, not a guard.
