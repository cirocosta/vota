# Security Model and Limitations

Vota demonstrates one way to combine poll-local linkable ring proofs,
one-hot encrypted ballots, threshold decryption, and a signed public history.
It has no independent security audit and is not suitable for real elections or
other consequential decisions.

The current design-review gate is recorded in `design-review.md`. No
security-reviewed release claim is permitted while that gate remains open.

## What the implementation verifies

- The administrator signs an immutable manifest containing choices, the full
  eligible ring, trustee commitments, thresholds, and the voting window.
- An enrollment proves possession of one Ristretto255 eligibility scalar and
  binds its public key to one draft ID.
- A ballot proves that its encrypted vector contains exactly one selected
  position and that one member of the manifest ring authorized it.
- A ballot link tag rejects a conflicting second ballot made with the same
  eligibility scalar in the ordinary poll-local identity workflow.
- Trustees prove aggregate decryption shares and sign them with keys committed
  by the manifest.
- Offline audit replay verifies every included ballot and trustee proof,
  object-to-event binding, aggregate, threshold tally, and collector checkpoint.

## Explicit limitations

- Ring membership hides which eligible key signed, not network metadata. The
  centralized collector can observe IP addresses, timing, and submission size.
  Vota provides no anonymous transport.
- Eligibility decisions and real-world identity checks happen out of band. An
  administrator can omit people, enroll controlled keys, or distribute
  different draft information before freeze.
- Per-poll identity files reduce accidental cross-poll reuse. The protocol
  cannot stop a participant from deliberately enrolling the same eligibility
  scalar in multiple polls. Such reuse produces the same link tag and links
  participation.
- A trustee quorum can decrypt individual ballot ciphertexts by writing tools
  outside Vota. The supported CLI creates shares only for a closed aggregate;
  cryptography cannot enforce that policy against colluding key holders.
- Published totals can reveal a choice in a small or unanimous poll. The
  privacy threshold suppresses tally publication below a configured ballot
  count, but it does not provide differential privacy.
- The collector can censor, delay, or fork views. Signed receipts and
  checkpoint comparison can expose inconsistent histories when participants
  compare records; they do not guarantee inclusion or availability.
- Endpoint compromise, screen capture, swap, terminal recording, malware, or a
  malicious random source can reveal choices or keys.
- The cryptographic construction is educational and Vota-specific. It is not
  wire-compatible with Monero, ElectionGuard, or another voting system.

## Key handling

Administrator, voter, and trustee key files use Argon2id plus
XChaCha20-Poly1305 envelopes with role tags and owner-only permissions. Trustee
ceremony shares use fresh X25519 ephemeral keys, HKDF-SHA-256, and
XChaCha20-Poly1305 authenticated encryption for each recipient.

Terminal passphrase, token, and voter choice readers disable echo. File
descriptor input exists for automation. The CLI defines no passphrase, token,
private-key, or choice value flags.

The collector checkpoint key is different: the process must unlock it without
an interactive passphrase, so Vota stores it as a strict owner-only file. Host
access exposes that key and permits forged future checkpoints, receipts, and
tally signatures.

## Supported assurance

Committed deterministic vectors cover ring proofs, election proofs, manifests,
audit records, and receipts. Tests mutate proofs and artifacts, fuzz binary
parsers and verifiers, exercise concurrent uniqueness constraints, run a live
subprocess election, and replay its public record offline. These are regression
controls, not a security proof or external review.
