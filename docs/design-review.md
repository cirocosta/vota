# Cryptographic Design Review Status

No independent cryptographic design review has been completed for Vota.

This blocks any release claim that Vota is security-reviewed or suitable for a
real election. It does not block local educational builds labeled
`vota-v1-experimental`.

A future review must cover, at minimum:

- LSAG transcript construction, hash-to-group use, linkability, and anonymity
  assumptions.
- Enrollment possession proofs and the operational risk of eligibility scalar
  reuse across polls.
- One-hot ballot proofs, aggregate formation, threshold share proofs, and
  bounded discrete-log tally recovery.
- Distributed ceremony authentication, encrypted share delivery, complaint
  handling, and malicious-dealer behavior.
- Canonical encoding, domain separation, artifact binding, audit replay, and
  collector equivocation detection.
- Endpoint, metadata, small-poll, administrator, trustee-collusion, and key
  lifecycle limitations documented in `security.md`.

Findings must be recorded with reproducible evidence. Unresolved findings stay
visible; tests or warnings must not be weakened to obtain approval.
