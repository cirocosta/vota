# Vota v1 Experimental Protocol

Status: implementation contract for educational software. This protocol is not
suitable for real elections.

## Encoding

Public artifacts are JSON canonicalized with RFC 8785 before hashing or signing.
Duplicate object keys, unknown fields, multiple JSON values, non-canonical group
encodings, and artifacts larger than 1 MiB are rejected. Binary values use a
lowercase hexadecimal payload with a type prefix, such as
`ristretto255:<64 hex characters>`.

Each transcript is:

```text
ASCII domain separator || 0x00 || transcript fields
```

Variable-length fields are encoded as an unsigned 64-bit big-endian byte length
followed by the bytes. Fixed-size group elements and scalars use their canonical
32-byte encodings. Lists encode their element count followed by each encoded
element. Implementations must not concatenate ambiguous variable-length fields.

The complete domain registry is the ordered result of
`protocol.DomainSeparators()`. Unknown domains fail closed.

## Poll manifest

The poll ID is SHA-256 over `vota:v1:poll-id`, a zero byte, and the RFC 8785
canonical manifest with `poll_id` and `authority_signature` set to empty strings.
The administrator signs the poll ID and canonical unsigned manifest under
`vota:v1:manifest-signature` using Ed25519.

Eligible Ristretto255 keys are validated, deduplicated, and sorted by canonical
encoded bytes. Every voter uses this exact order. The ring is immutable after
the manifest is signed.

## Enrollment proof

An enrollment proves possession of scalar `x` for public key `P = xG` with a
Schnorr proof bound to the draft poll ID:

```text
k <- random scalar
R = kG
c = Hs(vota:v1:enrollment-proof, draft_poll_id, P, R)
s = k + cx
proof = (R, s)
```

Verification checks `sG = R + cP`.

## Linkable ring proof

Version 1 uses a single-key LSAG-style proof over the complete ring
`P[0..n-1]`. The signer knows `x` and index `j` such that `P[j] = xG`.

The link tag is:

```text
I = x * Hp(vota:v1:ring-hash-to-group, poll_id, P[j])
```

Per-poll keys make this standard link tag poll-local without changing the
linking equation. The ballot choice and encryption randomness are not inputs to
`I`.

The signed message is the ballot hash. Challenges bind protocol, poll ID,
manifest hash, canonical ring hash, ballot hash, `I`, and every reconstructed
`L_i` and `R_i`. Signing follows the closed Schnorr challenge chain from
MRL-0005 section 2.1. Verification reconstructs the full chain and requires the
final challenge to equal the first. All scalar and group encodings are canonical.

## Encrypted choice

For election public key `Y = yG`, each choice position encrypts a bit `m`:

```text
r <- random scalar
A = rG
B = mG + rY
C = (A, B)
```

A disjunctive Chaum-Pedersen proof under `vota:v1:choice-proof` proves that
`m` is zero or one without revealing it. Ciphertexts are homomorphically added,
and a second proof under `vota:v1:choice-sum-proof` proves that the sum of all
positions encrypts exactly one.

The Fiat-Shamir transcript binds the protocol, poll ID, manifest hash, choice
index, election key, ciphertext, and all proof commitments.

## Ballot envelope

The ballot hash is SHA-256 over `vota:v1:ballot-hash`, a zero byte, and the
canonical envelope with `eligibility_proof`, `nullifier`, and `ballot_hash`
empty. The ring proof signs this hash. The final envelope contains ciphertexts,
validity proof, link tag as `nullifier`, ring proof, and ballot hash.

Changing any ciphertext, proof, poll identifier, manifest hash, scheme, or
protocol invalidates the ballot.

## Trustee ceremony and tally

Trustees use a Feldman verifiable secret-sharing ceremony. Trustee `i` samples a
degree `quorum-1` polynomial and publishes coefficient commitments under
`vota:v1:ceremony-commitment`. Encrypted or authenticated point-to-point shares
are outside the public artifact. Each recipient verifies its share against the
commitments. Aggregate public key `Y` is the sum of constant coefficient
commitments. No combined private key is constructed.

Accepted ciphertexts are added by choice position. The aggregate artifact binds
the ordered accepted ballot hashes and summed ciphertexts under
`vota:v1:aggregate-hash`.

For aggregate component `(A, B)`, trustee `i` publishes `D_i = y_i A` and a
Chaum-Pedersen proof under `vota:v1:decryption-share-proof` that the same secret
relates its public share and `D_i`. A quorum combines shares with Lagrange
coefficients to recover `M = B - yA`. Because `M = total * G` and the total is
bounded by 256, the verifier finds the integer total by a bounded table lookup.

Trustee APIs accept a closed aggregate artifact only. No supported operation
creates a decryption share for an individual ballot.

## Audit chain

The genesis event uses 32 zero bytes as `previous_hash`. Each event hash is
SHA-256 over `vota:v1:audit-event`, a zero byte, and canonical event content with
`event_hash` empty. Sequence numbers start at 1 and increase by exactly one.

A receipt binds poll ID, ballot hash, sequence, event hash, and checkpoint hash
under `vota:v1:receipt-signature`. Checkpoints are signed by the collector's
Ed25519 checkpoint key. Comparing checkpoints detects divergent histories but
does not prevent collector censorship or equivocation.

## Failure rules

- Unknown versions, suites, schemes, encodings, and domains fail closed.
- Invalid public inputs return errors and never panic.
- Cheap size and encoding checks run before proof verification.
- Duplicate nullifiers reject a conflicting ballot; byte-identical resubmission
  returns the original receipt.
- Tally publication requires a valid trustee quorum and the manifest privacy
  threshold.
- Totals must be non-negative, one per choice, and sum to accepted ballots.

## References

- Monero Research Lab, MRL-0005, section 2.1
- RFC 9496, Ristretto255
- RFC 8785, JSON Canonicalization Scheme
- ElectionGuard encrypted ballot and quorum tally concepts

These references guide the educational construction. Vota is not wire-compatible
with Monero or ElectionGuard.
