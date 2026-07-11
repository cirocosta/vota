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

Before enrollment, the draft poll ID is SHA-256 over
`vota:v1:poll-draft-id`, a zero byte, and canonical draft identity JSON. The
identity contains the schema and protocol versions, eligibility scheme,
question, choices, trustee IDs, signing keys and ceremony commitments, quorum,
election public key, privacy threshold, normalized UTC window, authority key,
and experimental warning. It excludes enrollments. Choices and trustees are
sorted by ID before hashing.

The poll ID is SHA-256 over `vota:v1:poll-id`, a zero byte, and the RFC 8785
canonical manifest with `poll_id` and `authority_signature` set to empty strings.
The administrator signs the poll ID and canonical unsigned manifest under
`vota:v1:manifest-signature` using Ed25519. The signed bytes are the domain, a
zero byte, the length-prefixed 32-byte poll ID, and the length-prefixed
canonical manifest with only `authority_signature` empty.

Eligible Ristretto255 keys are validated, deduplicated, and sorted by canonical
encoded bytes. Choices and trustees are sorted by ID. Every voter uses these
exact orders. The manifest is immutable after it is signed.

The manifest hash is SHA-256 over `vota:v1:manifest-hash`, a zero byte, and the
complete signed canonical manifest. Ballots carry this hash verbatim.

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

The hash-to-scalar transcript contains, in order, the enrollment domain, a zero
byte, and length-prefixed raw draft ID, eligibility public key, and `R`. The
proof artifact encodes canonical `R || s` bytes. Changing the draft, key, proof,
trustee ceremony, or poll window invalidates enrollment.

## Linkable ring proof

Version 1 uses a single-key LSAG-style proof over the complete ring
`P[0..n-1]`. The signer knows `x` and index `j` such that `P[j] = xG`.

The link tag is:

```text
I = x * Hp(vota:v1:ring-hash-to-group, P[j])
```

Per-poll keys make this standard link tag poll-local without changing the
hash-to-group or linking equations. Reusing an eligibility private key in a
different poll would make participation linkable and is rejected by identity
and manifest workflows. The poll ID, ballot choice, and encryption randomness
are not inputs to `I`.

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

For each position, define `Q_0 = B` and `Q_1 = B - G`. The proof encodes
`(c_0, c_1, s_0, s_1)`. Verification reconstructs:

```text
U_b = s_b G - c_b A
V_b = s_b Y - c_b Q_b
```

It then requires `c_0 + c_1` to equal the hash-to-scalar of, in order, the
domain, poll ID, manifest hash, choice index, election key, `A`, `B`, `U_0`,
`V_0`, `U_1`, and `V_1`.

For the sum proof, let `A*` and `B*` be the component-wise ciphertext sums and
`Q* = B* - G`. Its equality proof encodes `(c, s)`, reconstructs
`U = sG - cA*` and `V = sY - cQ*`, and hashes, in order, the domain, poll ID,
manifest hash, election key, `A*`, `B*`, bases `G` and `Y`, statements `A*` and
`Q*`, and commitments `U` and `V`.

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

Trustee indices are the integers 1 through `n`. Dealer `d` publishes
`C_(d,k) = a_(d,k)G` and privately sends `f_d(i)` to trustee `i`. Recipient `i`
checks:

```text
f_d(i)G = sum(k=0..quorum-1, i^k C_(d,k))
```

Its final share is `y_i = sum_d f_d(i)`. Its public share is derived from the
same commitment equation, without reading any private share.

Accepted ciphertexts are added by choice position. The aggregate artifact binds
the ordered accepted ballot hashes, ballot count, poll ID, and summed
ciphertexts under `vota:v1:aggregate-hash`. Ballot hashes are ordered by their
accepted audit sequence and included in the public aggregate artifact.

For aggregate component `(A, B)`, trustee `i` publishes `D_i = y_i A` and a
Chaum-Pedersen proof under `vota:v1:decryption-share-proof` that the same secret
relates its public share and `D_i`. A quorum combines shares with Lagrange
coefficients to recover `M = B - yA`. Because `M = total * G` and the total is
bounded by 256, the verifier finds the integer total by a bounded table lookup.

Trustee APIs accept a closed aggregate artifact only. No supported operation
creates a decryption share for an individual ballot.

The share equality proof uses bases `G` and `A`, statements `Y_i` and `D_i`,
and the same `(c, s)` reconstruction as the sum proof. Its transcript binds, in
order, the domain, aggregate hash, trustee index, choice index, election key,
trustee public key, aggregate `A`, aggregate `B`, `D_i`, both bases, both
statements, and both reconstructed commitments. Shares with a different
aggregate hash, trustee index, choice count, or proof fail closed.

Each trustee share artifact is signed with that trustee's manifest Ed25519 key.
The signed bytes are the decryption-share domain, a zero byte, and the
length-prefixed canonical share with `signature` empty. The public share object
hash is SHA-256 over the same domain, a zero byte, and the complete signed
canonical share.

Tally evidence sorts participating trustee indices in ascending order and
encodes, in order, a version byte, aggregate hash, ballot count, choice count,
each bounded total, trustee count, and each trustee index. Totals must sum to
the ballot count before the evidence can be encoded.

The tally evidence hash is SHA-256 over `vota:v1:tally-evidence`, a zero byte,
and the canonical tally with evidence hash and signature empty. The collector
signs the 32-byte evidence hash using the same domain and length-delimited
transcript format. A valid tally must contain one total per manifest choice and
the totals must sum to the accepted ballot count.

## Audit chain

The genesis event uses 32 zero bytes as `previous_hash`. Each event hash is
SHA-256 over `vota:v1:audit-event`, a zero byte, and canonical event content with
`event_hash` empty. Event content includes the poll ID, sequence, type, object
hash, previous hash, and normalized UTC acceptance time. Sequence numbers start
at 1 and increase by exactly one; acceptance times cannot move backward.

A checkpoint hash is SHA-256 over `vota:v1:checkpoint-hash`, a zero byte, and
canonical checkpoint content with hash and signature empty. The collector signs
that hash under `vota:v1:checkpoint-signature` with its Ed25519 checkpoint key.
A receipt signature binds length-prefixed poll ID, ballot hash, sequence, event
hash, and checkpoint hash under `vota:v1:receipt-signature`. Comparing valid
checkpoints at the same poll and sequence detects divergent histories but does
not prevent collector censorship or equivocation.

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
