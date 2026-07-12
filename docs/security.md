# Security Model

Vota is for low-consequence anonymous team polls. It is not a general election
system.

## Guarantee

An eligible SSH key can claim one blind credential per poll. A finalized
credential can cast one ballot. The credit database stream contains SSH
fingerprints and blinded issuance transcripts, but no serials or choices. The
ballot stream contains anonymous credential hashes and choices, but no SSH keys
or fingerprints.

Given the blindness of RFC 9474 RSABSSA and an honest protocol execution,
persisted server records and the public audit log contain no cryptographic join
from an SSH identity to its ballot.

## Trust assumption

The single host is trusted not to correlate issuance and redemption using live
metadata. Vota does not log IP addresses, raw URLs, poll IDs, SSH material,
credential material, choices, or request bodies. A reverse proxy must follow
the same rule.

A malicious operator with host access can still observe:

- source IP addresses and TLS fingerprints;
- request timing and order;
- process memory before fields are separated;
- the issuer private key and checkpoint private key;
- small or predictable voting patterns.

Blind credentials do not prevent those observations. Run the server only with
an operator the team trusts under this model.

## Protected properties

- Only configured SSH administrators can create or close polls.
- Only allowlisted Ed25519 SSH keys can claim credits.
- Claim retries are idempotent only for the same request ID and blinded value.
- Concurrent claims for one SSH key commit at most one issuance.
- Credentials bind their poll, issuer key, random serial, and protocol domain.
- Concurrent redemption of one credential commits at most one ballot.
- An exact ballot retry returns the stored signed receipt without appending a
  second ballot. A retry with another choice is rejected.
- Open polls expose neither individual ballots nor partial totals.
- Signed hash-chain checkpoints reveal modification of published ballot logs.
- Offline replay recomputes the final tally and validates receipt inclusion.

## Not protected

- Server censorship before a receipt is issued.
- A malicious issuer minting extra credentials.
- A sequencer showing different signed histories to people who never compare
  checkpoints.
- Compromise of a participant computer or `ssh-agent`.
- Theft of unfinished local recovery state or an unspent bearer credential.
- Inference from a small, unanimous, or predictable result.
- Post-quantum attackers.

## Key material

The issuer RSA key and checkpoint Ed25519 key are created with mode `0600`.
They have separate roles and must be backed up together with the SQLite
database. The administrator file contains public SSH keys and can be mode
`0644`.

Version 1 accepts `ssh-ed25519` keys only. RSA, ECDSA, DSA, SSH certificates,
and FIDO-backed SSH keys are rejected.
