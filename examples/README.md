# Concept Examples

These small programs explain the equations used by Vota and related privacy
systems. They are runnable teaching aids, not alternate protocol
implementations.

```sh
go run ./examples/ecc-basics
go run ./examples/stealth-address
go run ./examples/ring-signature
go run ./examples/threshold-tally
```

- `ecc-basics` shows scalar-to-point public keys, Diffie-Hellman agreement, and
  point addition in Ristretto255.
- `stealth-address` derives and scans a one-time destination with separate view
  and spend keys. It demonstrates the construction, not Monero wire
  compatibility.
- `ring-signature` uses Vota's real LSAG package to show signer ambiguity,
  verification, and link tags.
- `threshold-tally` uses Vota's real election package to prove one-hot ballots,
  aggregate ciphertexts, and recover totals with a two-of-three trustee quorum.
- `legacy-ecc` preserves the earlier X25519 and Monero-inspired exploration.

Each directory has tests for the invariant printed by its program.
