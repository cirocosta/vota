# Vota v1 Dependency Review

This record covers dependencies selected before cryptographic implementation.
Versions are pinned in `go.mod` and must be re-reviewed when updated.

## Cobra

- Module: `github.com/spf13/cobra`
- Version at selection: `v1.10.2`
- License: Apache-2.0
- Purpose: CLI composition only
- Security boundary: no cryptographic or artifact validation responsibility

## JSON Canonicalization Scheme

- Module: `github.com/gowebpki/jcs`
- Version at selection: `v1.0.1`
- License: Apache-2.0
- Purpose: RFC 8785 canonical JSON transformation
- Repository activity checked: 2026-07-11; repository updated in 2026
- Audit status: no independent audit identified
- Compensating evidence: RFC examples, local deterministic fixtures, duplicate
  field rejection before canonicalization, and differential tests required for
  every signed artifact

## Go cryptography extensions

- Module: `golang.org/x/crypto`
- Version at selection: `v0.54.0`
- License: BSD-3-Clause
- Purpose: legacy Keccak in the preserved example; future Argon2id and
  XChaCha20-Poly1305 keystores
- Security boundary: use only documented exported primitives; no forked code

## Ristretto255

- Module: `github.com/gtank/ristretto255`
- Version at selection: `v0.2.0`
- License: BSD-3-Clause
- Purpose: RFC 9496 prime-order group and scalar operations
- Repository activity checked: 2026-07-11; repository updated in 2026
- Audit status: no package-specific independent audit identified
- Security boundary: all group and scalar inputs require canonical decoding;
  Vota adds protocol equations but does not fork group arithmetic
- Compensating evidence: RFC vectors from the dependency, deterministic Vota
  vectors, every-position ring tests, mutation tests, fuzzing, race checks, and
  benchmarks through ring size 256

## Pending selections

The SQLite dependency remains unselected. Its implementation task must record
version, license, maintenance state, known audit status, vulnerability scan,
and API rationale before adding it to `go.mod`.
