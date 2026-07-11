# Vota v1 Dependency Review

This record covers dependencies selected before cryptographic implementation.
Versions are pinned in `go.mod` and must be re-reviewed when updated.

## Go toolchain

- Language version: Go 1.26
- Minimum pinned toolchain: Go 1.26.5
- Reason for patch pin: Go 1.26.0 through 1.26.4 contain `GO-2026-5856` in
  `crypto/tls`; Vota's HTTP client reaches the affected handshake path
- Verification: the full test, race, vet, build, staticcheck, and govulncheck
  suite passes with Go 1.26.5 and reports zero reachable vulnerabilities

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

## SQLite

- Module: `modernc.org/sqlite`
- Version at selection: `v1.53.0`
- License: BSD-3-Clause; bundled SQLite is public domain
- Purpose: `database/sql` SQLite driver for transactional collector state
- Repository activity checked: 2026-07-11; `v1.53.0` was published 2026-06-21
- CGO: not required
- Audit status: no driver-specific independent audit identified
- Selection rationale: pure-Go Linux and macOS builds, current tagged release,
  connection-level pragma support, and standard `database/sql` integration
- Compensating evidence: migration replay, foreign-key checks, deferred ballot
  and event constraints, fault injection, 50-writer uniqueness tests, race
  tests, and vulnerability reachability scanning
