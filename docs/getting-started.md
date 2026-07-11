# Getting Started

Vota requires the Go toolchain pinned in `go.mod`. The current pin is Go
1.26.5.

## Verified demonstration

Run the same subprocess workflow used by CI:

```sh
go test ./test/e2e -run TestAnonymousPollWorkflow -count=1 -v
```

The test builds `cmd/vota`, starts a collector on loopback, and uses only
temporary files. It performs these checked operations:

1. Create three encrypted trustee keys with Ed25519 signing keys and X25519
   ceremony transport keys.
1. Exchange signed, encrypted Feldman contributions and finalize one secret
   share per trustee.
1. Create an administrator key and a three-choice poll draft.
1. Create five poll-local voter identities and add their possession proofs.
1. Freeze and publish the signed manifest.
1. Cast and submit three encrypted ballots.
1. Reject a second ballot from one identity and a ballot from a non-enrolled
   identity.
1. Close the poll, submit two aggregate decryption shares, and verify totals.
1. Export the public record and reproduce the tally offline.
1. Stop the collector and inspect logs and public artifacts for secret fields.

This test is the maintained runnable example. See
`test/e2e/workflow_test.go` for exact artifact construction and command
arguments.

## Build and inspect the CLI

```sh
go build -o /tmp/vota ./cmd/vota
/tmp/vota version --json
/tmp/vota --help
```

The command groups are:

```text
vota admin key create
vota trustee key create
vota trustee ceremony init
vota trustee ceremony contribute
vota trustee ceremony finalize
vota identity create
vota identity enroll export
vota poll create
vota poll eligible add
vota poll freeze
vota poll publish
vota poll get
vota vote cast
vota vote submit
vota poll close
vota trustee tally-share
vota tally submit-share
vota tally get
vota audit export
vota audit verify
vota audit compare
vota serve
```

Use `vota <group> <command> --help` for required flags. Passphrases and
administrator tokens are read without echo from a terminal by default.
Automation passes them through an already-open file descriptor. Automated
choice input uses `vote cast --choice-stdin`; no choice value flag exists.
Every command writes the educational-use warning to stderr so canonical JSON
stdout remains machine-readable.

## Artifact lifecycle

The administrator creates a draft before enrollments exist. Each voter
identity is bound to that draft ID and exports a proof of possession. Freezing
sorts and signs the final eligible ring and makes the manifest immutable.

Ballot casting is offline after the voter has a manifest. Submission returns a
receipt that the CLI verifies against the collector's signed public chain.
Closing creates one encrypted aggregate. Trustee commands accept that aggregate
and the signed manifest, not individual ballot ciphertexts. The collector
publishes a tally after a valid quorum and only when the accepted ballot count
meets the manifest privacy threshold.

`audit export` downloads a complete public record. `audit verify` needs no
database or network access. It replays ballot proofs, event bindings,
aggregation, trustee shares, threshold evidence, totals, and checkpoints.
