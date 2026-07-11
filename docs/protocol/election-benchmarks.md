# Election Cryptography Performance Baseline

Recorded 2026-07-11 on Linux/amd64 with Go 1.26.4 and an Intel Core i9-9900K.
Command:

```sh
go test ./internal/crypto/election -run '^$' \
  -bench 'Benchmark(BallotProof|ThresholdTally)$' -benchtime=200ms -benchmem
```

| Operation | Time/op | Bytes/op | Allocations/op |
|:---|---:|---:|---:|
| Encrypt and prove 10 choices | 3.23 ms | 35,417 | 561 |
| Verify 10 choices | 3.50 ms | 29,672 | 415 |
| Combine 2-of-3 shares for 256 ballots and 2 choices | 1.29 ms | 14,400 | 200 |

Parser and verifier fuzzing uses:

```sh
go test ./internal/crypto/election -run '^$' \
  -fuzz '^FuzzArtifactParsers$' -fuzztime=5s
```

These numbers are regression evidence, not a production capacity claim.
