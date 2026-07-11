# Election Cryptography Performance Baseline

Recorded 2026-07-11 on Linux/amd64 with Go 1.26.5 and an Intel Core i9-9900K.
Command:

```sh
go test ./internal/crypto/election -run '^$' \
  -bench 'Benchmark(BallotProof|ThresholdTally)$' -benchtime=200ms -benchmem
```

| Operation                                           | Time/op | Bytes/op | Allocations/op |
| :-------------------------------------------------- | ------: | -------: | -------------: |
| Encrypt and prove 10 choices                        | 3.24 ms |   35,064 |            539 |
| Verify 10 choices                                   | 3.46 ms |   29,320 |            393 |
| Combine 2-of-3 shares for 256 ballots and 2 choices | 1.24 ms |   14,424 |            194 |

Parser and verifier fuzzing uses:

```sh
go test ./internal/crypto/election -run '^$' \
  -fuzz '^FuzzArtifactParsers$' -fuzztime=5s
```

These numbers are regression evidence, not a production capacity claim.
