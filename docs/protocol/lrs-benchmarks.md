# Ring-v1 Performance Baseline

Recorded 2026-07-11 on Linux/amd64 with Go 1.26.4 and an Intel Core i9-9900K.
Command:

```sh
go test ./internal/crypto/lrs -run '^$' -bench 'Benchmark(Sign|Verify)$' \
  -benchtime=200ms -benchmem
```

| Operation | Ring size | Time/op | Bytes/op | Allocations/op |
|:---|---:|---:|---:|---:|
| Verify | 16 | 2.69 ms | 24,289 | 494 |
| Verify | 64 | 10.57 ms | 95,584 | 1,934 |
| Verify | 128 | 22.12 ms | 190,432 | 3,854 |
| Verify | 256 | 44.38 ms | 379,744 | 7,694 |
| Sign | 16 | 2.64 ms | 32,561 | 592 |
| Sign | 64 | 10.56 ms | 129,970 | 2,320 |
| Sign | 128 | 21.10 ms | 260,019 | 4,624 |
| Sign | 256 | 45.50 ms | 519,350 | 9,232 |

The 128-member result is below the educational requirement of 2 seconds. These
numbers are regression evidence, not a production capacity claim.
