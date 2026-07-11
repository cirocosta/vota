# Ring-v1 Performance Baseline

Recorded 2026-07-11 on Linux/amd64 with Go 1.26.5 and an Intel Core i9-9900K.
Command:

```sh
go test ./internal/crypto/lrs -run '^$' -bench 'Benchmark(Sign|Verify)$' \
  -benchtime=200ms -benchmem
```

| Operation | Ring size |  Time/op | Bytes/op | Allocations/op |
| :-------- | --------: | -------: | -------: | -------------: |
| Verify    |        16 |  2.71 ms |   23,105 |            428 |
| Verify    |        64 | 10.57 ms |   90,944 |          1,676 |
| Verify    |       128 | 21.27 ms |  181,184 |          3,340 |
| Verify    |       256 | 42.10 ms |  361,281 |          6,668 |
| Sign      |        16 |  2.67 ms |   31,376 |            526 |
| Sign      |        64 | 10.52 ms |  125,330 |          2,062 |
| Sign      |       128 | 21.42 ms |  250,771 |          4,110 |
| Sign      |       256 | 42.49 ms |  500,881 |          8,206 |

The 128-member result is below the educational requirement of 2 seconds. These
numbers are regression evidence, not a production capacity claim.
