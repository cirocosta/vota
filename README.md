# Vota

Vota is experimental educational software for anonymous, encrypted polls. It is
not suitable for real elections or other consequential decisions.

The implementation follows
[`docs/prds/001-vota-anonymous-poll-cli.md`](docs/prds/001-vota-anonymous-poll-cli.md).

## Build

```sh
go build -o /tmp/vota ./cmd/vota
/tmp/vota version --json
```

The original elliptic-curve experiments remain under `examples/legacy-ecc`
while Vota's versioned protocol packages are implemented.
