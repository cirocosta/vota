# Vota

Vota is experimental educational software for anonymous, encrypted polls. It
is not suitable for real elections or consequential decisions.

```sh
go build -o /tmp/vota ./cmd/vota
/tmp/vota --help
go test ./test/e2e -run TestAnonymousPollWorkflow -count=1
```

The end-to-end test runs a complete local poll with three trustees and five
eligible identities on Linux and macOS.

Documentation:

- [Getting started](docs/getting-started.md)
- [Security model and limitations](docs/security.md)
- [Cryptographic design review status](docs/design-review.md)
- [Collector operations](docs/operations.md)
- [Experimental protocol](docs/protocol/vota-v1-experimental.md)
- [Public artifacts](docs/protocol/artifacts.md)
- [Dependencies](docs/protocol/dependencies.md)

The original elliptic-curve experiments remain in `examples/legacy-ecc`.
