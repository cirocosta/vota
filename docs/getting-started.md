# Getting Started

The supported Vota workflow has four primary commands:

```sh
vota serve --config server.json
vota poll create --server https://vota.example --admin-identity admin.pub --members team.keys --question "Lunch?" --choice Pizza --choice Ramen --closes-at 2026-07-12T16:00:00Z
vota vote https://vota.example/polls/sha256:... --identity developer.pub
vota poll result https://vota.example/polls/sha256:...
```

Poll administrators also use `vota poll close`. Anyone can use
`vota audit export` and `vota audit verify` after close.

Follow the [SSH-credit quickstart](ssh-credit-quickstart.md) for a local poll or
the [operations guide](operations.md) for a persistent server.
