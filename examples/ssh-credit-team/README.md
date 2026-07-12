# Three-Developer SSH-Credit Poll

`demo.sh` is a disposable end-to-end example of the supported Vota workflow.
It creates three SSH Ed25519 identities, loads them into one demo agent, starts
one server with one SQLite database, creates a lunch poll, casts three votes,
tests duplicate rejection, closes the poll, and verifies the exported audit
record. It then restarts the original server, restores a copied database and
key set, and checks aggregate health.

Run from the repository root:

```sh
./examples/ssh-credit-team/demo.sh
```

The single demo agent represents three separate developer computers. In a real
team, each person has only their own private key and runs `vota vote` locally.
All interaction goes through the shared poll URL and server API.
