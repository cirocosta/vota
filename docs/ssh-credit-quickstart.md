# SSH-Credit Quickstart

This demo runs one local Vota process, creates a three-person poll, casts three
votes, rejects a duplicate claim, closes the poll, and verifies the audit log.

Requirements: Go, OpenSSH, `curl`, and a POSIX shell.

## Automated demo

From the repository root:

```sh
./examples/ssh-credit-team/demo.sh
```

The script creates temporary demo-only SSH keys. It removes all temporary files
when it exits.

## Use your team's keys

Build Vota:

```sh
go build -o ./vota ./cmd/vota
```

Create `admin.keys` with the public key allowed to create and close polls:

```sh
cp ~/.ssh/id_ed25519.pub admin.keys
```

Create `team.keys`:

```text
alice ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
bob ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
carol ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

Copy [`server.example.json`](../examples/ssh-credit-team/server.example.json),
replace its paths, and start Vota:

```sh
./vota serve --config server.json
```

Create a poll from another terminal. The administrator's private key must be
loaded in `ssh-agent`:

```sh
ssh-add ~/.ssh/id_ed25519

POLL_URL="$(./vota poll create \
  --server http://127.0.0.1:8080 \
  --admin-identity ~/.ssh/id_ed25519.pub \
  --members team.keys \
  --question "Where should we have lunch?" \
  --choice Pizza \
  --choice Ramen \
  --choice Salad \
  --closes-at 2026-07-12T16:00:00Z)"
```

Share `$POLL_URL`. Each teammate runs:

```sh
./vota vote "$POLL_URL" --identity ~/.ssh/id_ed25519.pub
```

Close, inspect, and audit:

```sh
./vota poll close "$POLL_URL" --admin-identity ~/.ssh/id_ed25519.pub
./vota poll result "$POLL_URL"

POLL_ID="${POLL_URL##*/}"
./vota audit export \
  --server http://127.0.0.1:8080 \
  --poll "$POLL_ID" \
  --out audit
./vota audit verify --record audit
```

The server knows which key claims a credit. It does not learn the unblinded
credential during issuance. The trust assumption remains: the shared host must
not correlate claim and ballot traffic using IP addresses, timing, or live
process observation.
