# Collector Operations

Vota is a local educational collector, not a production election service. The
`serve` command reads strict JSON or YAML:

```json
{
  "listen_address": "127.0.0.1:8080",
  "database_path": "./vota.sqlite",
  "public_base_url": "http://127.0.0.1:8080",
  "admin_token_hashes": ["sha256:<64 lowercase hex characters>"],
  "checkpoint_key_path": "./checkpoint.key",
  "shutdown_timeout": "10s",
  "log_level": "info"
}
```

Start the collector:

```sh
vota serve --config server.json
```

## Configuration behavior

- `listen_address` defaults to `127.0.0.1:8080`.
- A non-loopback address fails unless `acknowledge_experimental: true` is set.
- `database_path`, `checkpoint_key_path`, and at least one precomputed
  `admin_token_hashes` entry are required.
- `public_base_url` is validated when present. The current collector does not
  use it to construct responses.
- `tls_certificate_path` and `tls_private_key_path` must be configured
  together. When present, the process uses Go's HTTPS server.
- Request bodies default to 1 MiB. Verification concurrency defaults to four.
- Request, read, write, idle, header, and shutdown limits have bounded defaults
  in `internal/httpapi` and `internal/cli/server`.
- Log levels are `debug`, `info`, `warn`, and `error`. Logs contain fixed
  request metadata, not request bodies or artifact identifiers.

The checkpoint key is an Ed25519 private key used for checkpoints, receipts,
and tally signatures. On first startup Vota creates the configured key file
with owner-only permissions. The server refuses an existing group-readable or
world-readable key. This unattended server key is not encrypted by a
passphrase; protect the host and file.

The SQLite store enables foreign keys, WAL mode, migrations, and transactional
state changes. Restarting with the same database and checkpoint key preserves
the public history and signature identity.

## HTTP surface

The implemented routes are:

```text
POST /v1/polls
GET  /v1/polls/{poll_id}
POST /v1/polls/{poll_id}/ballots
GET  /v1/polls/{poll_id}/receipts/{ballot_hash}
POST /v1/polls/{poll_id}/close
POST /v1/polls/{poll_id}/tally-shares
GET  /v1/polls/{poll_id}/tally
GET  /v1/polls/{poll_id}/audit
GET  /healthz
GET  /readyz
```

Poll publication and close require a bearer token whose SHA-256 hash matches
the configured set. Other mutation integrity comes from ballot or trustee
proofs and signatures. `/healthz` reports process health. `/readyz` checks the
database through the application service.

SIGINT and SIGTERM start bounded graceful shutdown. The collector stops
accepting connections, waits for active HTTP requests, and closes SQLite.
