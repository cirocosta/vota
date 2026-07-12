# Operations

Read the [security model](security.md) before exposing Vota to a network. The
server assumes its operator and reverse proxy do not correlate or log client
metadata.

## Files

One persistent directory is enough:

```text
/var/lib/vota/
  vota.sqlite
  checkpoint.key
  issuer.key
  admin.keys
  server.json
```

`checkpoint.key` and `issuer.key` must be mode `0600`. Back up the database and
both private keys as one set. Restoring only the database loses the ability to
issue valid credentials or prove continuity of signed history.

## Configuration

```json
{
  "listen_address": "127.0.0.1:8080",
  "database_path": "/var/lib/vota/vota.sqlite",
  "public_base_url": "https://vota.example",
  "checkpoint_key_path": "/var/lib/vota/checkpoint.key",
  "issuer_key_path": "/var/lib/vota/issuer.key",
  "admin_keys_path": "/var/lib/vota/admin.keys",
  "shutdown_timeout": "10s"
}
```

`admin.keys` contains one canonical `ssh-ed25519` public key per line. A
display name before the key is also accepted.

```text
alice ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

Start the process:

```sh
vota serve --config /var/lib/vota/server.json
```

Optional single-container deployment:

```sh
cp examples/ssh-credit-team/server.container.example.json \
  /var/lib/vota/server.json
docker build -f examples/ssh-credit-team/Dockerfile -t vota .
docker run --rm \
  -p 127.0.0.1:8080:8080 \
  -v /var/lib/vota:/data \
  vota
```

The container still runs one Vota process and uses one mounted SQLite
database. The example publishes only to host loopback and acknowledges the
experimental non-loopback listener inside the container. Change
`public_base_url` before sharing a poll URL.

The first start creates the issuer and checkpoint keys. A non-loopback listener
requires configured TLS or `acknowledge_experimental: true`. Prefer a local
listener behind one TLS reverse proxy.

## Reverse proxy logging

Disable access logs for Vota. Do not add request tracing, distributed tracing,
body logging, query logging, client-IP headers, or per-poll metric labels.

Minimal Caddy example:

```text
vota.example {
    log {
        output discard
    }
    reverse_proxy 127.0.0.1:8080
}
```

The proxy and Vota remain one trust domain. The proxy is not an anonymity
network.

## Health

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
vota diagnose --config /var/lib/vota/server.json
```

Readiness replays both hash chains and verifies stored checkpoints. Diagnose
prints aggregate counts only. It never prints poll IDs, SSH fingerprints,
credentials, or choices.

## Backup and restore

Stop Vota cleanly, then copy the complete persistent directory:

```sh
systemctl stop vota
tar -C /var/lib -czf vota-backup.tgz vota
systemctl start vota
```

Restore into an empty directory with the original permissions, start Vota, and
check readiness plus a known closed result:

```sh
tar -C /var/lib -xzf vota-backup.tgz
chmod 600 /var/lib/vota/checkpoint.key /var/lib/vota/issuer.key
vota serve --config /var/lib/vota/server.json
```

The end-to-end test exercises restart and restore from copied database and key
files.

## Key rotation

Issuer and checkpoint rotation is not supported in version 1. Replacing either
key invalidates continuity for existing polls. Create a new deployment and keep
the old server or its audit exports available until old polls no longer need
verification.
