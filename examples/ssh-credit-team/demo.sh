#!/bin/sh
set -eu

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/vota-demo.XXXXXX")
SERVER_PID=

cleanup() {
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	ssh-agent -k >/dev/null 2>&1 || true
	rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

stop_server() {
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID"
		wait "$SERVER_PID"
		SERVER_PID=
	fi
}

wait_ready() {
	until curl -fsS http://127.0.0.1:18080/readyz >/dev/null 2>&1; do
		sleep 0.1
	done
}

go build -o "$ROOT/vota" ./cmd/vota

eval "$(ssh-agent -s)" >/dev/null

for name in alice bob carol; do
	ssh-keygen -q -t ed25519 -N '' -f "$ROOT/$name" </dev/null
	ssh-add "$ROOT/$name" >/dev/null
done

cp "$ROOT/alice.pub" "$ROOT/admin.keys"
{
	printf 'alice '
	cat "$ROOT/alice.pub"
	printf 'bob '
	cat "$ROOT/bob.pub"
	printf 'carol '
	cat "$ROOT/carol.pub"
} >"$ROOT/team.keys"

cat >"$ROOT/server.json" <<EOF
{
  "listen_address": "127.0.0.1:18080",
  "database_path": "$ROOT/vota.sqlite",
  "public_base_url": "http://127.0.0.1:18080",
  "checkpoint_key_path": "$ROOT/checkpoint.key",
  "issuer_key_path": "$ROOT/issuer.key",
  "admin_keys_path": "$ROOT/admin.keys"
}
EOF

"$ROOT/vota" serve --config "$ROOT/server.json" >"$ROOT/server.log" 2>&1 &
SERVER_PID=$!
wait_ready

if date -u -v+1H '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then
	CLOSES_AT=$(date -u -v+1H '+%Y-%m-%dT%H:%M:%SZ')
else
	CLOSES_AT=$(date -u -d '+1 hour' '+%Y-%m-%dT%H:%M:%SZ')
fi

POLL_URL=$("$ROOT/vota" poll create \
	--server http://127.0.0.1:18080 \
	--admin-identity "$ROOT/alice.pub" \
	--members "$ROOT/team.keys" \
	--question 'Where should we have lunch?' \
	--choice Pizza \
	--choice Ramen \
	--choice Salad \
	--closes-at "$CLOSES_AT")

printf '1\n' | "$ROOT/vota" vote "$POLL_URL" --identity "$ROOT/alice.pub" --choice-stdin --receipt-out "$ROOT/alice-receipt.json"
printf '2\n' | "$ROOT/vota" vote "$POLL_URL" --identity "$ROOT/bob.pub" --choice-stdin --receipt-out "$ROOT/bob-receipt.json"
printf '3\n' | "$ROOT/vota" vote "$POLL_URL" --identity "$ROOT/carol.pub" --choice-stdin --receipt-out "$ROOT/carol-receipt.json"

if printf '1\n' | "$ROOT/vota" vote "$POLL_URL" --identity "$ROOT/alice.pub" --choice-stdin >/dev/null 2>&1; then
	printf '%s\n' 'duplicate claim unexpectedly succeeded' >&2
	exit 1
fi

"$ROOT/vota" poll close "$POLL_URL" --admin-identity "$ROOT/alice.pub"
"$ROOT/vota" poll result "$POLL_URL"

POLL_ID=${POLL_URL##*/}
"$ROOT/vota" audit export --server http://127.0.0.1:18080 --poll "$POLL_ID" --out "$ROOT/audit"
"$ROOT/vota" audit verify --record "$ROOT/audit"

stop_server
"$ROOT/vota" serve --config "$ROOT/server.json" >>"$ROOT/server.log" 2>&1 &
SERVER_PID=$!
wait_ready
"$ROOT/vota" poll result "$POLL_URL" >/dev/null

stop_server
mkdir "$ROOT/restore"
cp "$ROOT/vota.sqlite" "$ROOT/checkpoint.key" "$ROOT/issuer.key" "$ROOT/admin.keys" "$ROOT/restore/"
cat >"$ROOT/restore/server.json" <<EOF
{
  "listen_address": "127.0.0.1:18080",
  "database_path": "$ROOT/restore/vota.sqlite",
  "public_base_url": "http://127.0.0.1:18080",
  "checkpoint_key_path": "$ROOT/restore/checkpoint.key",
  "issuer_key_path": "$ROOT/restore/issuer.key",
  "admin_keys_path": "$ROOT/restore/admin.keys"
}
EOF
"$ROOT/vota" serve --config "$ROOT/restore/server.json" >>"$ROOT/server.log" 2>&1 &
SERVER_PID=$!
wait_ready
"$ROOT/vota" poll result "$POLL_URL" >/dev/null
"$ROOT/vota" diagnose --config "$ROOT/restore/server.json" >/dev/null

printf 'Demo passed. Temporary files: %s\n' "$ROOT"
