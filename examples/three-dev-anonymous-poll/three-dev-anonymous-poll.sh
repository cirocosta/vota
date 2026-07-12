#!/usr/bin/env bash
# Runs a local, educational Vota poll for three people. Choices are typed at
# runtime and are never written into this script or printed by it.
set -euo pipefail

for command in curl jq shasum go; do
	command -v "$command" >/dev/null || {
		printf 'missing required command: %s\n' "$command" >&2
		exit 1
	}
done

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="${WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/vota-three-dev.XXXXXX")}"
vota="${VOTA_BIN:-$work/vota}"
port="${VOTA_PORT:-18080}"
server="http://127.0.0.1:$port"
key_passphrase="${VOTA_DEMO_PASSPHRASE:-demo-only-passphrase}"
admin_token="${VOTA_DEMO_ADMIN_TOKEN:-demo-only-admin-token}"
keep_demo="${KEEP_DEMO:-0}"
server_pid=""

umask 077
mkdir -p "$work/contributions" "$work/ballots"
cd "$root"

cleanup() {
	if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
		kill -INT "$server_pid"
		wait "$server_pid" || true
	fi
	if [[ "$keep_demo" == "1" ]]; then
		printf '\nDemo files retained at: %s\n' "$work"
	else
		rm -rf "$work"
	fi
}
trap cleanup EXIT

rfc3339_after_one_hour() {
	if [[ "$(uname)" == "Darwin" ]]; then
		date -u -v+1H +%Y-%m-%dT%H:%M:%SZ
	else
		date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ
	fi
}

secret() {
	"$vota" "$@" --passphrase-fd 3 3<<<"$key_passphrase"
}

admin_secret() {
	"$vota" "$@" --admin-token-fd 3 3<<<"$admin_token"
}

printf 'Building Vota...\n'
go build -o "$vota" ./cmd/vota

printf 'Creating three trustee keys and a 2-of-3 election key...\n'
for index in 1 2 3; do
	secret trustee key create \
		--id "trustee-$index" \
		--out "$work/trustee-$index.key" \
		--public-out "$work/trustee-$index.public.json" >/dev/null
done

jq -n \
	--slurpfile trustee1 "$work/trustee-1.public.json" \
	--slurpfile trustee2 "$work/trustee-2.public.json" \
	--slurpfile trustee3 "$work/trustee-3.public.json" \
	'{schema_version: 1, protocol: "vota-v1-experimental", quorum: 2,
    trustees: [$trustee1[0], $trustee2[0], $trustee3[0]]}' \
	>"$work/ceremony.config.json"

"$vota" trustee ceremony init \
	--config "$work/ceremony.config.json" \
	--out "$work/ceremony.request.json" >/dev/null

for index in 1 2 3; do
	secret trustee ceremony contribute \
		--input "$work/ceremony.request.json" \
		--key "$work/trustee-$index.key" \
		--out "$work/contributions/trustee-$index.json" >/dev/null
done

for index in 1 2 3; do
	secret trustee ceremony finalize \
		--input-dir "$work/contributions" \
		--request "$work/ceremony.request.json" \
		--key "$work/trustee-$index.key" \
		--out "$work/trustee-$index.final.key" \
		--public-out "$work/ceremony-$index.public.json" >/dev/null
done

printf 'Creating and freezing the three-person poll...\n'
secret admin key create --out "$work/admin.key" >/dev/null
opens_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
closes_at="$(rfc3339_after_one_hour)"
jq -n \
	--arg opens_at "$opens_at" \
	--arg closes_at "$closes_at" \
	--slurpfile ceremony "$work/ceremony-1.public.json" \
	'{question: "Which team lunch option?",
    choices: [
      {id: "pizza", label: "Pizza"},
      {id: "ramen", label: "Ramen"},
      {id: "salad", label: "Salad"}
    ],
    trustees: $ceremony[0].trustees,
    trustee_quorum: 2,
    privacy_threshold: 3,
    opens_at: $opens_at,
    closes_at: $closes_at}' \
	>"$work/poll.config.json"

secret poll create \
	--config "$work/poll.config.json" \
	--admin-key "$work/admin.key" \
	--out "$work/poll.draft.json" >/dev/null

for index in 1 2 3; do
	secret identity create \
		--poll "$work/poll.draft.json" \
		--out "$work/voter-$index.key" >/dev/null
	secret identity enroll export \
		--identity "$work/voter-$index.key" \
		--out "$work/voter-$index.enrollment.json" >/dev/null
	"$vota" poll eligible add \
		--draft "$work/poll.draft.json" \
		--enrollment "$work/voter-$index.enrollment.json" >/dev/null
done

secret poll freeze --yes \
	--draft "$work/poll.draft.json" \
	--admin-key "$work/admin.key" \
	--out "$work/manifest.json" >/dev/null

token_hash="$(printf '%s' "$admin_token" | shasum -a 256 | awk '{print $1}')"
jq -n \
	--arg address "127.0.0.1:$port" \
	--arg server "$server" \
	--arg database "$work/vota.sqlite" \
	--arg checkpoint "$work/checkpoint.key" \
	--arg token_hash "sha256:$token_hash" \
	'{listen_address: $address, public_base_url: $server,
    database_path: $database, checkpoint_key_path: $checkpoint,
    admin_token_hashes: [$token_hash], shutdown_timeout: "2s"}' \
	>"$work/server.json"

"$vota" serve --config "$work/server.json" >"$work/server.log" 2>&1 &
server_pid="$!"
for _ in {1..50}; do
	curl --silent --fail "$server/healthz" >/dev/null && break
	sleep 0.1
done
curl --silent --fail "$server/healthz" >/dev/null || {
	printf 'collector did not become healthy. See %s/server.log\n' "$work" >&2
	exit 1
}

admin_secret poll publish \
	--manifest "$work/manifest.json" \
	--server "$server" >/dev/null

printf '\nEach developer now enters a choice privately.\n'
printf 'Valid choices: pizza, ramen, salad. Input is not echoed or logged.\n'
for index in 1 2 3; do
	while :; do
		read -r -s -p "Developer $index choice: " choice
		printf '\n'
		case "$choice" in
		pizza | ramen | salad) break ;;
		*) printf 'Enter pizza, ramen, or salad.\n' >&2 ;;
		esac
	done
	printf '%s\n' "$choice" | "$vota" vote cast \
		--choice-stdin \
		--poll "$work/manifest.json" \
		--identity "$work/voter-$index.key" \
		--out "$work/ballots/ballot-$index.json" \
		--passphrase-fd 3 3<<<"$key_passphrase" >/dev/null
	"$vota" vote submit \
		--ballot "$work/ballots/ballot-$index.json" \
		--server "$server" \
		--receipt "$work/receipt-$index.json" >/dev/null
	unset choice
done

poll_id="$(jq -r '.poll_id' "$work/manifest.json")"
admin_secret poll close --poll "$poll_id" --server "$server" --json \
	>"$work/aggregate.json"
for index in 1 2; do
	secret trustee tally-share \
		--poll "$work/manifest.json" \
		--aggregate "$work/aggregate.json" \
		--key "$work/trustee-$index.final.key" \
		--out "$work/share-$index.json" >/dev/null
	"$vota" tally submit-share \
		--share "$work/share-$index.json" --server "$server" >/dev/null
done

"$vota" tally get --poll "$poll_id" --server "$server" --out "$work/tally.json" >/dev/null
"$vota" audit export --poll "$poll_id" --server "$server" --out "$work/audit" >/dev/null
"$vota" audit verify --record "$work/audit" --json >"$work/audit-report.json"

printf '\nPublished tally (no voter-to-choice mapping):\n'
jq -r '.totals[] | "  \(.choice_id): \(.total)"' "$work/tally.json"
printf '\nOffline audit passed. Accepted ballots: %s\n' \
	"$(jq -r '.accepted_ballot_count' "$work/audit-report.json")"
printf 'Set KEEP_DEMO=1 to retain local artifacts for inspection.\n'
