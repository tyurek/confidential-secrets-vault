#!/usr/bin/env bash
#
# End-to-end test for the confidential secrets vault write path.
#
# Builds the vault and the tinfoil-cli, starts the vault locally, and drives
# `tinfoil vault put/ls/rm` against it over EHBP — asserting that secrets are
# stored/listed/deleted, that an un-encrypted store is rejected, and that the
# CLI refuses to send when the vault's key doesn't match what it pinned.
#
# This uses --vault-hpke-key to pin the key out-of-band, bypassing attestation
# (there is no real enclave locally). It exercises everything except the
# attestation step itself.
#
# If a cvmimage checkout is present it also runs the real boot-path code — the
# cmd/boot vault fetch+decrypt (TestVaultFetchOpenLive) — against the vault,
# exercising the full store→release→decrypt lifecycle.
#
# Overridable via env:
#   TINFOIL_CLI_DIR   path to the tinfoil-cli checkout (default ~/tinfoil-cli)
#   CVMIMAGE_DIR      path to the cvmimage checkout    (default ~/cvmimage)
#   VAULT_PORT        port to run the vault on         (default 8099)
#
# Usage:  ./test-e2e.sh        (exits non-zero if any check fails)

set -uo pipefail

VAULT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="${TINFOIL_CLI_DIR:-$HOME/tinfoil-cli}"
CVMIMAGE_DIR="${CVMIMAGE_DIR:-$HOME/cvmimage}"
PORT="${VAULT_PORT:-8099}"
BASE="http://127.0.0.1:${PORT}"
REPO="me/my-workload"
export GOTOOLCHAIN=auto

command -v go   >/dev/null || { echo "go not found on PATH"; exit 1; }
command -v curl >/dev/null || { echo "curl not found on PATH"; exit 1; }
[ -d "$CLI_DIR" ] || { echo "tinfoil-cli not found at $CLI_DIR (set TINFOIL_CLI_DIR)"; exit 1; }

WORK="$(mktemp -d)"
SVAULT="$WORK/svault"
TINCLI="$WORK/tinfoil-cli"
FETCHDEMO="$WORK/fetch-demo"
LOG="$WORK/vault.log"
VAULT_PID=""

cleanup() {
  [ -n "$VAULT_PID" ] && kill "$VAULT_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

green="\033[32m"; red="\033[31m"; dim="\033[2m"; bold="\033[1m"; rst="\033[0m"
PASS=0; FAIL=0
ok()  { printf "  ${green}✓${rst} %s\n" "$1"; PASS=$((PASS+1)); }
bad() { printf "  ${red}✗${rst} %s\n" "$1"; [ -n "${2:-}" ] && printf "      ${dim}%s${rst}\n" "$2"; FAIL=$((FAIL+1)); }
section() { printf "\n${bold}%s${rst}\n" "$1"; }

# assert_contains <desc> <haystack> <needle>
assert_contains() {
  if printf '%s' "$2" | grep -qF -- "$3"; then ok "$1"; else bad "$1" "expected to contain '$3', got: $2"; fi
}
# assert_not_contains <desc> <haystack> <needle>
assert_not_contains() {
  if printf '%s' "$2" | grep -qF -- "$3"; then bad "$1" "did not expect '$3', got: $2"; else ok "$1"; fi
}

# tinfoil vault <args> against the local vault, pinning the real key.
cli() { "$TINCLI" vault "$@" --vault "$BASE" --vault-hpke-key "$KEY" --repo "$REPO"; }

section "Build"
( cd "$VAULT_DIR" && go build -o "$SVAULT" . ) || { echo "vault build failed"; exit 1; }
( cd "$VAULT_DIR" && go build -o "$FETCHDEMO" ./cmd/fetch-demo ) || { echo "fetch-demo build failed"; exit 1; }
( cd "$CLI_DIR"   && go build -o "$TINCLI" . ) || { echo "cli build failed"; exit 1; }
ok "built vault, fetch-demo, and tinfoil-cli"
HAVE_CMDBOOT=0
if [ -d "$CVMIMAGE_DIR/tinfoil/cmd/boot" ]; then
  HAVE_CMDBOOT=1; ok "found cvmimage cmd/boot (real boot-path test)"
else
  printf "  (skipping cmd/boot test — set CVMIMAGE_DIR to a cvmimage checkout)\n"
fi

section "Unit tests"
( cd "$VAULT_DIR" && go test ./... >/dev/null 2>&1 ) && ok "vault unit tests" || bad "vault unit tests"
( cd "$CLI_DIR"   && go test ./... >/dev/null 2>&1 ) && ok "cli unit tests"   || bad "cli unit tests"

section "Start vault"
"$SVAULT" -addr "127.0.0.1:${PORT}" -identity "$WORK/identity.json" -dev-verify >"$LOG" 2>&1 &
VAULT_PID=$!
# Wait for the key endpoint to answer (retry across connection-refused).
if ! curl -fs --retry 30 --retry-connrefused --retry-delay 1 -o /dev/null "$BASE/.well-known/hpke-keys" 2>/dev/null; then
  echo "vault did not become ready; log:"; cat "$LOG"; exit 1
fi
KEY="$(grep -oE 'vault HPKE key: [0-9a-f]+' "$LOG" | awk '{print $4}' | head -1)"
[ -n "$KEY" ] || { echo "could not read vault HPKE key from log:"; cat "$LOG"; exit 1; }
ok "vault listening on $BASE (key ${KEY:0:16}…)"

section "Write path"
out="$(printf 's3cret-value' | cli put DB_PASSWORD 2>&1)"
assert_contains "put DB_PASSWORD (stdin)" "$out" "Stored secret DB_PASSWORD"

out="$(cli put API_KEY --value 'ak-12345' 2>&1)"
assert_contains "put API_KEY (--value)" "$out" "Stored secret API_KEY"

out="$(cli ls 2>&1)"
assert_contains "ls shows DB_PASSWORD" "$out" "DB_PASSWORD"
assert_contains "ls shows API_KEY"     "$out" "API_KEY"

out="$(cli rm DB_PASSWORD 2>&1)"
assert_contains "rm DB_PASSWORD" "$out" "Deleted secret DB_PASSWORD"

out="$(cli ls 2>&1)"
assert_not_contains "ls no longer shows DB_PASSWORD" "$out" "DB_PASSWORD"
assert_contains     "ls still shows API_KEY"         "$out" "API_KEY"

section "Boot-release path (/fetch via --dev-verify)"
# Simulate a workload booting: it presents pk_W and gets API_KEY sealed back,
# then opens it with sk_W. fetch-demo prints the recovered {name:value} JSON.
out="$("$FETCHDEMO" -vault "$BASE" -repo "$REPO" -secrets API_KEY 2>&1)"
assert_contains "workload fetches & decrypts API_KEY" "$out" '"API_KEY":"ak-12345"'
out="$("$FETCHDEMO" -vault "$BASE" -repo "nobody/repo" -secrets API_KEY 2>&1)"
assert_contains "fetch for a repo with no secrets returns {}" "$out" "{}"

if [ "$HAVE_CMDBOOT" = 1 ]; then
  section "Boot stage 3b (real cmd/boot fetch+decrypt)"
  # The actual boot-path code: cmd/boot's vault fetch + circl-open of the
  # release the vault sealed with go's crypto/hpke (TestVaultFetchOpenLive).
  out="$(cd "$CVMIMAGE_DIR/tinfoil" && \
    VAULT_TEST_URL="$BASE" VAULT_TEST_REPO="$REPO" VAULT_TEST_VALUE="ak-12345" \
    go test -run Live -count=1 ./cmd/boot/ 2>&1)"
  if printf '%s' "$out" | grep -qE '^ok'; then
    ok "cmd/boot decrypts API_KEY (crypto/hpke↔circl interop)"
  else
    bad "cmd/boot fetch+decrypt" "$out"
  fi
fi

section "Negative checks"
# A plaintext POST (what a tampering host could attempt) must be rejected.
code="$(curl -s -o "$WORK/resp" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d '{"repo":"'"$REPO"'","name":"SNUCK_IN","value":"plain"}' "$BASE/store")"
if [ "$code" = "400" ]; then ok "plaintext /store rejected (HTTP 400)"; else bad "plaintext /store rejected" "got HTTP $code"; fi
out="$(cli ls 2>&1)"
assert_not_contains "plaintext secret was not stored" "$out" "SNUCK_IN"

# A wrong pinned key must make the CLI refuse to encrypt (before sending).
wrong="$(printf '0%.0s' $(seq 1 64))"
out="$("$TINCLI" vault put NOPE --value x --vault "$BASE" --vault-hpke-key "$wrong" --repo "$REPO" 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then ok "wrong key: CLI exits non-zero"; else bad "wrong key: CLI exits non-zero" "exit $rc"; fi
assert_contains "wrong key: refuses to encrypt" "$out" "mismatch"

section "Result"
printf "  %s${green}%d passed${rst}, ${red}%d failed${rst}\n" "" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
