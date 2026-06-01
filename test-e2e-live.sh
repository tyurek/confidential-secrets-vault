#!/usr/bin/env bash
#
# LIVE end-to-end test for the confidential secrets vault — real SEV-SNP enclave.
#
# Unlike test-e2e.sh (which uses --dev-verify and no real enclave), this drives
# the full attested loop on a real host:
#
#   start vault (capture) → dev-launch a workload → the enclave's boot stage 3b
#   sends its real SEV-SNP quote → vault verifies it and logs the measurement →
#   pin that measurement → `vault put` a secret → relaunch → the vault releases
#   the secret sealed to the enclave's attested HPKE key → cmd/boot decrypts it
#   in-enclave → assert DEMO_SECRET is in the container, and that the host (vault
#   log) only ever saw the secret's name, never its value.
#
# It MUST run on a tinfoil SEV-SNP host (needs /dev/sev + a local tinfoild with
# dev-launch). Verified on box2 (AMD Turin). It launches debug enclaves with
# random names and cleans them up.
#
# Overridable via env:
#   TINFOIL_CLI_DIR   tinfoil-cli checkout            (default ~/tinfoil-cli)
#   CVMIMAGE_DIR      cvmimage checkout, already built (default ~/cvmimage)
#   TINFOILD_ADMIN    tinfoild admin API             (default http://localhost:8080)
#   VAULT_PORT        port to run the vault on        (default 8473, unused on box2)
#   CVM_VERSION       cvm-version for FetchLegacy cache-hit + SSH inject (default 0.10.1)
#
# Usage:  ./test-e2e-live.sh        (exits non-zero if any check fails)

set -uo pipefail

VAULT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="${TINFOIL_CLI_DIR:-$HOME/tinfoil-cli}"
CVMIMAGE_DIR="${CVMIMAGE_DIR:-$HOME/cvmimage}"
ADMIN="${TINFOILD_ADMIN:-http://localhost:8080}"
PORT="${VAULT_PORT:-8473}"
CVM_VERSION="${CVM_VERSION:-0.10.1}"
export GOTOOLCHAIN=auto

green="\033[32m"; red="\033[31m"; dim="\033[2m"; bold="\033[1m"; rst="\033[0m"
PASS=0; FAIL=0
ok()  { printf "  ${green}✓${rst} %s\n" "$1"; PASS=$((PASS+1)); }
bad() { printf "  ${red}✗${rst} %s\n" "$1"; [ -n "${2:-}" ] && printf "      ${dim}%s${rst}\n" "$2"; FAIL=$((FAIL+1)); }
section() { printf "\n${bold}%s${rst}\n" "$1"; }
die() { echo "FATAL: $1" >&2; [ -n "${2:-}" ] && echo "$2" >&2; exit 1; }

for c in go curl jq ssh openssl base64; do command -v "$c" >/dev/null || die "$c not found on PATH"; done
[ -d "$CLI_DIR" ] || die "tinfoil-cli not found at $CLI_DIR (set TINFOIL_CLI_DIR)"
[ -e /dev/sev ] || die "/dev/sev missing — this test must run on a SEV-SNP host"
curl -fs --max-time 5 "$ADMIN/deployments" >/dev/null || die "tinfoild admin not reachable at $ADMIN"
for f in tinfoilcvm.vmlinuz tinfoilcvm.initrd tinfoilcvm.raw tinfoilcvm.hash; do
  [ -f "$CVMIMAGE_DIR/$f" ] || die "missing $CVMIMAGE_DIR/$f — build the image first (cd $CVMIMAGE_DIR && sudo make build)"
done
ROOTHASH="$(cat "$CVMIMAGE_DIR/tinfoilcvm.hash")"
[ -n "$ROOTHASH" ] || die "empty roothash in $CVMIMAGE_DIR/tinfoilcvm.hash"
# Fail fast if the port is taken (e.g. a leftover vault) — otherwise our svault
# can't bind, the health check passes against the foreign vault, and we hang
# waiting for a measurement in our own (empty) log.
ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE ":${PORT}\$" \
  && die "port ${PORT} is already in use (another vault?) — stop it or set VAULT_PORT=<free port>"

WORK="$(mktemp -d)"
SVAULT="$WORK/svault"; TINCLI="$WORK/tinfoil-cli"; LOG="$WORK/vault.log"
VAULT_PID=""; CAP_ID=""; RUN_ID=""
SECRET="s3cret-$(openssl rand -hex 4)"

# Tear down everything this run spun up (enclaves + vault), on any exit.
cleanup() {
  printf "\n${bold}Teardown${rst}\n"
  for id in "$CAP_ID" "$RUN_ID"; do
    [ -n "$id" ] && { curl -s --max-time 10 -X DELETE "$ADMIN/deployments/$id" >/dev/null 2>&1; echo "  - deleted enclave $id"; }
  done
  if [ -n "$VAULT_PID" ]; then kill "$VAULT_PID" 2>/dev/null; wait "$VAULT_PID" 2>/dev/null; echo "  - stopped vault"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---- vault lifecycle (capture then pinned), reusing one HPKE identity --------
start_vault() { # $1 = pinned measurement
  "$SVAULT" -addr "0.0.0.0:${PORT}" -identity "$WORK/identity.json" -pin-measurement "$1" >"$LOG" 2>&1 &
  VAULT_PID=$!
  curl -fs --retry 40 --retry-connrefused --retry-delay 1 -o /dev/null "http://localhost:${PORT}/health" \
    || die "vault did not become ready" "$(cat "$LOG")"
}
stop_vault() { [ -n "$VAULT_PID" ] && kill "$VAULT_PID" 2>/dev/null; wait "$VAULT_PID" 2>/dev/null; VAULT_PID=""; }

# ---- dev-launch the workload (prints the deployment JSON) ---------------------
devlaunch() { # $1 = name
  jq -n --arg name "$1" --arg cmdline "$CMDLINE" --arg config "$CONFIG_B64" --arg ext "$EXTCONFIG" \
        --arg kernel "$CVMIMAGE_DIR/tinfoilcvm.vmlinuz" --arg initrd "$CVMIMAGE_DIR/tinfoilcvm.initrd" \
        --arg disk "$CVMIMAGE_DIR/tinfoilcvm.raw" \
    '{name:$name, cpus:4, memory:4096, debug:true, skip_manifest:true, config:$config,
      external_config:$ext, custom_cmdline:$cmdline, kernel_file:$kernel, initrd_file:$initrd, disk_file:$disk}' \
  | curl -s --max-time 25 -X POST "$ADMIN/dev-launch" -H 'Content-Type: application/json' --data-binary @-
}

section "Build"
( cd "$VAULT_DIR" && go build -o "$SVAULT" . ) || die "vault build failed"
( cd "$CLI_DIR"   && go build -o "$TINCLI" . ) || die "cli build failed"
ok "built vault + tinfoil-cli"

section "Fixtures"
ssh-keygen -t ed25519 -N '' -C vault-e2e -f "$WORK/id" >/dev/null 2>&1 || die "ssh-keygen failed"
PUBKEY="$(cat "$WORK/id.pub")"

# Public, measured workload config: an nginx container that wants DEMO_SECRET and
# echoes it to its (in-enclave) logs. $DEMO_SECRET stays literal — the container
# shell expands it at runtime, so use a quoted heredoc.
cat > "$WORK/tinfoil-config.yml" <<YAML
cvm-version: ${CVM_VERSION}
cpus: 4
memory: 4096

shim:
  upstream-port: 8080
  tls-mode: self-signed

containers:
  - name: "secret-demo"
    image: "docker.io/library/nginx:alpine"
    restart: always
    read_only: false
    cap_add: ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "KILL"]
    secrets: [DEMO_SECRET]
    command:
      - /bin/sh
      - -c
      - |
        echo "tinfoil-demo: DEMO_SECRET=[\$DEMO_SECRET] len=\${#DEMO_SECRET}"
        nginx -g 'daemon off;'
YAML

# Private external config: SSH key for debug access, a (non-localhost) DOMAIN so
# real attestation runs, and the vault block. The CVM reaches the host vault via
# the qemu SLIRP gateway at 10.0.2.2.
cat > "$WORK/external-config.yml" <<YAML
env:
  DOMAIN: "vault-e2e.box2.tinfoil.sh"

secrets:
  SSH_AUTHORIZED_KEYS: |-
    ${PUBKEY}

vault:
  url: "http://10.0.2.2:${PORT}"
  repo: "demo/workload"
  secrets: [DEMO_SECRET]
YAML

CONFIG_B64="$(base64 -w0 < "$WORK/tinfoil-config.yml")"
EXTCONFIG="$(cat "$WORK/external-config.yml")"
# v0.10.x cmdline template with this build's verity roothash; tinfoild rewrites
# tinfoil-config-hash after it injects the debug SSH container.
CMDLINE="readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 root=/dev/mapper/root roothash=${ROOTHASH} tinfoil-config-hash=0e8b2855e735d401dae037c459b73cc3ed39d545ba9dac7028fdbd2824bed471"
ok "generated keypair, workload config, external config (secret=${SECRET})"

section "Capture measurement (real SEV-SNP quote)"
start_vault 00   # pin to a placeholder; the vault logs every verified quote's measurement
KEY="$(grep -oE 'vault HPKE key: [0-9a-f]+' "$LOG" | awk '{print $4}' | head -1)"
[ -n "$KEY" ] || die "could not read vault HPKE key" "$(cat "$LOG")"
CAP_ID="$(devlaunch "debug-vaulte2e-$(openssl rand -hex 3)" | jq -r '.id // empty')"
[ -n "$CAP_ID" ] || die "capture dev-launch failed"
MEAS=""
for i in $(seq 1 90); do
  MEAS="$(grep -oE 'quote verified, measurement=[0-9a-f]+' "$LOG" | tail -1 | cut -d= -f2)"
  [ -n "$MEAS" ] && break
  st="$(curl -s --max-time 4 "$ADMIN/deployments/$CAP_ID" | jq -r '.status // empty')"
  [ "$st" = failed ] && { MEAS="$(grep -oE 'quote verified, measurement=[0-9a-f]+' "$LOG" | tail -1 | cut -d= -f2)"; break; }
  sleep 2
done
[ -n "$MEAS" ] || die "vault never verified a quote within timeout" "$(tail -5 "$LOG")"
ok "vault verified the enclave's quote; measurement=${MEAS:0:24}…"
curl -s --max-time 8 -X DELETE "$ADMIN/deployments/$CAP_ID" >/dev/null 2>&1; CAP_ID=""
stop_vault

section "Pin + store"
start_vault "$MEAS"
ok "vault restarted, pinned to the captured measurement"
out="$("$TINCLI" vault put DEMO_SECRET --value "$SECRET" --repo demo/workload \
        --vault "http://localhost:${PORT}" --vault-hpke-key "$KEY" 2>&1)"
printf '%s' "$out" | grep -qF "Stored secret DEMO_SECRET" && ok "stored DEMO_SECRET (EHBP)" || bad "store DEMO_SECRET" "$out"

section "Release to a live enclave"
RUN_ID="$(devlaunch "debug-vaulte2e-$(openssl rand -hex 3)" | jq -r '.id // empty')"
[ -n "$RUN_ID" ] || die "run dev-launch failed"
RPORT="$(curl -s --max-time 5 "$ADMIN/deployments/$RUN_ID" | jq -r '.ssh_port // empty')"
status=""
for i in $(seq 1 120); do
  status="$(curl -s --max-time 4 "$ADMIN/deployments/$RUN_ID" | jq -r '.status // empty')"
  [ "$status" = ready ] && break
  [ "$status" = failed ] && break
  sleep 2
done
if [ "$status" = ready ]; then ok "workload booted to ready"
else bad "workload boot" "status=$status; $(curl -s "$ADMIN/deployments/$RUN_ID" | jq -r '[.boot_stages[]|select(.status=="failed")]|.[].detail' 2>/dev/null)"; fi
grep -qE 'released [0-9]+ secret' "$LOG" && ok "vault released the secret" || bad "vault release" "$(tail -3 "$LOG")"

section "Verify inside the enclave"
SSHC="ssh -i $WORK/id -p ${RPORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 root@localhost"
got=""
for i in $(seq 1 15); do
  got="$($SSHC 'docker exec $(docker ps -q --filter name=secret-demo) printenv DEMO_SECRET' 2>/dev/null)"
  [ -n "$got" ] && break
  sleep 2
done
[ "$got" = "$SECRET" ] && ok "container has DEMO_SECRET=$SECRET" || bad "DEMO_SECRET in container" "got: '${got}'"

section "Host never saw the plaintext"
if grep -qF "$SECRET" "$LOG"; then bad "vault log leaked the value"; else ok "vault log shows only the name + a release count, never the value"; fi
grep -qE 'stored "DEMO_SECRET"' "$LOG" && ok "host saw the secret name (expected)" || true

section "Result"
printf "  ${green}%d passed${rst}, ${red}%d failed${rst}\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
