# Secrets vault — Path A runbook (real SEV-SNP, end-to-end)

How to take the prototype from code to a **real SEV-SNP** run: a published, attested
vault CVM, secrets stored by the CLI, and a workload CVM that fetches them at boot with
a genuine quote verified against sigstore provenance. Design: `infra-harness/design/secrets-vault-prototype.md`.

## What's already done vs. what this runbook covers
- **Done (code, dev-validated):** the vault (`/store`, `/secrets`, `/fetch` with the
  `snpVerifier`, embedded sigstore root, `-behind-shim` mode), `tinfoil-cli vault`,
  `cmd/boot` stage 3b, the `Dockerfile` + `tinfoil-config.yml` here.
- **This runbook:** publish the vault image, deploy it as a CVM, store secrets, then
  publish + deploy a workload that fetches them. The two **publish** steps are the only
  hard prerequisites for *real* mode (sigstore provenance needs published images).

## Components
| Repo / path | Role |
|---|---|
| `confidential-secrets-vault` (here) | the vault CVM workload |
| `cvmimage` (`tinfoil/cmd/boot`) | boot stage 3b — must contain our changes for the workload image |
| `tinfoil-cli` (`vault` cmd) | developer stores secrets |
| your `confidential-*` workload repo | the thing that fetches secrets at boot |

Deploy/CLI specifics below are written generically — use your org's normal deploy flow
(`tinfoil-cli`/`tinctl`/dashboard) where noted.

---

## Phase 1 — Publish the vault image
1. **Resolve the EHBP dep** (the prototype pins it via a local `replace`):
   ```bash
   cd confidential-secrets-vault
   go mod edit -dropreplace=github.com/tinfoilsh/encrypted-http-body-protocol
   go get github.com/tinfoilsh/encrypted-http-body-protocol@v0.2.0   # the version the checkout was on
   go mod tidy && go build ./...
   ```
2. **Pin base-image digests** in `Dockerfile` (`golang:1.26-alpine@sha256:…`, `alpine:3.23@sha256:…`), like `confidential-model-router`.
3. **Build + publish with attestation.** Add a release workflow mirroring
   `confidential-model-router/.github/workflows/` so CI builds the image and emits a
   **sigstore attestation** → `ghcr.io/tinfoilsh/confidential-secrets-vault@sha256:<digest>`.
4. **Pin the image** in `tinfoil-config.yml` (replace the `@sha256:0000…` placeholder).

## Phase 2 — Deploy the vault as a CVM
1. Provide an **external-config** with `env.DOMAIN` (e.g. `secrets.<org>.tinfoil.sh`) and
   the cert-proxy token your deployments use — same as any `confidential-*` deploy. The
   vault needs **no** secrets injected.
2. **Deploy** `confidential-secrets-vault` to a SEV-SNP host (box2 is fine — CPU-only).
3. **Verify boot:** the deployment reaches `ready`, gets a TLS cert, and `/health` answers.
   Watch the vault log for **egress-blocked** VCEK/bundle fetches and adjust the
   `networks.egress.allow` list (`kdsintf.amd.com` / `kds-proxy.tinfoil.sh` /
   `api-github-proxy.tinfoil.sh`) until clean.
4. The vault is now live at `https://secrets.<org>.tinfoil.sh`, running `-behind-shim`
   (shim terminates EHBP + serves the HPKE key; the vault verifies workloads via SNP).

## Phase 3 — Store secrets
```bash
tinfoil-cli vault put DB_PASSWORD --value '…' \
  --repo <your-workload-repo> --vault secrets.<org>.tinfoil.sh
```
This does a real `SecureClient.Verify(vault)` (works because the vault image is now
published/attested — **no `--vault-hpke-key`**), EHBP-seals to the vault's attested key,
and stores under `(<your-workload-repo>, DB_PASSWORD)`. `vault ls --repo …` to confirm.

> Only register a repo **you control** (fork a base image if needed), and never one that
> ships a secret-exposing build (e.g. SSH/debug) — anything that repo publishes can fetch
> these secrets.

## Phase 4 — Publish the workload image (with boot stage 3b)
1. **Land the `cmd/boot` changes** (vault fetch stage) in the `cvmimage` your workload
   builds from — merge to `cvmimage` `main`, or point your workload at a branch/fork that
   has them. Without this the workload won't fetch.
2. **Publish the workload** `confidential-*` repo as a **sigstore-attested release** (so
   the vault can prove its provenance). Its release must build on the stage-3b cvmimage.
3. Add a `vault:` block to the **workload's external-config** (all non-secret):
   ```yaml
   vault:
     url: https://secrets.<org>.tinfoil.sh
     repo: <your-workload-repo>      # must match where you stored the secrets
     secrets: [DB_PASSWORD]
     digest: <release-digest>         # optional; vault uses latest if omitted
     # dev: true                      # ONLY for a --dev-verify vault; omit for real mode
   ```
   Each container that should receive a secret must also list it in its `secrets:` (the
   per-container scoping `buildEnv` already enforces).

## Phase 5 — Deploy the workload + verify
1. **Deploy** the workload to a SEV-SNP host.
2. At boot, `cmd/boot` stage 3b sends the **real quote + repo** to the vault; the
   `snpVerifier` runs `VerifyWithVCEK` + sigstore provenance, seals the secrets to `pk_W`,
   and `cmd/boot` decrypts and injects them as container env.
3. **Verify:** `tinctl watch <id>` shows the **`vault-secrets`** stage `OK`; the container
   comes up with the secret in its environment.

---

## Troubleshooting
- **`vault-secrets` fails at boot** — check the vault log: egress-blocked (fix the
  allowlist), `provenance:` (the workload repo/digest has no matching sigstore bundle —
  is it a published release?), or `measurement mismatch` (the running image ≠ the
  attested release).
- **Empty secrets** — the workload's proven `repo` must equal the repo the secrets were
  stored under; and the container must declare the names in its `secrets:`.
- **`SecureClient.Verify` fails on `put`** — the vault image isn't published/attested yet;
  finish Phase 1 (or use `--vault-hpke-key <key>` for a non-real write).
- **Dev-launch won't work in real mode** — locally built images have no sigstore bundle;
  real mode requires a published release.

## Fast local dev loop (no publishing, not real SEV)
For iterating without the publish pipeline, run the vault standalone with `--dev-verify`
and use the e2e harness — see `./test-e2e.sh` (builds the vault + CLI + `cmd/boot`, runs
store → list → delete → fetch with real crypto, dev attestation).
