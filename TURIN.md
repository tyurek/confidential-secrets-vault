# Verifying SEV-SNP quotes on AMD Turin (Zen 5)

The vault verifies a workload's SEV-SNP attestation report before releasing
secrets to it. For this demo, that verification has to work on **AMD Turin (Zen 5)** hosts —
e.g. `box2.tinfoil.sh`, an EPYC 9275F. This note records why Turin needs special
handling and exactly what `vcek.go` does about it, because none of it is obvious
and the failure modes all looked like something else.

## Why not just use tinfoil-go?

`tinfoil-go`'s verifier (`verifier/attestation`) **hardcodes Genoa**: it forces
`opts.Product = SEV_PRODUCT_GENOA` and only embeds the Genoa `cert_chain`. It
cannot verify a Turin report at all. So the vault verifies SEV-SNP itself, using
`go-sev-guest` directly for the report-signature primitive and `crypto/x509` for
the certificate chain. (`tinfoil-go` is still used for everything else.)

## Why not just use a newer go-sev-guest?

We pin `go-sev-guest v0.14.1` (the latest *release*, and what `tinfoil-go`
depends on). Its `main` branch (as of 2025-11) adds v5-report parsing and fixes
**one** of the three issues below (#2), but still ships #1 and #3 — so it would
not remove the workarounds, only one of them, at the cost of depending on an
unreleased commit. Verified empirically against `box2`'s real quote. If
go-sev-guest later releases full Turin support, the `fetchTurinVCEK` /
`turinVCEKURL` and manual-chain code here can be reconsidered.

## The three Turin gaps in go-sev-guest v0.14.1

All three were found while verifying a real `box2` quote. The first two corrupt
the VCEK *fetch*; the third breaks the *verify*. `crypto/x509` parses the Turin
VCEK fine — only go-sev-guest's SEV-specific code trips.

### 1. Chip ID is 8 bytes on Turin, not 64

The report's `CHIP_ID` field is 64 bytes. On Genoa/Milan the whole field is the
hardware ID; on **Turin it's an 8-byte ID left-aligned and zero-padded**
(`snphost show identifier` → `6BB1229B7692B710`). go-sev-guest hex-encodes all
64 bytes into the KDS URL:

```
.../vcek/v1/Turin/6bb1229b7692b710000000…000   →  404 Not Found
.../vcek/v1/Turin/6bb1229b7692b710           →  200 (correct)
```
On 5th-Gen EPYC Turin, the per-chip identifier is an 8-byte Public Serial Number.

Full command: `sudo /home/ubuntu/.cargo/bin/snphost show identifier`

**Fix:** when the trailing 56 bytes are zero, use the first 8
(`fetchVCEK`, guarded by `allZero(id[8:])`).

### 2. TCB layout shifted by a new FMC field

A VCEK is per-(chip, TCB). The TCB component levels go in the URL query. Turin
**inserts a new FMC (Firmware Management Component) byte at index 0**, shifting
everything:

```
TCB_VERSION bytes:  Genoa = [BL, TEE, _, _, _, _, _, MICROCODE]
                    Turin = [FMC, BL, TEE, SNP, _, _, _, MICROCODE]
```

go-sev-guest v0.14.1 decodes the Genoa layout, so it asks KDS for the wrong
TCB's VCEK. KDS returns *a* cert (so the fetch "succeeds"), but it's the wrong
key, and the report-signature check then fails with a bare
`x509: ECDSA verification failure` — which looks like a corrupt report, not a
wrong cert. (go-sev-guest `main` fixes this one.)

**Fix:** build the URL ourselves from the report's `ReportedTcb`
(`turinVCEKURL`), mapping `fmcSPL=byte0, blSPL=byte1, teeSPL=byte2,
snpSPL=byte3, ucodeSPL=byte7`. Locked in by `TestTurinVCEKURL` against the exact
URL AMD's `snphost` produces.

### 3. VCEK cert carries the FMC OID `…1.3.9`, which SnpAttestation rejects

Turin VCEK certs include an extra non-critical extension —
`1.3.6.1.4.1.3704.1.3.9` (the FMC security patch level). go-sev-guest's
`verify.SnpAttestation` walks the cert's `…1.3.x` extensions to cross-check the
cert TCB against the report TCB and hard-errors on the unknown OID:

```
not an AMD KDS OID: 1.3.6.1.4.1.3704.1.3.9
```

go-sev-guest `main` still ships only `.3.1`–`.3.8`, so this is unfixed there too.

**Fix:** don't use `SnpAttestation`. Verify the chain and signature directly
(`verifyReport`):

- **Chain** — `crypto/x509`'s `CheckSignatureFrom` (VCEK ← ASK ← ARK). It
  verifies signatures and CA status only; it does not parse the SEV TCB
  extensions, so the unknown OID is ignored. The ARK/ASK come from go-sev-guest's
  own embedded AMD CA bundles (`trust.AskArk{Genoa,Turin}VcekBytes`) — the same
  roots its `SnpAttestation` would use, so no certs are vendored here.
- **Report signature** — `verify.SnpReportSignature(rawBytes, vcek)` on the
  **raw** report bytes. (Don't go through the proto: go-sev-guest's
  `ReportToAbiBytes` drops Turin v5 fields, so a proto round-trip changes the
  signed component and fails ECDSA. The raw path reads fixed offsets and is
  version-independent.)
- **Measurement / REPORTDATA** — read from the parsed proto (fixed early
  offsets, correct for v5): measurement, and the HPKE key at `REPORTDATA[32:64]`.

## What we verify (and what we deliberately skip)

We prove: the report is **signed by a VCEK that AMD issued for this chip at this
TCB** (chain to the embedded AMD root), and the report binds the measurement and
the enclave's HPKE key. We skip `SnpAttestation`'s cert-vs-report TCB
cross-check (the part that needs the `.3.9` OID). That check is **redundant
here**: we fetch the VCEK using the report's *own* reported TCB, and a TCB-
rollback would change the signing key and fail the signature check — so a forged
or downgraded report cannot pass. Authorization on top of this (a pinned
measurement, or sigstore provenance) is unchanged.

## Trust anchor

The root of trust is go-sev-guest's embedded AMD CA bundle for the product
(`trust.AskArkTurinVcekBytes` / `trust.AskArkGenoaVcekBytes`, sourced by
go-sev-guest from `kdsintf.amd.com/vcek/v1/<product>/cert_chain`). We reuse those
rather than vendoring our own — they're the exact roots `SnpAttestation` trusts,
so this verification is anchored identically to the standard path; we only swap
out the OID-parsing step. The per-chip VCEK is fetched per-boot from KDS (cached
via `kds-proxy.tinfoil.sh`). (Sanity-checked once: the Turin ARK matches the
independent copy in `oak_attestation_verification/data/ark_turin.pem`.)

## Tests

`turin_test.go`, against a committed real `box2` report + VCEK
(`testdata/box2-turin-*`):

- `TestTurinVCEKURL` — chip-ID + TCB URL (bugs #1, #2), offline.
- `TestTurinVerifyReport` — chain + raw-signature verify + extraction (bug #3),
  offline; also asserts the Genoa chain rejects a Turin VCEK.
- `TestTurinFetchAndVerifyLive` — end-to-end fetch from KDS + verify; gated on
  `VAULT_LIVE_SNP=1`.
