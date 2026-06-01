package main

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

// TestVerifyReportAgainstLiveQuote exercises the vault's go-sev-guest based
// verification against a real production SEV-SNP quote (atc.tinfoil.sh, a Genoa
// host): the measurement and REPORTDATA-bound HPKE key it extracts must match
// tinfoil-go's own verifier, both with the bundle's VCEK and with one fetched
// from KDS. (box2 is Turin with a masked chip ID — that path is exercised live.)
// Gated (needs network):
//
//	VAULT_LIVE_SNP=1 go test -run VerifyReport -v ./...
func TestVerifyReportAgainstLiveQuote(t *testing.T) {
	if os.Getenv("VAULT_LIVE_SNP") == "" {
		t.Skip("set VAULT_LIVE_SNP=1 to run against a live SEV-SNP quote")
	}
	bundle, err := attestation.FetchBundle()
	require.NoError(t, err)
	require.Equal(t, attestation.SevGuestV2, bundle.EnclaveAttestationReport.Format)

	vcek, err := base64.StdEncoding.DecodeString(bundle.VCEK)
	require.NoError(t, err)

	// Ground truth: tinfoil-go's verifier (Genoa).
	ev, err := bundle.EnclaveAttestationReport.VerifyWithVCEK(vcek)
	require.NoError(t, err)
	want := ev.Measurement.Registers[0]
	t.Logf("measurement: %s", want)

	// Our verifier, with the supplied VCEK, must agree.
	meas, hpke, err := verifyReport(bundle.EnclaveAttestationReport, vcek)
	require.NoError(t, err)
	require.Equal(t, want, meas)
	require.Equal(t, ev.HPKEPublicKey, hpke)

	// And with a VCEK fetched from KDS (this host doesn't mask its chip ID).
	fetched, err := fetchVCEK(bundle.EnclaveAttestationReport)
	require.NoError(t, err)
	meas2, hpke2, err := verifyReport(bundle.EnclaveAttestationReport, fetched)
	require.NoError(t, err)
	require.Equal(t, want, meas2)
	require.Equal(t, ev.HPKEPublicKey, hpke2)
}
