package main

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/base64"
	"os"
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

// box2 (EPYC 9275F, Turin) reference quote — see TURIN.md. The report's only
// "interesting" content is its public REPORTDATA (a per-boot HPKE/TLS key); the
// VCEK is a public AMD cert. Both are safe to commit as fixtures.
const (
	box2Measurement = "4b29a3b0804ec7dbd70309fd556d94f796ad8dfe7e87fba14a0fcd9644e000c7fc0a4f834bc249b18f3f542a0412d1ac"
	box2HPKEKey      = "e84dd2d9c5ecff32a4d829bd1375652d3f540ceeb204644c1761548132273735"
	// What snphost (AMD's own tool) reports for box2 — the URL go-sev-guest gets wrong.
	box2VCEKURL = "https://kds-proxy.tinfoil.sh/vcek/v1/Turin/6bb1229b7692b710?fmcSPL=1&blSPL=1&teeSPL=1&snpSPL=4&ucodeSPL=82"
)

func box2Doc(t *testing.T) (*attestation.Document, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/box2-turin-report.bin")
	require.NoError(t, err)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err = zw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return &attestation.Document{Format: attestation.SevGuestV2, Body: base64.StdEncoding.EncodeToString(buf.Bytes())}, raw
}

// TestTurinVCEKURL locks in the chip-ID and TCB-layout fixes (bugs #1 and #2):
// Turin's 8-byte chip ID and its FMC-shifted TCB bytes must produce the same
// VCEK URL AMD's snphost does.
func TestTurinVCEKURL(t *testing.T) {
	_, raw := box2Doc(t)
	report, err := abi.ReportToProto(raw)
	require.NoError(t, err)
	id := report.GetChipId()
	require.Len(t, id, 64)
	require.True(t, allZero(id[8:]), "Turin chip ID is 8 bytes left-aligned in the 64-byte field")
	require.Equal(t, box2VCEKURL, turinVCEKURL(id[:8], report.GetReportedTcb()))
	require.Equal(t, sevsnp.SevProduct_SEV_PRODUCT_TURIN, reportProduct(report))
}

// TestTurinVerifyReport locks in the chain + raw-signature verification (bug #3
// workaround): given the (committed) VCEK, the report verifies offline and we
// recover the right measurement and REPORTDATA HPKE key.
func TestTurinVerifyReport(t *testing.T) {
	doc, _ := box2Doc(t)
	vcek, err := os.ReadFile("testdata/box2-turin-vcek.der")
	require.NoError(t, err)
	meas, hpke, err := verifyReport(doc, vcek)
	require.NoError(t, err)
	require.Equal(t, box2Measurement, meas)
	require.Equal(t, box2HPKEKey, hpke)

	// The chain check is real: this Turin VCEK does not chain to the Genoa ASK.
	gAsk, _, err := amdChain(sevsnp.SevProduct_SEV_PRODUCT_GENOA)
	require.NoError(t, err)
	c, err := x509.ParseCertificate(vcek)
	require.NoError(t, err)
	require.Error(t, c.CheckSignatureFrom(gAsk))
}

// TestTurinFetchAndVerifyLive ties it together against KDS: fetchVCEK must build
// the right URL, download the VCEK, and verifyReport must accept it. Gated:
//
//	VAULT_LIVE_SNP=1 go test -run TurinFetchAndVerifyLive
func TestTurinFetchAndVerifyLive(t *testing.T) {
	if os.Getenv("VAULT_LIVE_SNP") == "" {
		t.Skip("set VAULT_LIVE_SNP=1 to fetch the VCEK from KDS")
	}
	doc, _ := box2Doc(t)
	vcek, err := fetchVCEK(doc)
	require.NoError(t, err)
	meas, hpke, err := verifyReport(doc, vcek)
	require.NoError(t, err)
	require.Equal(t, box2Measurement, meas)
	require.Equal(t, box2HPKEKey, hpke)
}
