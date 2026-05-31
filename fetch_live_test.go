package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

// TestSNPVerifierAgainstLiveBundle runs the real release verifier against a live
// production SEV-SNP attestation bundle (atc.tinfoil.sh), and cross-checks that
// the pk_W it extracts matches tinfoil-go's canonical full verification. Needs
// network; gated so the normal suite stays offline.
//
//	VAULT_LIVE_SNP=1 go test -run Live -v ./...
func TestSNPVerifierAgainstLiveBundle(t *testing.T) {
	if os.Getenv("VAULT_LIVE_SNP") == "" {
		t.Skip("set VAULT_LIVE_SNP=1 to verify against a live SEV-SNP bundle (needs network)")
	}
	const repo = "tinfoilsh/confidential-model-router" // inference.tinfoil.sh

	bundle, err := attestation.FetchBundle()
	require.NoError(t, err)
	require.Equal(t, attestation.SevGuestV2, bundle.EnclaveAttestationReport.Format, "expected a SEV-SNP bundle")

	v, err := newSNPVerifier(nil)
	require.NoError(t, err)

	gotRepo, pkW, err := v.verify(&fetchRequest{Repo: repo, Bundle: bundle})
	require.NoError(t, err)
	require.Equal(t, repo, gotRepo)
	require.NotEmpty(t, pkW)

	// The canonical full verifier (incl. the cert check we skip at boot) must
	// extract the same attested pk_W from REPORTDATA.
	gt, err := client.NewSecureClient(bundle.Domain, repo).VerifyFromBundle(bundle)
	require.NoError(t, err)
	require.Equal(t, gt.HPKEPublicKey, pkW)

	// Exercise the GitHub sigstore-bundle fetch path: drop the carried bundle so
	// the vault must fetch it for (repo, digest), and confirm it still verifies.
	stripped := *bundle
	stripped.SigstoreBundle = nil
	_, pkW2, err := v.verify(&fetchRequest{Repo: repo, Bundle: &stripped})
	require.NoError(t, err)
	require.Equal(t, pkW, pkW2)

	t.Logf("verified live SEV-SNP bundle: domain=%s repo=%s pk_W=%s (also via vault-fetched sigstore bundle)", bundle.Domain, gotRepo, pkW)
}
