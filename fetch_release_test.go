package main

import (
	"os"
	"testing"

	"github.com/tinfoilsh/tinfoil-go/verifier/github"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

// TestVerifyPublishedRelease runs the vault's own verification primitives
// (fetch attestation bundle + sigstore-verify against the embedded trust root)
// against a published release, confirming the snpVerifier can consume it. Gated:
//   VAULT_VERIFY_REPO=<owner>/confidential-secrets-vault go test -run VerifyPublishedRelease -v
func TestVerifyPublishedRelease(t *testing.T) {
	repo := os.Getenv("VAULT_VERIFY_REPO")
	if repo == "" {
		t.Skip("set VAULT_VERIFY_REPO to verify a published release")
	}
	digest, err := github.FetchLatestDigest(repo)
	if err != nil {
		t.Fatalf("FetchLatestDigest: %v", err)
	}
	t.Logf("latest digest: %s", digest)

	bundle, err := github.FetchAttestationBundle(repo, digest)
	if err != nil {
		t.Fatalf("FetchAttestationBundle: %v", err)
	}
	sig, err := sigstore.NewClientFromJSON(trustedRootJSON)
	if err != nil {
		t.Fatalf("sigstore client: %v", err)
	}
	meas, err := sig.VerifyAttestation(bundle, repo, digest)
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	t.Logf("verified release measurement: %+v", meas)
}
