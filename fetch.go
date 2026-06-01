package main

import (
	"crypto/ecdh"
	"crypto/hpke"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/google/go-sev-guest/proto/sevsnp"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	"github.com/tinfoilsh/tinfoil-go/verifier/github"
	"github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

// fetchInfo binds an HPKE-sealed release to this protocol/version. The workload
// must open with the same info string.
const fetchInfo = "tinfoil-secrets-vault/fetch/v1"

// fetchRequest is what a booting workload sends to /fetch. None of it is secret
// — the attestation evidence and pk_W are all public — so the request itself is
// not EHBP-sealed; confidentiality comes from sealing the *response* to pk_W.
type fetchRequest struct {
	Repo       string   `json:"repo"`
	SecretRefs []string `json:"secret_refs"`
	Nonce      string   `json:"nonce"`

	// Attestation evidence, consumed by snpVerifier.
	Bundle *attestation.Bundle `json:"bundle,omitempty"`
	// Claimed per-boot HPKE key (hex). Authoritative pk_W comes from the quote's
	// REPORTDATA; this field is only used by devVerifier (no attestation).
	PKW string `json:"pk_w,omitempty"`
}

// fetchResponse carries the requested secrets HPKE-sealed to pk_W. The host that
// proxies it sees only ciphertext; only the workload holding sk_W can open it.
type fetchResponse struct {
	Enc        []byte `json:"enc"`        // HPKE encapsulated key
	Ciphertext []byte `json:"ciphertext"` // {name: value, ...} sealed to pk_W
	Nonce      string `json:"nonce"`
}

// verifier authorizes a release: it validates the request's attestation evidence
// and returns the *proven* repo and the *attested* pk_W to seal to. The handler
// trusts only what verify returns, never the raw request fields — so the
// verifier is the single security gate of the release path.
type verifier interface {
	verify(req *fetchRequest) (repo, pkW string, err error)
}

func fetchHandler(st *store, v verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req fetchRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		repo, pkW, err := v.verify(&req)
		if err != nil {
			http.Error(w, "attestation rejected: "+err.Error(), http.StatusForbidden)
			return
		}

		plaintext, err := json.Marshal(st.get(repo, req.SecretRefs))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		enc, ct, err := sealTo(pkW, plaintext)
		if err != nil {
			http.Error(w, "seal failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("released %d secret(s) for %s", len(req.SecretRefs), repo)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fetchResponse{Enc: enc, Ciphertext: ct, Nonce: req.Nonce})
	}
}

// sealTo HPKE-seals plaintext to a workload's per-boot public key (hex, raw
// X25519). Suite matches identity.NewIdentity: X25519 / HKDF-SHA256 / AES-256-GCM.
func sealTo(pkHex string, plaintext []byte) (enc, ct []byte, err error) {
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding pk_w: %w", err)
	}
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(pkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing pk_w: %w", err)
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(fetchInfo))
	if err != nil {
		return nil, nil, err
	}
	ct, err = sender.Seal(nil, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}

// devVerifier trusts the repo and pk_W asserted in the request with no
// attestation check. Testing only (enabled by --dev-verify): any caller can
// claim any repo, so it must never gate real secrets.
type devVerifier struct{}

func (devVerifier) verify(req *fetchRequest) (string, string, error) {
	if req.Repo == "" || req.PKW == "" {
		return "", "", fmt.Errorf("repo and pk_w are required")
	}
	return req.Repo, req.PKW, nil
}

// snpVerifier is the real release gate. It mirrors the cert-free subset of
// tinfoil-go's SecureClient verification (the workload has no TLS cert yet at
// boot stage 3b, and pk_W's authenticity comes from the SNP signature over
// REPORTDATA, not the cert):
//
//  1. sigstore: the bundle proves the code was built from repo@digest → codeMeasurement
//  2. SNP quote: VerifyWithVCEK → { enclave measurement, pk_W from REPORTDATA }
//  3. bind them: codeMeasurement == enclave measurement
//
// The proven repo is the tenant key; pk_W is the hardware-attested key to seal to.
type snpVerifier struct {
	sig   *sigstore.Client
	repos map[string]bool // nil → any repo that proves provenance
}

//go:embed trusted_root.json
var trustedRootJSON []byte

func newSNPVerifier(repos []string) (*snpVerifier, error) {
	// Embed the sigstore trust root rather than fetching it over TUF, so the
	// vault's only egress is the VCEK + the GitHub attestation bundle.
	sig, err := sigstore.NewClientFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("sigstore client: %w", err)
	}
	var set map[string]bool
	if len(repos) > 0 {
		set = make(map[string]bool, len(repos))
		for _, r := range repos {
			set[r] = true
		}
	}
	return &snpVerifier{sig: sig, repos: set}, nil
}

func (v *snpVerifier) verify(req *fetchRequest) (string, string, error) {
	if req.Bundle == nil || req.Bundle.EnclaveAttestationReport == nil {
		return "", "", fmt.Errorf("attestation bundle required")
	}
	if v.repos != nil && !v.repos[req.Repo] {
		return "", "", fmt.Errorf("repo %q not authorized", req.Repo)
	}

	// Provenance: prove the running code was built from req.Repo. The workload
	// may carry its sigstore bundle; if not, fetch it from GitHub for the
	// (repo, digest) it claims (digest defaults to the repo's latest release).
	var err error
	sigBundle, digest := req.Bundle.SigstoreBundle, req.Bundle.Digest
	if len(sigBundle) == 0 {
		if digest == "" {
			if digest, err = github.FetchLatestDigest(req.Repo); err != nil {
				return "", "", fmt.Errorf("latest digest for %s: %w", req.Repo, err)
			}
		}
		if sigBundle, err = github.FetchAttestationBundle(req.Repo, digest); err != nil {
			return "", "", fmt.Errorf("fetch sigstore bundle: %w", err)
		}
	}
	codeMeasurement, err := v.sig.VerifyAttestation(sigBundle, req.Repo, digest)
	if err != nil {
		return "", "", fmt.Errorf("provenance: %w", err)
	}

	vcek, err := bundleVCEK(req.Bundle)
	if err != nil {
		return "", "", fmt.Errorf("vcek: %w", err)
	}
	ev, err := req.Bundle.EnclaveAttestationReport.VerifyWithVCEK(vcek)
	if err != nil {
		return "", "", fmt.Errorf("quote: %w", err)
	}

	if err := codeMeasurement.Equals(ev.Measurement); err != nil {
		return "", "", fmt.Errorf("code/enclave measurement mismatch: %w", err)
	}
	if ev.HPKEPublicKey == "" {
		return "", "", fmt.Errorf("quote carries no HPKE key in REPORTDATA")
	}
	return req.Repo, ev.HPKEPublicKey, nil
}

// pinVerifier verifies the SEV-SNP quote for real (VerifyWithVCEK) but checks the
// measurement against a pinned value instead of deriving the repo via sigstore.
// For dev-launched workloads that have no published provenance — real attestation,
// pinned identity. `repo` is taken as the (trusted) storage label.
type pinVerifier struct {
	measurement string // expected SEV-SNP measurement (hex, the quote's register 0)
}

func (p pinVerifier) verify(req *fetchRequest) (string, string, error) {
	if req.Bundle == nil || req.Bundle.EnclaveAttestationReport == nil {
		return "", "", fmt.Errorf("attestation bundle required")
	}
	vcek, err := bundleVCEK(req.Bundle)
	if err != nil {
		return "", "", fmt.Errorf("vcek: %w", err)
	}
	got, hpke, err := verifyReport(req.Bundle.EnclaveAttestationReport, vcek, sevsnp.SevProduct_SEV_PRODUCT_TURIN)
	if err != nil {
		return "", "", fmt.Errorf("quote: %w", err)
	}
	log.Printf("fetch: SEV-SNP quote verified, measurement=%s", got)
	if !strings.EqualFold(got, p.measurement) {
		return "", "", fmt.Errorf("measurement %s not pinned (want %s)", got, p.measurement)
	}
	if hpke == "" {
		return "", "", fmt.Errorf("quote carries no HPKE key in REPORTDATA")
	}
	return req.Repo, hpke, nil
}
