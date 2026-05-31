// Command fetch-demo simulates a workload's boot-release fetch: it generates a
// per-boot HPKE keypair, asks the vault for its repo's secrets, opens the sealed
// response with sk_W, and prints the recovered {name: value} JSON. For local
// testing against a vault running with --dev-verify.
//
// The wire structs and the info string below must match the vault
// (confidential-secrets-vault/fetch.go); the e2e test fails loudly if they drift.
package main

import (
	"bytes"
	"crypto/hpke"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

const fetchInfo = "tinfoil-secrets-vault/fetch/v1"

type fetchRequest struct {
	Repo       string   `json:"repo"`
	PKW        string   `json:"pk_w"`
	SecretRefs []string `json:"secret_refs"`
	Nonce      string   `json:"nonce"`
}

type fetchResponse struct {
	Enc        []byte `json:"enc"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      string `json:"nonce"`
}

func main() {
	vault := flag.String("vault", "http://127.0.0.1:8099", "vault base URL")
	repo := flag.String("repo", "", "repo to fetch secrets for")
	secrets := flag.String("secrets", "", "comma-separated secret names")
	flag.Parse()
	if *repo == "" || *secrets == "" {
		log.Fatal("usage: fetch-demo -repo <repo> -secrets a,b,c [-vault URL]")
	}

	wl, err := identity.NewIdentity() // per-boot HPKE keypair (pk_W / sk_W)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	reqBody, _ := json.Marshal(fetchRequest{
		Repo: *repo, PKW: wl.MarshalPublicKeyHex(),
		SecretRefs: strings.Split(*secrets, ","), Nonce: "demo-nonce",
	})
	resp, err := http.Post(strings.TrimRight(*vault, "/")+"/fetch", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		log.Fatalf("fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("fetch failed: HTTP %d", resp.StatusCode)
	}
	var fr fetchResponse
	if err := json.NewDecoder(resp.Body).Decode(&fr); err != nil {
		log.Fatalf("decode: %v", err)
	}

	r, err := hpke.NewRecipient(fr.Enc, wl.PrivateKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(fetchInfo))
	if err != nil {
		log.Fatalf("recipient: %v", err)
	}
	plain, err := r.Open(nil, fr.Ciphertext)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	fmt.Print(string(plain))
}
