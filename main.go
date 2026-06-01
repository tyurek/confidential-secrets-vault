// Command confidential-secrets-vault is the prototype secrets vault (see
// design/secrets-vault-prototype.md). It holds developer secrets in RAM, keyed
// by repo, and hands them out end-to-end encrypted so the host never sees
// plaintext: /store (EHBP), /secrets (list/delete), /fetch (verify + seal).
//
// Standalone (testing) it terminates EHBP itself. Deployed as a CVM behind the
// tinfoil shim (-behind-shim), the shim does EHBP and serves the HPKE key, so
// the vault reads plaintext /store.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	idFile := flag.String("identity", "vault_identity.json", "HPKE identity file (standalone mode only; generated if absent)")
	devVerify := flag.Bool("dev-verify", false, "INSECURE: trust the repo/pk_w a workload claims at /fetch without attestation (testing only)")
	pinMeasurement := flag.String("pin-measurement", "", "verify the SEV-SNP quote for real but accept any workload whose measurement equals this hex (no sigstore provenance) — for dev-launched workloads")
	behindShim := flag.Bool("behind-shim", false, "deployed behind the tinfoil shim: the shim does EHBP and serves the HPKE key, so read plaintext /store and don't serve /.well-known/hpke-keys")
	flag.Parse()

	var v verifier
	var err error
	switch {
	case *devVerify:
		v = devVerifier{}
		log.Printf("WARNING: --dev-verify enabled; /fetch trusts claimed repo/pk_w without attestation")
	case *pinMeasurement != "":
		v = pinVerifier{measurement: *pinMeasurement}
		log.Printf("pin-measurement mode: releasing to verified SEV-SNP quotes with measurement %s", *pinMeasurement)
	default:
		if v, err = newSNPVerifier(nil); err != nil {
			log.Fatalf("snp verifier: %v", err)
		}
	}

	// Standalone (testing) the vault does its own EHBP and serves its key, so it
	// needs an HPKE identity. Behind the shim, the shim owns all of that.
	var id *identity.Identity
	if !*behindShim {
		if id, err = identity.FromFile(*idFile); err != nil {
			log.Fatalf("identity: %v", err)
		}
		log.Printf("vault HPKE key: %s", id.MarshalPublicKeyHex())
	}

	log.Printf("secrets vault listening on %s (behind-shim=%v)", *addr, *behindShim)
	log.Fatal(http.ListenAndServe(*addr, newMux(id, newStore(), v, *behindShim)))
}

type storeRequest struct {
	Repo  string `json:"repo"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

func newMux(id *identity.Identity, st *store, v verifier, behindShim bool) http.Handler {
	mux := http.NewServeMux()

	storeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Standalone: the EHBP middleware passes un-encapsulated requests straight
		// through, so require the encapsulation header — its presence means the
		// body was decrypted, never plaintext the host could have read. Behind the
		// shim the shim already decrypted (and consumed the header), so the body
		// is trusted plaintext.
		if !behindShim && r.Header.Get(protocol.EncapsulatedKeyHeader) == "" {
			http.Error(w, "store requests must be EHBP-encrypted", http.StatusBadRequest)
			return
		}
		var req storeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Repo == "" || req.Name == "" {
			http.Error(w, "repo and name are required", http.StatusBadRequest)
			return
		}
		st.put(req.Repo, req.Name, req.Value)
		log.Printf("stored %q for %s", req.Name, req.Repo)
		w.WriteHeader(http.StatusOK)
	})

	if behindShim {
		mux.Handle("/store", storeHandler) // shim already EHBP-decrypted
	} else {
		mux.HandleFunc(protocol.KeysPath, id.ConfigHandler)
		mux.Handle("/store", id.Middleware()(storeHandler))
	}

	// /secrets (GET list, DELETE) move only names, never a value, so they are
	// not behind the EHBP middleware. Caller authentication is the noted
	// prototype gap — anyone reachable can list/delete a repo's secret names.
	mux.HandleFunc("/secrets", func(w http.ResponseWriter, r *http.Request) {
		repo := r.URL.Query().Get("repo")
		if repo == "" {
			http.Error(w, "repo is required", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string][]string{"secrets": st.names(repo)})
		case http.MethodDelete:
			name := r.URL.Query().Get("name")
			if name == "" {
				http.Error(w, "name is required", http.StatusBadRequest)
				return
			}
			if !st.delete(repo, name) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// /fetch is the boot-release path: the verifier validates the workload's
	// attestation and returns (repo, pk_W); the handler seals that repo's
	// requested secrets to pk_W. See design/secrets-vault-prototype.md §3.
	mux.HandleFunc("/fetch", fetchHandler(st, v))

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	return mux
}
