package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFetchIsolatesTenantsWithSharedKeyNames covers two different orgs sharing
// one vault, each with an identically-named secret (API_KEY) holding a different
// value. Secrets are keyed by repo (the tenant), so each org's attested workload
// must get its own value and never the other's — and a name that only exists in
// the other tenant must not resolve.
func TestFetchIsolatesTenantsWithSharedKeyNames(t *testing.T) {
	st := newStore()
	st.put("orgA/workload", "API_KEY", "key-AAA")
	st.put("orgA/workload", "DB_URL", "postgres://a/only")
	st.put("orgB/workload", "API_KEY", "key-BBB") // same name, different value
	ts := httptest.NewServer(newMux(newID(t), st, devVerifier{}, false))
	defer ts.Close()

	// fetchAPIKey runs a workload attesting as `repo` and returns the API_KEY it
	// receives, opened with its own per-boot key.
	fetchAPIKey := func(repo string) map[string]string {
		wl := newID(t)
		resp, fr := doFetch(t, ts.URL, fetchRequest{
			Repo: repo, PKW: wl.MarshalPublicKeyHex(),
			SecretRefs: []string{"API_KEY"}, Nonce: "n",
		})
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.NotContains(t, string(fr.Ciphertext), "key-", "host must not see plaintext in the sealed release")
		var got map[string]string
		require.NoError(t, json.Unmarshal(openSealed(t, wl, fr.Enc, fr.Ciphertext), &got))
		return got
	}

	gotA := fetchAPIKey("orgA/workload")
	gotB := fetchAPIKey("orgB/workload")
	require.Equal(t, map[string]string{"API_KEY": "key-AAA"}, gotA)
	require.Equal(t, map[string]string{"API_KEY": "key-BBB"}, gotB)
	require.NotEqual(t, gotA["API_KEY"], gotB["API_KEY"], "same-named keys must not collide across tenants")

	// orgB asking for a name that only orgA has gets nothing — no cross-tenant read.
	wl := newID(t)
	_, fr := doFetch(t, ts.URL, fetchRequest{
		Repo: "orgB/workload", PKW: wl.MarshalPublicKeyHex(),
		SecretRefs: []string{"DB_URL"}, Nonce: "n",
	})
	var crossed map[string]string
	require.NoError(t, json.Unmarshal(openSealed(t, wl, fr.Enc, fr.Ciphertext), &crossed))
	require.Empty(t, crossed, "orgB must not reach orgA's DB_URL")
}
