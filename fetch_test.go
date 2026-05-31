package main

import (
	"bytes"
	"crypto/hpke"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

func newID(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	return id
}

func doFetch(t *testing.T, base string, req fetchRequest) (*http.Response, fetchResponse) {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	resp, err := http.Post(base+"/fetch", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	var fr fetchResponse
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&fr))
	}
	resp.Body.Close()
	return resp, fr
}

// openSealed is the workload side: open the release with sk_W.
func openSealed(t *testing.T, wl *identity.Identity, enc, ct []byte) []byte {
	t.Helper()
	r, err := hpke.NewRecipient(enc, wl.PrivateKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(fetchInfo))
	require.NoError(t, err)
	pt, err := r.Open(nil, ct)
	require.NoError(t, err)
	return pt
}

func TestFetchReleasesSealedSecrets(t *testing.T) {
	st := newStore()
	st.put("me/wl", "DB_PASSWORD", "s3cret")
	st.put("me/wl", "API_KEY", "ak-1")
	st.put("other/wl", "SECRET", "nope")
	ts := httptest.NewServer(newMux(newID(t), st, devVerifier{}, false))
	defer ts.Close()

	wl := newID(t) // workload per-boot keypair
	resp, fr := doFetch(t, ts.URL, fetchRequest{
		Repo: "me/wl", PKW: wl.MarshalPublicKeyHex(),
		SecretRefs: []string{"DB_PASSWORD", "API_KEY"}, Nonce: "n1",
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "n1", fr.Nonce)
	require.NotContains(t, string(fr.Ciphertext), "s3cret", "host must not see plaintext in the sealed release")

	var got map[string]string
	require.NoError(t, json.Unmarshal(openSealed(t, wl, fr.Enc, fr.Ciphertext), &got))
	require.Equal(t, map[string]string{"DB_PASSWORD": "s3cret", "API_KEY": "ak-1"}, got)
}

func TestFetchOnlyOwnerKeyCanOpen(t *testing.T) {
	st := newStore()
	st.put("me/wl", "A", "v")
	ts := httptest.NewServer(newMux(newID(t), st, devVerifier{}, false))
	defer ts.Close()

	wl := newID(t)
	_, fr := doFetch(t, ts.URL, fetchRequest{Repo: "me/wl", PKW: wl.MarshalPublicKeyHex(), SecretRefs: []string{"A"}, Nonce: "n"})

	// A different per-boot key must not open the release sealed to wl.
	other := newID(t)
	r, err := hpke.NewRecipient(fr.Enc, other.PrivateKey(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(fetchInfo))
	require.NoError(t, err)
	_, err = r.Open(nil, fr.Ciphertext)
	require.Error(t, err)
}

func TestFetchUnknownRepoReturnsEmpty(t *testing.T) {
	st := newStore()
	st.put("me/wl", "A", "v")
	ts := httptest.NewServer(newMux(newID(t), st, devVerifier{}, false))
	defer ts.Close()

	wl := newID(t)
	resp, fr := doFetch(t, ts.URL, fetchRequest{Repo: "unknown/repo", PKW: wl.MarshalPublicKeyHex(), SecretRefs: []string{"A"}, Nonce: "n"})
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got map[string]string
	require.NoError(t, json.Unmarshal(openSealed(t, wl, fr.Enc, fr.Ciphertext), &got))
	require.Empty(t, got)
}

func TestFetchSNPVerifierRejectsWithoutBundle(t *testing.T) {
	st := newStore()
	// &snpVerifier{} with a nil sigstore client is fine here: a request with no
	// attestation bundle is rejected before the client is ever touched.
	ts := httptest.NewServer(newMux(newID(t), st, &snpVerifier{}, false))
	defer ts.Close()

	resp, _ := doFetch(t, ts.URL, fetchRequest{Repo: "me/wl", PKW: newID(t).MarshalPublicKeyHex(), SecretRefs: []string{"A"}, Nonce: "n"})
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}
