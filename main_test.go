package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	ehbp "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

// TestWritePathRoundTrip drives the vault the way the CLI does: store a secret
// over the EHBP-sealed channel, then list and delete it over plain HTTP.
func TestWritePathRoundTrip(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	st := newStore()
	ts := httptest.NewServer(newMux(id, st, devVerifier{}, false))
	defer ts.Close()

	tr, err := ehbp.NewTransport(ts.URL)
	require.NoError(t, err)
	sealed := &http.Client{Transport: tr}

	body, err := json.Marshal(storeRequest{Repo: "me/wl", Name: "DB_PASSWORD", Value: "s3cret"})
	require.NoError(t, err)
	resp, err := sealed.Post(ts.URL+"/store", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	require.Equal(t, "s3cret", st.get("me/wl", []string{"DB_PASSWORD"})["DB_PASSWORD"])

	// list (plain GET)
	lr, err := http.Get(ts.URL + "/secrets?repo=me/wl")
	require.NoError(t, err)
	var out struct {
		Secrets []string `json:"secrets"`
	}
	require.NoError(t, json.NewDecoder(lr.Body).Decode(&out))
	lr.Body.Close()
	require.Equal(t, []string{"DB_PASSWORD"}, out.Secrets)

	// delete (plain DELETE)
	dreq, err := http.NewRequest(http.MethodDelete, ts.URL+"/secrets?repo=me/wl&name=DB_PASSWORD", nil)
	require.NoError(t, err)
	dr, err := http.DefaultClient.Do(dreq)
	require.NoError(t, err)
	dr.Body.Close()
	require.Equal(t, http.StatusNoContent, dr.StatusCode)
	require.Empty(t, st.names("me/wl"))
}

// TestStoreRejectsPlaintextPost confirms /store is actually behind the EHBP
// middleware: an un-encrypted POST must not be accepted as a stored secret.
func TestStoreRejectsPlaintextPost(t *testing.T) {
	id, err := identity.NewIdentity()
	require.NoError(t, err)
	st := newStore()
	ts := httptest.NewServer(newMux(id, st, devVerifier{}, false))
	defer ts.Close()

	body, _ := json.Marshal(storeRequest{Repo: "me/wl", Name: "A", Value: "v"})
	resp, err := http.Post(ts.URL+"/store", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	require.NotEqual(t, http.StatusOK, resp.StatusCode)
	require.Empty(t, st.names("me/wl"))
}

// TestBehindShimAcceptsPlaintextStore: deployed behind the shim, the shim has
// already EHBP-decrypted, so a plaintext /store is the expected (and accepted)
// case. No HPKE identity is needed in this mode.
func TestBehindShimAcceptsPlaintextStore(t *testing.T) {
	st := newStore()
	ts := httptest.NewServer(newMux(nil, st, devVerifier{}, true))
	defer ts.Close()

	body, _ := json.Marshal(storeRequest{Repo: "me/wl", Name: "A", Value: "v"})
	resp, err := http.Post(ts.URL+"/store", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "v", st.get("me/wl", []string{"A"})["A"])
}
