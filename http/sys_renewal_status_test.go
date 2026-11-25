// Copyright IBM Corp. 2026
// SPDX-License-Identifier: BUSL-1.1

package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/vault"
	"github.com/stretchr/testify/require"
)

// waitForUnsealed polls the core until the expiration manager has finished
// restoring and the node reports unsealed.
func waitForUnsealed(t *testing.T, core *vault.Core) {
	t.Helper()
	require.Eventually(t, func() bool {
		if core.Sealed() || core.Expiration() == nil {
			return false
		}
		return !core.Expiration().InRestoreMode()
	}, 15*time.Second, 25*time.Millisecond)
}

// TestRenewToken_HTTPSealed verifies that renew-self returns 503 with the
// sealed error body while Vault is sealed, carries no auth payload, and then
// succeeds with 200 after unseal.
func TestRenewToken_HTTPSealed(t *testing.T) {
	core, keys, root := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	config := api.DefaultConfig()
	config.Address = addr
	client, err := api.NewClient(config)
	require.NoError(t, err)
	client.SetToken(root)

	// Create a renewable token that we will renew through the HTTP API.
	secret, err := client.Auth().Token().Create(&api.TokenCreateRequest{
		Lease: "1h",
	})
	require.NoError(t, err)
	renewableToken := secret.Auth.ClientToken

	// Seal the core directly.
	require.NoError(t, core.Seal(root))

	// A raw PUT to renew-self while sealed must be a 503 without an auth field.
	body, err := json.Marshal(map[string]interface{}{})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, addr+"/v1/auth/token/renew-self", bytes.NewReader(body))
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	var sealedBody map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&sealedBody))
	errs, ok := sealedBody["errors"].([]interface{})
	require.True(t, ok, "expected errors array, got %#v", sealedBody)
	require.NotEmpty(t, errs)
	require.Contains(t, errs[0], "Vault is sealed")
	_, hasAuth := sealedBody["auth"]
	require.False(t, hasAuth, "sealed response must not contain an auth field")

	// Re-unseal the same core.
	for _, key := range keys {
		unsealed, err := vault.TestCoreUnseal(core, key)
		require.NoError(t, err)
		if unsealed {
			break
		}
	}
	waitForUnsealed(t, core)

	// The same request now succeeds.
	renewClient, err := api.NewClient(config)
	require.NoError(t, err)
	renewClient.SetToken(renewableToken)
	out, err := renewClient.Auth().Token().RenewSelf(3600)
	require.NoError(t, err)
	require.NotNil(t, out.Auth)
}

// TestRenewToken_RenewalIdIdempotent verifies that two token renewals sharing
// an explicit renewal_id return identical auth data and that the optional field
// is accepted without breaking the legacy request shape.
func TestRenewToken_RenewalIdIdempotent(t *testing.T) {
	core, _, root := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	config := api.DefaultConfig()
	config.Address = addr
	client, err := api.NewClient(config)
	require.NoError(t, err)
	client.SetToken(root)

	secret, err := client.Auth().Token().Create(&api.TokenCreateRequest{Lease: "1h"})
	require.NoError(t, err)
	token := secret.Auth.ClientToken

	renewOnce := func() map[string]interface{} {
		req := client.NewRequest(http.MethodPut, "/v1/auth/token/renew")
		require.NoError(t, req.SetJSONBody(map[string]interface{}{
			"token":      token,
			"renewal_id": "shared-idempotency-key",
		}))
		resp, rerr := client.RawRequest(req)
		require.NoError(t, rerr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		return body
	}

	first := renewOnce()
	second := renewOnce()

	firstAuth, ok := first["auth"].(map[string]interface{})
	require.True(t, ok)
	secondAuth, ok := second["auth"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, firstAuth["client_token"], secondAuth["client_token"])
	require.Equal(t, firstAuth["lease_duration"], secondAuth["lease_duration"])

	// The idempotency cache must hold exactly one entry for the shared key.
	require.Len(t, core.RenewGateForTest().DedupForTest(), 1)
}

// TestRenewStatus_HTTP verifies the sudo/root protection and response shape of
// sys/leases/renewal-status: a default-policy token gets 403 without inflight
// data, while root gets 200 with the full field set and no identifiers.
func TestRenewStatus_HTTP(t *testing.T) {
	core, _, root := vault.TestCoreUnsealed(t)
	ln, addr := TestServer(t, core)
	defer ln.Close()

	config := api.DefaultConfig()
	config.Address = addr
	rootClient, err := api.NewClient(config)
	require.NoError(t, err)
	rootClient.SetToken(root)

	// Install a restrictive policy and mint a non-root token bound to it.
	policy := `
path "auth/token/lookup-self" { capabilities = ["read"] }
`
	require.NoError(t, rootClient.Sys().PutPolicy("renew-status-test", policy))

	limited, err := rootClient.Auth().Token().Create(&api.TokenCreateRequest{
		Policies: []string{"renew-status-test"},
	})
	require.NoError(t, err)
	limitedClient, err := api.NewClient(config)
	require.NoError(t, err)
	limitedClient.SetToken(limited.Auth.ClientToken)

	// The limited token must be forbidden from the sudo endpoint.
	req := limitedClient.NewRequest(http.MethodGet, "/v1/sys/leases/renewal-status")
	resp, err := limitedClient.RawRequest(req)
	require.Error(t, err)
	require.NotNil(t, resp)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	// The forbidden response must not carry any gate counters.
	var forbiddenBody map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&forbiddenBody))
	_, hasInflight := forbiddenBody["inflight"]
	require.False(t, hasInflight, "403 response must not include inflight")
	if nested, ok := forbiddenBody["data"].(map[string]interface{}); ok {
		_, nestedInflight := nested["inflight"]
		require.False(t, nestedInflight, "403 response data must not include inflight")
	}

	// Root reads the endpoint successfully with all expected fields.
	rootReq := rootClient.NewRequest(http.MethodGet, "/v1/sys/leases/renewal-status")
	rootResp, err := rootClient.RawRequest(rootReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rootResp.StatusCode)

	var result struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rootResp.Body).Decode(&result))
	expected := []string{"state", "epoch", "inflight", "sealed_rejections", "stale_commits", "restore_completed_at"}
	for _, key := range expected {
		_, ok := result.Data[key]
		require.True(t, ok, "missing field %s", key)
	}

	// No identifying lease/token/accessor strings may appear.
	raw, _ := json.Marshal(result.Data)
	blob := string(raw)
	require.NotContains(t, blob, "accessor")
	require.NotContains(t, blob, "lease_id")
	require.NotContains(t, blob, "client_token")
}
