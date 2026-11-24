// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/audit"
	"github.com/hashicorp/vault/helper/identity"
	"github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// controlGroupTestHarness is a single-node in-memory core with a controlled
// secret path, identity entities and tokens for a requester and two approvers.
type controlGroupTestHarness struct {
	t    *testing.T
	core *Core
	ctx  context.Context

	root string

	requesterToken  string
	requesterEntity string
	approverAToken  string
	approverAEntity string
	approverBToken  string
	approverBEntity string
	outsiderToken   string
	outsiderEntity  string

	noop *audit.NoopAudit
}

const controlGroupTestPolicy = `
path "secret/controlled" {
  capabilities = ["create", "read", "update", "delete", "list"]
  control_group = {
    max_ttl = "10m"
    factor "ops" {
      identity {
        group_names = ["ops-approvers"]
        approvals = %d
      }
    }
  }
}

path "secret/free" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/control-group/request" {
  capabilities = ["update"]
}

path "sys/control-group/cancel" {
  capabilities = ["update"]
}

path "sys/control-group/authorize" {
  capabilities = ["update"]
}
`

// controlGroupApproverPolicy grants an approver the capability on the
// controlled path plus the control-group endpoints, without the control_group
// block. This models a principal who could perform the operation but is still
// required to approve someone else's.
const controlGroupApproverPolicy = `
path "secret/controlled" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/control-group/authorize" {
  capabilities = ["update"]
}

path "sys/control-group/request" {
  capabilities = ["update"]
}

path "sys/control-group/cancel" {
  capabilities = ["update"]
}
`

// controlGroupOutsiderPolicy lets a principal call the control group endpoints
// but grants no capability on the controlled path, so their approvals must be
// rejected on policy grounds rather than by the endpoint's own ACL check.
const controlGroupOutsiderPolicy = `
path "sys/control-group/authorize" {
  capabilities = ["update"]
}

path "sys/control-group/request" {
  capabilities = ["update"]
}

path "sys/control-group/cancel" {
  capabilities = ["update"]
}
`

// newControlGroupTestHarness builds the fixture. approvals sets the number of
// distinct approvers required.
func newControlGroupTestHarness(t *testing.T, approvals int) *controlGroupTestHarness {
	t.Helper()

	core, _, root := TestCoreUnsealed(t)
	ctx := namespace.RootContext(context.Background())
	h := &controlGroupTestHarness{t: t, core: core, ctx: ctx, root: root}

	// Enable a noop audit device so we can assert lifecycle records.
	var noop *audit.NoopAudit
	core.auditBackends["noop"] = func(config *audit.BackendConfig, _ audit.HeaderFormatter) (audit.Backend, error) {
		var err error
		noop, err = audit.NewNoopAudit(config)
		return noop, err
	}
	enable := logical.TestRequest(t, logical.UpdateOperation, "sys/audit/noop")
	enable.ClientToken = root
	enable.Data["type"] = "noop"
	_, err := core.HandleRequest(ctx, enable)
	require.NoError(t, err)
	h.noop = noop

	require.NoError(t, core.policyStore.SetPolicy(ctx, mustParsePolicy(t, "controlled", fmt.Sprintf(controlGroupTestPolicy, approvals))))
	require.NoError(t, core.policyStore.SetPolicy(ctx, mustParsePolicy(t, "approver", controlGroupApproverPolicy)))
	require.NoError(t, core.policyStore.SetPolicy(ctx, mustParsePolicy(t, "outsider", controlGroupOutsiderPolicy)))

	// Create entities, a controlling group, and tokens bound to each entity.
	h.requesterEntity = h.createEntity("requester")
	h.approverAEntity = h.createEntity("approver-a")
	h.approverBEntity = h.createEntity("approver-b")
	h.outsiderEntity = h.createEntity("outsider")

	require.NoError(t, core.identityStore.sanitizeAndUpsertGroup(ctx, &identity.Group{
		Name:            "ops-approvers",
		Type:            groupTypeInternal,
		MemberEntityIDs: []string{h.approverAEntity, h.approverBEntity},
	}, nil, nil))

	h.requesterToken = h.createToken("controlled", h.requesterEntity)
	h.approverAToken = h.createToken("approver", h.approverAEntity)
	h.approverBToken = h.createToken("approver", h.approverBEntity)
	h.outsiderToken = h.createToken("outsider", h.outsiderEntity)

	return h
}

func mustParsePolicy(t *testing.T, name, raw string) *Policy {
	t.Helper()
	p, err := ParseACLPolicy(namespace.RootNamespace, fmt.Sprintf("name = %q\n%s", name, raw))
	require.NoError(t, err)
	return p
}

func (h *controlGroupTestHarness) createEntity(name string) string {
	h.t.Helper()
	e := &identity.Entity{Name: name, NamespaceID: namespace.RootNamespaceID}
	require.NoError(h.t, h.core.identityStore.sanitizeEntity(h.ctx, e))
	require.NoError(h.t, h.core.identityStore.upsertEntity(h.ctx, e, nil, true))
	return e.ID
}

func (h *controlGroupTestHarness) createToken(policy, entityID string) string {
	h.t.Helper()
	te := &logical.TokenEntry{
		Path:        "test",
		Policies:    []string{policy},
		EntityID:    entityID,
		NamespaceID: namespace.RootNamespaceID,
		TTL:         time.Hour,
	}
	testMakeTokenDirectly(h.t, h.core.tokenStore, te)
	return te.ID
}

// do performs a request as the given token.
func (h *controlGroupTestHarness) do(token string, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error) {
	h.t.Helper()
	req := logical.TestRequest(h.t, op, path)
	req.ClientToken = token
	for k, v := range data {
		req.Data[k] = v
	}
	return h.core.HandleRequest(h.ctx, req)
}

// controlledWrite issues a write to the controlled path and expects it to be
// held, returning the pending accessor and completion token. A held request is
// reported as a normal wrapped response: the pending token is in wrap_info.
func (h *controlGroupTestHarness) controlledWrite(data map[string]interface{}) (accessor, token string) {
	h.t.Helper()
	resp, err := h.do(h.requesterToken, logical.UpdateOperation, "secret/controlled", data)
	require.NoError(h.t, err)
	require.NotNil(h.t, resp)
	require.False(h.t, resp.IsError(), "held request errored: %v", resp.Error())
	require.NotNil(h.t, resp.WrapInfo, "held request has no wrap_info: %#v", resp.Data)
	require.NotEmpty(h.t, resp.WrapInfo.Token)
	require.NotEmpty(h.t, resp.WrapInfo.Accessor)
	return resp.WrapInfo.Accessor, resp.WrapInfo.Token
}

func (h *controlGroupTestHarness) authorize(token, accessor string, deny bool) (*logical.Response, error) {
	h.t.Helper()
	return h.do(token, logical.UpdateOperation, "sys/control-group/authorize", map[string]interface{}{
		"accessor": accessor,
		"deny":     deny,
	})
}

func (h *controlGroupTestHarness) approve(token, accessor string) *logical.Response {
	h.t.Helper()
	resp, err := h.authorize(token, accessor, false)
	require.NoError(h.t, err)
	if resp.IsError() {
		h.t.Fatalf("approve failed: %v", resp.Error())
	}
	return resp
}

func (h *controlGroupTestHarness) status(token, accessor string) *logical.Response {
	h.t.Helper()
	resp, err := h.do(token, logical.UpdateOperation, "sys/control-group/request", map[string]interface{}{
		"accessor": accessor,
	})
	require.NoError(h.t, err)
	require.False(h.t, resp.IsError(), "status errored: %v", resp.Error())
	return resp
}

// complete presents the pending token to sys/wrapping/unwrap.
func (h *controlGroupTestHarness) complete(token string) (*logical.Response, error) {
	h.t.Helper()
	req := logical.TestRequest(h.t, logical.UpdateOperation, "sys/wrapping/unwrap")
	req.ClientToken = token
	req.Data["token"] = token
	return h.core.HandleRequest(h.ctx, req)
}

// remainingInt pulls "remaining" from a response as an int.
func remainingInt(t *testing.T, resp *logical.Response) int {
	t.Helper()
	require.NotNil(t, resp)
	v, ok := resp.Data["remaining"]
	require.True(t, ok, "response has no remaining: %#v", resp.Data)
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		t.Fatalf("unexpected remaining type %T", v)
		return 0
	}
}

func approvedBool(t *testing.T, resp *logical.Response) bool {
	t.Helper()
	v, ok := resp.Data["approved"]
	require.True(t, ok)
	b, ok := v.(bool)
	require.True(t, ok)
	return b
}

func (h *controlGroupTestHarness) auditPaths() []string {
	h.t.Helper()
	var out []string
	for _, r := range h.noop.Req {
		if r != nil {
			out = append(out, r.Path)
		}
	}
	for _, r := range h.noop.RespReq {
		if r != nil {
			out = append(out, r.Path)
		}
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestControlGroup_ApprovalFlow exercises the primary path: hold, approve by a
// second principal, automatic threshold, then replay on unwrap.
func TestControlGroup_ApprovalFlow(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)

	accessor, token := h.controlledWrite(map[string]interface{}{"value": "topsecret"})

	// The write must not have executed. Read as root, which bypasses ACLs and so
	// is not itself held by the control group.
	require.Nil(t, h.readAsRoot("secret/controlled"))

	// Status reports one outstanding approval.
	require.Equal(t, 1, remainingInt(t, h.status(h.requesterToken, accessor)))

	// The approver approves.
	ar := h.approve(h.approverAToken, accessor)
	require.True(t, approvedBool(t, ar))
	require.Equal(t, 0, remainingInt(t, ar))

	// Completing with the pending token executes the frozen write.
	cr, err := h.complete(token)
	require.NoError(t, err)
	require.NotNil(t, cr)

	// The secret now exists, proving the original write ran.
	readResp := h.readAsRoot("secret/controlled")
	require.NotNil(t, readResp)
	require.Equal(t, "topsecret", readResp.Data["value"])

	// The persisted lifecycle trail contains the full chain, in order.
	trail := h.status(h.requesterToken, accessor).Data["audit_trail"].([]map[string]interface{})
	var actions []string
	for _, ev := range trail {
		actions = append(actions, ev["action"].(string))
	}
	for _, want := range []string{"requested", "approved", "threshold_reached", "completed"} {
		require.True(t, containsString(actions, want), "audit trail missing %q in %v", want, actions)
	}
	// And the audit device saw the requester's hold and the completion.
	paths := h.auditPaths()
	for _, want := range []string{"control-group/requested", "control-group/completed"} {
		require.True(t, containsString(paths, want), "audit device missing %q in %v", want, paths)
	}
}

// readAsRoot reads a path using the root token, bypassing ACLs.
func (h *controlGroupTestHarness) readAsRoot(path string) *logical.Response {
	h.t.Helper()
	resp, err := h.do(h.root, logical.ReadOperation, path, nil)
	require.NoError(h.t, err)
	if resp != nil {
		require.False(h.t, resp.IsError(), "root read errored: %v", resp.Error())
	}
	return resp
}

// TestControlGroup_UnknownApproverRejected ensures an approval from a principal
// outside the policy factors is invalid and does not count.
func TestControlGroup_UnknownApproverRejected(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)
	accessor, _ := h.controlledWrite(map[string]interface{}{"value": "x"})

	resp, err := h.authorize(h.outsiderToken, accessor, false)
	require.Error(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "not authorized")

	require.Equal(t, 1, remainingInt(t, h.status(h.requesterToken, accessor)))
}

// TestControlGroup_SelfApprovalRejected ensures the requester cannot approve
// their own request even when they belong to a controlling group.
func TestControlGroup_SelfApprovalRejected(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)
	// Put the requester into the controlling group as well.
	require.NoError(t, h.core.identityStore.sanitizeAndUpsertGroup(h.ctx, &identity.Group{
		Name:            "ops-approvers",
		Type:            groupTypeInternal,
		MemberEntityIDs: []string{h.approverAEntity, h.approverBEntity, h.requesterEntity},
	}, nil, nil))

	accessor, _ := h.controlledWrite(map[string]interface{}{"value": "x"})

	resp, err := h.authorize(h.requesterToken, accessor, false)
	require.Error(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "requester cannot approve")
	require.Equal(t, 1, remainingInt(t, h.status(h.requesterToken, accessor)))
}

// TestControlGroup_RepeatedApprovalRejected ensures the same approver cannot
// count twice toward the threshold.
func TestControlGroup_RepeatedApprovalRejected(t *testing.T) {
	h := newControlGroupTestHarness(t, 2)
	accessor, _ := h.controlledWrite(map[string]interface{}{"value": "x"})

	h.approve(h.approverAToken, accessor)
	resp, err := h.authorize(h.approverAToken, accessor, false)
	require.Error(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "already responded")
	require.Equal(t, 1, remainingInt(t, h.status(h.requesterToken, accessor)))
}

// TestControlGroup_DenialTerminates ensures a denial aborts the request and the
// original operation never executes.
func TestControlGroup_DenialTerminates(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)
	accessor, token := h.controlledWrite(map[string]interface{}{"value": "x"})

	resp, err := h.authorize(h.approverAToken, accessor, true)
	require.Error(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "denied")

	// Status reflects the denial.
	st := h.status(h.requesterToken, accessor)
	require.Equal(t, true, st.Data["denied"])

	// Completion is refused.
	_, err = h.complete(token)
	require.Error(t, err)

	// No write happened.
	require.Nil(t, h.readAsRoot("secret/controlled"))
}

// TestControlGroup_CancelByRequester ensures the requester can withdraw a
// pending request and the token stops working.
func TestControlGroup_CancelByRequester(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)
	accessor, token := h.controlledWrite(map[string]interface{}{"value": "x"})

	resp, err := h.do(h.requesterToken, logical.UpdateOperation, "sys/control-group/cancel", map[string]interface{}{
		"accessor": accessor,
		"reason":   "changed my mind",
	})
	require.NoError(t, err)
	require.False(t, resp.IsError())
	require.Equal(t, true, resp.Data["cancelled"])

	_, err = h.complete(token)
	require.Error(t, err)

	require.Nil(t, h.readAsRoot("secret/controlled"))
}

// TestControlGroup_Expiry ensures an expired request cannot be completed and is
// reported as expired.
func TestControlGroup_Expiry(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)
	accessor, token := h.controlledWrite(map[string]interface{}{"value": "x"})

	// Force expiry by rewriting the record's deadline into the past.
	state, err := h.core.loadControlGroupState(h.ctx, accessor)
	require.NoError(t, err)
	require.NotNil(t, state)
	state.ExpirationTime = time.Now().Add(-time.Second)
	require.NoError(t, h.core.persistControlGroupState(h.ctx, namespace.RootNamespace, state))

	// Approval after expiry is refused.
	resp, err := h.authorize(h.approverAToken, accessor, false)
	require.Error(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "expired")

	// Completion after expiry is refused.
	_, err = h.complete(token)
	require.Error(t, err)
}

// TestControlGroup_FrozenParameters ensures the completed operation uses the
// parameters captured at request time. Because the replay is driven only by the
// stored record, attempts to smuggle different data through the completion call
// have no effect.
func TestControlGroup_FrozenParameters(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)
	accessor, token := h.controlledWrite(map[string]interface{}{"value": "original"})
	h.approve(h.approverAToken, accessor)

	// Complete, but attach replacement data to the unwrap request.
	req := logical.TestRequest(t, logical.UpdateOperation, "sys/wrapping/unwrap")
	req.ClientToken = token
	req.Data["token"] = token
	req.Data["value"] = "tampered"
	resp, err := h.core.HandleRequest(h.ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The stored value is what was written, not the injected replacement.
	readResp := h.readAsRoot("secret/controlled")
	require.NotNil(t, readResp)
	require.Equal(t, "original", readResp.Data["value"])
	require.NotEqual(t, "tampered", readResp.Data["value"])
}

// TestControlGroup_ReplayIsSingleUse ensures the pending token cannot be used
// twice to run the operation twice.
func TestControlGroup_ReplayIsSingleUse(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)

	accessor, token := h.controlledWrite(map[string]interface{}{"value": "once"})
	h.approve(h.approverAToken, accessor)

	_, err := h.complete(token)
	require.NoError(t, err)

	// A second completion with the same token must fail.
	_, err = h.complete(token)
	require.Error(t, err)

	// The audit trail shows exactly one completion.
	var completions int
	for _, p := range h.auditPaths() {
		if p == "control-group/completed" {
			completions++
		}
	}
	require.Equal(t, 1, completions)
}

// TestControlGroup_NonControlledPathUnaffected ensures a path without a control
// group executes immediately and consults no control group state.
func TestControlGroup_NonControlledPathUnaffected(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)

	resp, err := h.do(h.requesterToken, logical.UpdateOperation, "secret/free", map[string]interface{}{"value": "ok"})
	require.NoError(t, err)
	require.False(t, resp.IsError())

	readResp, err := h.do(h.requesterToken, logical.ReadOperation, "secret/free", nil)
	require.NoError(t, err)
	require.NotNil(t, readResp)
	require.Equal(t, "ok", readResp.Data["value"])

	// No pending control group record should exist.
	keys, err := h.core.controlGroupView().List(h.ctx, controlGroupStoragePrefix)
	require.NoError(t, err)
	require.Empty(t, keys)
}

// TestControlGroup_RequiresEntityToken ensures a non-entity token cannot create
// a request it could then self-approve.
func TestControlGroup_RequiresEntityToken(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)

	te := &logical.TokenEntry{
		Path:        "test",
		Policies:    []string{"controlled"},
		NamespaceID: namespace.RootNamespaceID,
		TTL:         time.Hour,
	}
	testMakeTokenDirectly(t, h.core.tokenStore, te)

	resp, _ := h.do(te.ID, logical.UpdateOperation, "secret/controlled", map[string]interface{}{"value": "x"})
	require.NotNil(t, resp)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "entity-backed token")

	keys, lerr := h.core.controlGroupView().List(h.ctx, controlGroupStoragePrefix)
	require.NoError(t, lerr)
	require.Empty(t, keys)
}

// TestControlGroup_TwoApprovers ensures a threshold of two requires two
// distinct approvers and only completes after the second.
func TestControlGroup_TwoApprovers(t *testing.T) {
	h := newControlGroupTestHarness(t, 2)
	accessor, token := h.controlledWrite(map[string]interface{}{"value": "two"})

	first := h.approve(h.approverAToken, accessor)
	require.False(t, approvedBool(t, first))
	require.Equal(t, 1, remainingInt(t, first))

	// Completion before the threshold is refused.
	_, err := h.complete(token)
	require.Error(t, err)

	second := h.approve(h.approverBToken, accessor)
	require.True(t, approvedBool(t, second))
	require.Equal(t, 0, remainingInt(t, second))

	_, err = h.complete(token)
	require.NoError(t, err)

	readResp := h.readAsRoot("secret/controlled")
	require.NotNil(t, readResp)
	require.Equal(t, "two", readResp.Data["value"])
}

// TestControlGroup_ApproverWithoutCapabilityRejected ensures a member of the
// controlling group who lacks the path capability cannot approve.
func TestControlGroup_ApproverWithoutCapabilityRejected(t *testing.T) {
	h := newControlGroupTestHarness(t, 2)

	// Move approver B into the group but give them only the control-group
	// endpoints, no capability on secret/controlled.
	noCapEntity := h.createEntity("approver-no-cap")
	require.NoError(t, h.core.identityStore.sanitizeAndUpsertGroup(h.ctx, &identity.Group{
		Name:            "ops-approvers",
		Type:            groupTypeInternal,
		MemberEntityIDs: []string{h.approverAEntity, h.approverBEntity, noCapEntity},
	}, nil, nil))
	noCapToken := h.createToken("outsider", noCapEntity)

	accessor, _ := h.controlledWrite(map[string]interface{}{"value": "x"})

	resp, err := h.authorize(noCapToken, accessor, false)
	require.Error(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "does not hold the policy capability")
	require.Equal(t, 2, remainingInt(t, h.status(h.requesterToken, accessor)))
}

// TestControlGroup_ResultMatchesDirectExecution checks that completing a
// controlled request returns the same response a direct execution would have
// produced for the frozen request.
func TestControlGroup_ResultMatchesDirectExecution(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)

	accessor, token := h.controlledWrite(map[string]interface{}{"value": "parity"})
	h.approve(h.approverAToken, accessor)
	completeResp, err := h.complete(token)
	require.NoError(t, err)
	require.NotNil(t, completeResp)

	// The completion result is delivered as the raw HTTP body of the original
	// response, identical to the response-wrapping flow.
	rawBody, ok := completeResp.Data[logical.HTTPRawBody]
	require.True(t, ok, "completion did not return a raw body: %#v", completeResp.Data)
	var httpResp logical.HTTPResponse
	switch b := rawBody.(type) {
	case []byte:
		require.NoError(t, jsonutil.DecodeJSON(b, &httpResp))
	case string:
		require.NoError(t, jsonutil.DecodeJSON([]byte(b), &httpResp))
	default:
		t.Fatalf("unexpected raw body type %T", rawBody)
	}

	// A direct execution of the same operation produces equivalent data. The
	// controlled operation is a write, whose empty response is what the freeze
	// captured too.
	require.Empty(t, httpResp.Data)

	// Both leave the same stored value, and a direct read of the controlled
	// path (once approved) matches a direct read of an identical uncontrolled
	// write done the same way.
	directResp, err := h.do(h.requesterToken, logical.UpdateOperation, "secret/free", map[string]interface{}{"value": "parity"})
	require.NoError(t, err)
	if directResp != nil {
		require.False(t, directResp.IsError())
	}

	directRead := h.readAsRoot("secret/free")
	replayRead := h.readAsRoot("secret/controlled")
	require.Equal(t, directRead.Data["value"], replayRead.Data["value"])
}

// TestControlGroup_CancelWhenUnreachable models a threshold that can no longer
// be reached (an approver's access was removed). An authorized approver may
// cancel with a reason, terminating the request.
func TestControlGroup_CancelWhenUnreachable(t *testing.T) {
	h := newControlGroupTestHarness(t, 2)
	accessor, token := h.controlledWrite(map[string]interface{}{"value": "x"})

	h.approve(h.approverAToken, accessor)

	// Approver A (authorized) cancels because B can no longer approve.
	cancelResp, err := h.do(h.approverAToken, logical.UpdateOperation, "sys/control-group/cancel", map[string]interface{}{
		"accessor": accessor,
		"reason":   "second approver no longer authorized",
	})
	require.NoError(t, err)
	require.False(t, cancelResp.IsError())
	require.Equal(t, true, cancelResp.Data["cancelled"])

	_, err = h.complete(token)
	require.Error(t, err)
	require.Nil(t, h.readAsRoot("secret/controlled"))

	// The trail records the cancellation with its reason.
	trail := h.status(h.requesterToken, accessor).Data["audit_trail"].([]map[string]interface{})
	var found bool
	for _, ev := range trail {
		if ev["action"].(string) == "cancelled" && ev["detail"].(string) == "second approver no longer authorized" {
			found = true
		}
	}
	require.True(t, found, "cancellation trail missing reason: %v", trail)
}

// TestControlGroup_UnauthorizedCancelRejected ensures an unrelated principal
// cannot cancel someone else's request.
func TestControlGroup_UnauthorizedCancelRejected(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)
	accessor, _ := h.controlledWrite(map[string]interface{}{"value": "x"})

	resp, err := h.do(h.outsiderToken, logical.UpdateOperation, "sys/control-group/cancel", map[string]interface{}{
		"accessor": accessor,
	})
	require.Error(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "only the requester or an authorized approver")
}

// failingPutStorage fails Put for keys under a given prefix while delegating
// everything else. It lets a test force the persistence step of an approval to
// fail without disturbing the rest of the core.
type failingPutStorage struct {
	logical.Storage
	failPrefix string
}

func (s *failingPutStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if strings.HasPrefix(entry.Key, s.failPrefix) {
		return errors.New("injected storage failure")
	}
	return s.Storage.Put(ctx, entry)
}

// TestControlGroup_PersistenceFailureAbortsApproval ensures that if the
// approval cannot be persisted, the approval is not recorded and the request
// cannot be marked approved — so a write is never "approved but not executed"
// or "executed but not recorded".
func TestControlGroup_PersistenceFailureAbortsApproval(t *testing.T) {
	h := newControlGroupTestHarness(t, 1)
	accessor, token := h.controlledWrite(map[string]interface{}{"value": "x"})

	// Swap the system barrier view for one whose Puts on control group keys
	// fail. Reads still succeed.
	origView := h.core.systemBarrierView
	defer func() { h.core.systemBarrierView = origView }()
	inmem := &logical.InmemStorage{}
	copyEntries(t, origView, inmem)
	h.core.systemBarrierView = NewBarrierView(&failingPutStorage{Storage: inmem, failPrefix: controlGroupStoragePrefix}, "")

	// Approval must fail.
	_, err := h.authorize(h.approverAToken, accessor, false)
	require.Error(t, err)

	// The approval must not have been recorded: the request is still pending.
	h.core.systemBarrierView = origView
	require.Equal(t, 1, remainingInt(t, h.status(h.requesterToken, accessor)))
	require.False(t, approvedBool(t, h.status(h.requesterToken, accessor)))

	// And completion cannot run.
	_, err = h.complete(token)
	require.Error(t, err)
	require.Nil(t, h.readAsRoot("secret/controlled"))
}

// copyEntries copies every control-group key from src into dst so the swapped
// view still sees the pending record.
func copyEntries(t *testing.T, src *BarrierView, dst logical.Storage) {
	t.Helper()
	ctx := namespace.RootContext(context.Background())
	keys, err := src.List(ctx, controlGroupStoragePrefix)
	require.NoError(t, err)
	for _, k := range keys {
		entry, err := src.Get(ctx, controlGroupStoragePrefix+k)
		require.NoError(t, err)
		require.NoError(t, dst.Put(ctx, entry))
	}
}

// TestControlGroup_LegacyPolicyStillLoads ensures a policy written with the
// legacy "ttl" key (or no TTL at all) still parses, so existing policy files
// need no edits.
func TestControlGroup_LegacyPolicyStillLoads(t *testing.T) {
	cases := map[string]string{
		"legacy ttl": `
name = "legacy"
path "secret/controlled" {
  capabilities = ["update"]
  control_group = {
    ttl = "1h"
    factor "ops" {
      identity {
        group_names = ["ops-approvers"]
        approvals = 1
      }
    }
  }
}`,
		"no ttl": `
name = "legacy"
path "secret/controlled" {
  capabilities = ["update"]
  control_group = {
    factor "ops" {
      identity {
        group_names = ["ops-approvers"]
        approvals = 1
      }
    }
  }
}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			pol, err := ParseACLPolicy(namespace.RootNamespace, raw)
			require.NoError(t, err)
			require.NotNil(t, pol.Paths[0].Permissions.ControlGroup)
			require.Len(t, pol.Paths[0].Permissions.ControlGroup.Factors, 1)
		})
	}
}
