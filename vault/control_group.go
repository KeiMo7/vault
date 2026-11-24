// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/vault/helper/identity"
	"github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/wrapping"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/copystructure"
)

// Control groups implement "two person rule" enforcement for paths whose
// policy declares a control_group block.
//
// Lifetime of a controlled request:
//
//  1. Authorization succeeds against the caller's ACL, but the matched
//     permission requires approvals. checkNeedsCG freezes the request, persists
//     a pending record and mints a one-time control-group token. The caller gets
//     back ErrControlGroupPending plus the token in a wrap_info block, exactly
//     as if response wrapping had been requested.
//
//  2. Other principals call sys/control-group/authorize with the accessor. Each
//     approval is checked against the identities named by the policy factors and
//     is recorded against the pending request. The requester can never approve
//     their own request, and an entity can only approve once.
//
//  3. When every factor reaches its threshold the record is marked approved.
//     Approval is recorded in a single durable write; if that write fails the
//     approval is not counted and the request cannot run.
//
//  4. The requester completes the request by presenting the control-group token
//     to sys/wrapping/unwrap. That path replays the frozen operation, path and
//     data. The completion call cannot supply or alter any of them.
//
//  5. The requester can withdraw a pending request, and an authorized approver
//     can cancel one (for example when a threshold has become unreachable).
//     A request past its deadline is expired on access and, later, swept from
//     storage.
//
// Cost on uncontrolled requests: checkNeedsCG inspects the ACL results that
// CheckToken already computed and returns immediately when no control group is
// attached. No storage is read.
//
// Scope: control groups are an ACL construct, so they apply to requests
// authorized by ACL permissions. The root token carries the "root" policy and
// bypasses ACL evaluation entirely, so root is not subject to control groups;
// neither are requests that skip ACL checks. This matches the rule that root is
// the operator break-glass identity.

const (
	// controlGroupStoragePrefix is where pending request records live, under
	// the system barrier view.
	controlGroupStoragePrefix = "control-group/request/"

	// controlGroupConfigStoragePath holds the cluster-wide configuration.
	controlGroupConfigStoragePath = "config/control-group"

	// defaultControlGroupTTL is used when a policy omits a max_ttl. The parser
	// permits omitting it for backwards compatibility, so a runtime default is
	// required.
	defaultControlGroupTTL = 24 * time.Hour

	// controlGroupSweepInterval is how often expired records are reclaimed.
	controlGroupSweepInterval = time.Minute

	// controlGroupGracePeriod keeps an expired record visible briefly after its
	// deadline so a late status read can still see the trail.
	controlGroupGracePeriod = 5 * time.Minute
)

var (
	// ErrControlGroupPending signals that a request is held awaiting approvals.
	// It is logical.ErrMultiAuthzPending so existing clients recognize it.
	ErrControlGroupPending = logical.ErrMultiAuthzPending

	// ErrControlGroupExpired is returned once a pending request passes its
	// deadline.
	ErrControlGroupExpired = errors.New("control group request has expired")

	// ErrControlGroupCancelled is returned after a request is withdrawn.
	ErrControlGroupCancelled = errors.New("control group request was cancelled")

	// ErrControlGroupDenied is returned after an approver rejects a request.
	ErrControlGroupDenied = errors.New("control group request was denied")
)

// controlGroupState is the persisted representation of a pending request.
type controlGroupState struct {
	// Accessor is the stable, non-secret handle for the request.
	Accessor string `json:"accessor"`

	// TokenID is the internal token ID used to authenticate the completion
	// call. It is never returned to clients.
	TokenID string `json:"token_id"`

	// TokenAccessor is the accessor of the pending token, returned in the
	// initial response's wrap_info.
	TokenAccessor string `json:"token_accessor"`

	RequesterEntityID    string `json:"requester_entity_id"`
	RequesterEntityName  string `json:"requester_entity_name"`
	RequesterNamespaceID string `json:"requester_namespace_id"`

	// Operation, Path and Data are the frozen original request. They are never
	// updated after creation.
	Operation logical.Operation      `json:"operation"`
	Path      string                 `json:"path"`
	Data      map[string]interface{} `json:"data"`
	Headers   map[string][]string    `json:"headers,omitempty"`

	PolicyName string `json:"policy_name,omitempty"`

	// Factors is an immutable snapshot of the approval requirement, so a later
	// policy edit cannot loosen an in-flight request.
	Factors []controlGroupFactorState `json:"factors"`

	Approvals []controlGroupApproval `json:"approvals"`

	// Denial terminates the request.
	Denial *controlGroupApproval `json:"denial,omitempty"`

	Approved   bool      `json:"approved"`
	ApprovedAt time.Time `json:"approved_at"`

	Cancelled    bool      `json:"cancelled"`
	CancelledAt  time.Time `json:"cancelled_at"`
	CancelReason string    `json:"cancel_reason,omitempty"`

	Completed   bool      `json:"completed"`
	CompletedAt time.Time `json:"completed_at"`

	ExpiredAt time.Time `json:"expired_at,omitempty"`

	// CreationTime and ExpirationTime bound the request. ExpirationTime is
	// fixed at creation and is never extended.
	CreationTime   time.Time `json:"creation_time"`
	ExpirationTime time.Time `json:"expiration_time"`

	AuditTrail []controlGroupAuditEvent `json:"audit_trail,omitempty"`
}

// controlGroupFactorState is the persisted form of one policy factor.
type controlGroupFactorState struct {
	Name                   string   `json:"name"`
	GroupIDs               []string `json:"group_ids,omitempty"`
	GroupNames             []string `json:"group_names,omitempty"`
	ApprovalsRequired      int      `json:"approvals_required"`
	ControlledCapabilities []string `json:"controlled_capabilities,omitempty"`
}

// controlGroupApproval records one actor's decision.
type controlGroupApproval struct {
	EntityID   string `json:"entity_id"`
	EntityName string `json:"entity_name"`
	// TokenAccessor identifies the token used; the token itself is not stored.
	TokenAccessor string `json:"token_accessor,omitempty"`
	// Factors lists the factor names this approval counted toward.
	Factors []string  `json:"factors,omitempty"`
	Time    time.Time `json:"time"`
}

// controlGroupAuditEvent is one entry in a request's lifecycle trail.
type controlGroupAuditEvent struct {
	Time      time.Time `json:"time"`
	ActorID   string    `json:"actor_id,omitempty"`
	ActorName string    `json:"actor_name,omitempty"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail,omitempty"`
}

// controlGroupManager holds in-process synchronization and the config cache.
// It is embedded in Core.
type controlGroupManager struct {
	lock   sync.RWMutex
	config *controlGroupConfig

	// requestLocks serialize mutations of individual pending requests.
	requestLocks []*locksutil.LockEntry

	// sweepCancel stops the background sweeper.
	sweepCancel context.CancelFunc
}

// controlGroupConfig is the persisted cluster-wide configuration.
type controlGroupConfig struct {
	// MaxTTL caps the lifetime of any pending request. Zero means no cap.
	MaxTTL time.Duration `json:"max_ttl"`
}

func newControlGroupManager() *controlGroupManager {
	return &controlGroupManager{requestLocks: locksutil.CreateLocks()}
}

func (m *controlGroupManager) setConfig(cfg *controlGroupConfig) {
	if m == nil {
		return
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.config = cfg
}

func (m *controlGroupManager) maxTTL() time.Duration {
	if m == nil {
		return 0
	}
	m.lock.RLock()
	defer m.lock.RUnlock()
	if m.config == nil {
		return 0
	}
	return m.config.MaxTTL
}

func (m *controlGroupManager) requestLock(accessor string) *locksutil.LockEntry {
	return locksutil.LockForKey(m.requestLocks, accessor)
}

// controlGroupCheckNeeded reports whether the request must be held for
// approvals. It runs inside CheckToken, immediately after policy evaluation, so
// it reuses the ACL results that were just computed; no storage is read.
//
// Requests that are already completing a control group, or that are running
// under one, are never held again.
func controlGroupCheckNeeded(authResults *AuthResults, req *logical.Request) bool {
	if authResults == nil || authResults.ACLResults == nil {
		return false
	}
	results := authResults.ACLResults
	if results.ControlGroup == nil || len(results.ControlGroup.Factors) == 0 {
		return false
	}
	if isControlGroupRun(req) || hasControlGroupToken(req) {
		return false
	}
	return controlGroupAppliesToOperation(results.ControlGroup, req.Operation, results.CapabilitiesBitmap)
}

// checkNeedsCG runs from handleRequest when CheckToken reported that the
// request requires approvals. It creates the durable pending record and the
// one-time token, and returns the response carrying that token.
//
// It recomputes the ACL permission solely to obtain the factors and TTL; the
// token has already been validated by CheckToken at this point.
func checkNeedsCG(ctx context.Context, c *Core, req *logical.Request, auth *logical.Auth, ctErr error, nonHMACReqDataKeys []string) (error, *logical.Response, *logical.Auth, error) {
	if ctErr != nil {
		return ctErr, nil, nil, nil
	}
	if isControlGroupRun(req) || hasControlGroupToken(req) {
		return nil, nil, nil, nil
	}

	acl, te, entity, _, err := c.fetchACLTokenEntryAndEntity(ctx, req)
	if err != nil || acl == nil {
		// Authorization already succeeded; do not mask it with a lookup error.
		return nil, nil, nil, nil
	}
	results := acl.AllowOperation(ctx, req, false)
	if results == nil || results.ControlGroup == nil || len(results.ControlGroup.Factors) == 0 {
		return nil, nil, nil, nil
	}
	if !controlGroupAppliesToOperation(results.ControlGroup, req.Operation, results.CapabilitiesBitmap) {
		return nil, nil, nil, nil
	}
	// Self-approval must be prevented structurally; a request without an
	// entity-backed caller has no requester to exclude.
	if entity == nil || entity.ID == "" {
		return logical.ErrPermissionDenied, logical.ErrorResponse("control group requires an entity-backed token"), nil, nil
	}

	return c.createControlGroupRequest(ctx, req, auth, entity, te, results)
}

// checkErrControlGroupTokenNeedsCreated reports whether err means a pending
// control-group token has to be created (and, on a perf standby, forwarded).
func checkErrControlGroupTokenNeedsCreated(err error) bool {
	return errors.Is(err, ErrControlGroupPending)
}

// hasControlGroupToken reports whether the request presents a pending token.
func hasControlGroupToken(req *logical.Request) bool {
	te := req.TokenEntry()
	return te != nil && len(te.Policies) == 1 && te.Policies[0] == controlGroupPolicyName
}

// controlGroupAppliesToOperation reports whether op is controlled. A factor
// that names no controlled_capabilities controls every granted capability.
func controlGroupAppliesToOperation(cg *ControlGroup, op logical.Operation, capabilities uint32) bool {
	capName, bit, ok := capabilityForOperation(op)
	if !ok || capabilities&bit == 0 {
		return false
	}

	explicit := false
	for _, f := range cg.Factors {
		if f == nil || len(f.ControlledCapabilities) == 0 {
			continue
		}
		explicit = true
		for _, cc := range f.ControlledCapabilities {
			if cc == capName {
				return true
			}
		}
	}
	return !explicit
}

// capabilityForOperation maps an operation to the capability name that grants
// it and the corresponding capability bit.
func capabilityForOperation(op logical.Operation) (string, uint32, bool) {
	switch op {
	case logical.CreateOperation:
		return CreateCapability, CreateCapabilityInt, true
	case logical.ReadOperation, logical.HeaderOperation:
		return ReadCapability, ReadCapabilityInt, true
	case logical.UpdateOperation:
		return UpdateCapability, UpdateCapabilityInt, true
	case logical.DeleteOperation:
		return DeleteCapability, DeleteCapabilityInt, true
	case logical.ListOperation:
		return ListCapability, ListCapabilityInt, true
	case logical.PatchOperation:
		return PatchCapability, PatchCapabilityInt, true
	case logical.RecoverOperation:
		return RecoverCapability, RecoverCapabilityInt, true
	default:
		return "", 0, false
	}
}

// createControlGroupRequest freezes the request, writes the pending record and
// mints the one-time token.
func (c *Core) createControlGroupRequest(ctx context.Context, req *logical.Request, auth *logical.Auth, entity *identity.Entity, requesterTE *logical.TokenEntry, results *ACLResults) (error, *logical.Response, *logical.Auth, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err, nil, nil, nil
	}

	ttl := results.ControlGroup.TTL
	if ttl <= 0 {
		ttl = defaultControlGroupTTL
	}
	if capTTL := c.controlGroup.maxTTL(); capTTL > 0 && ttl > capTTL {
		ttl = capTTL
	}

	// The pending token carries only the control-group policy, a single use
	// and the same TTL as the request, so a leak cannot outlive the request and
	// cannot be used for anything but completion. Its accessor is the stable,
	// non-secret handle for the pending request.
	cgToken := &logical.TokenEntry{
		Path:           req.Path,
		Policies:       []string{controlGroupPolicyName},
		EntityID:       entity.ID,
		TTL:            ttl,
		ExplicitMaxTTL: ttl,
		NumUses:        1,
		NamespaceID:    ns.ID,
		DisplayName:    "control-group",
	}
	if err := c.CreateToken(ctx, cgToken); err != nil {
		c.logger.Error("failed to create control group token", "error", err)
		return ErrInternalError, nil, nil, nil
	}

	now := time.Now().UTC()
	state := &controlGroupState{
		Accessor:             cgToken.Accessor,
		TokenID:              cgToken.ID,
		TokenAccessor:        cgToken.Accessor,
		RequesterEntityID:    entity.ID,
		RequesterEntityName:  entity.Name,
		RequesterNamespaceID: ns.ID,
		Operation:            req.Operation,
		Path:                 req.Path,
		Data:                 deepCopyData(req.Data),
		Headers:              cloneHeaders(req.Headers),
		PolicyName:           firstGrantingPolicy(results),
		Factors:              controlGroupFactorsFromPolicy(results.ControlGroup),
		CreationTime:         now,
		ExpirationTime:       now.Add(ttl),
	}
	state.AuditTrail = append(state.AuditTrail, controlGroupAuditEvent{
		Time:      now,
		ActorID:   entity.ID,
		ActorName: entity.Name,
		Action:    "requested",
		Detail:    fmt.Sprintf("%s %s", req.Operation, req.Path),
	})

	// Track the token with the expiration manager so it is revoked at TTL even
	// if nobody touches the pending record again.
	leaseAuth := &logical.Auth{
		ClientToken: cgToken.ID,
		Policies:    []string{controlGroupPolicyName},
		LeaseOptions: logical.LeaseOptions{
			TTL:       ttl,
			Renewable: false,
		},
	}
	if err := c.expiration.RegisterAuth(ctx, cgToken, leaseAuth, ""); err != nil {
		c.tokenStore.revokeOrphan(ctx, cgToken.ID)
		c.logger.Error("failed to register control group token lease", "error", err)
		return ErrInternalError, nil, nil, nil
	}

	// Persist before returning the token: a caller must never hold a token for
	// a request that is not durably recorded.
	if err := c.persistControlGroupState(ctx, ns, state); err != nil {
		c.tokenStore.revokeOrphan(ctx, cgToken.ID)
		c.logger.Error("failed to persist control group request", "error", err)
		return ErrInternalError, nil, nil, nil
	}

	remaining := controlGroupRemainingApprovals(state)
	c.auditControlGroupEvent(ctx, req, auth, "control-group/requested", map[string]interface{}{
		"accessor":            state.Accessor,
		"request_path":        state.Path,
		"operation":           string(state.Operation),
		"requester_entity_id": state.RequesterEntityID,
		"policy":              state.PolicyName,
		"remaining":           remaining,
		"expiration_time":     state.ExpirationTime.Format(time.RFC3339Nano),
	})

	resp := &logical.Response{
		Data: map[string]interface{}{
			"accessor":        state.Accessor,
			"request_path":    state.Path,
			"operation":       string(state.Operation),
			"remaining":       remaining,
			"approved":        false,
			"request_time":    state.CreationTime.Format(time.RFC3339Nano),
			"expiration_time": state.ExpirationTime.Format(time.RFC3339Nano),
			"factors":         controlGroupFactorStatus(state),
		},
		WrapInfo: &wrapping.ResponseWrapInfo{
			TTL:          ttl,
			Token:        cgToken.ExternalID,
			Accessor:     cgToken.Accessor,
			CreationTime: state.CreationTime,
			CreationPath: state.Path,
			Format:       "uuid",
		},
	}
	return ErrControlGroupPending, resp, nil, nil
}

// persistControlGroupState durably writes a pending record.
func (c *Core) persistControlGroupState(ctx context.Context, ns *namespace.Namespace, state *controlGroupState) error {
	view := c.controlGroupView()
	if view == nil {
		return errors.New("control group storage is unavailable")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal control group request: %w", err)
	}
	ctx = namespace.ContextWithNamespace(ctx, ns)
	return view.Put(ctx, &logical.StorageEntry{
		Key:   controlGroupStoragePrefix + state.Accessor,
		Value: raw,
	})
}

// loadControlGroupState reads a pending record by accessor.
func (c *Core) loadControlGroupState(ctx context.Context, accessor string) (*controlGroupState, error) {
	accessor = strings.TrimSpace(accessor)
	if accessor == "" {
		return nil, errors.New("missing control group accessor")
	}
	view := c.controlGroupView()
	if view == nil {
		return nil, errors.New("control group storage is unavailable")
	}
	entry, err := view.Get(ctx, controlGroupStoragePrefix+accessor)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	state := new(controlGroupState)
	if err := jsonutil.DecodeJSON(entry.Value, state); err != nil {
		return nil, fmt.Errorf("failed to decode control group request: %w", err)
	}
	return state, nil
}

// authorizeControlGroup records an approval or denial for a pending request.
func (c *Core) authorizeControlGroup(ctx context.Context, req *logical.Request, actor *identity.Entity, actorTE *logical.TokenEntry, accessor string, deny bool) (*logical.Response, error) {
	if actor == nil || actor.ID == "" {
		return logical.ErrorResponse("control group approval requires an entity-backed token"), logical.ErrPermissionDenied
	}

	lock := c.controlGroup.requestLock(accessor)
	lock.Lock()
	defer lock.Unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	state, err := c.loadControlGroupState(ctx, accessor)
	if err != nil {
		return nil, ErrInternalError
	}
	if state == nil {
		return logical.ErrorResponse("control group request not found"), logical.ErrNotFound
	}

	if expired := controlGroupIsExpired(state); expired {
		if err := c.expireControlGroup(ctx, ns, state, "expired"); err != nil {
			return nil, ErrInternalError
		}
		return logical.ErrorResponse(ErrControlGroupExpired.Error()), logical.ErrInvalidRequest
	}
	switch {
	case state.Cancelled:
		return logical.ErrorResponse(ErrControlGroupCancelled.Error()), logical.ErrInvalidRequest
	case state.Denial != nil:
		return logical.ErrorResponse(ErrControlGroupDenied.Error()), logical.ErrInvalidRequest
	case state.Completed:
		return logical.ErrorResponse("control group request has already been completed"), logical.ErrInvalidRequest
	}

	// The requester may never approve or deny their own request.
	if actor.ID == state.RequesterEntityID {
		return logical.ErrorResponse("the requester cannot approve their own control group request"), logical.ErrPermissionDenied
	}

	// One response per entity.
	for _, ap := range state.Approvals {
		if ap.EntityID == actor.ID {
			return logical.ErrorResponse("entity has already responded to this control group request"), logical.ErrInvalidRequest
		}
	}
	if state.Denial != nil && state.Denial.EntityID == actor.ID {
		return logical.ErrorResponse("entity has already responded to this control group request"), logical.ErrInvalidRequest
	}

	// An approver's response only counts if the approver is themselves
	// authorized by policy: they must be a member of at least one factor and
	// must hold the capability for the frozen operation on the frozen path.
	// Approvals from principals without the capability are invalid.
	matched, err := c.controlGroupFactorsSatisfiedBy(ctx, ns, state, actor)
	if err != nil {
		return nil, ErrInternalError
	}
	if len(matched) == 0 {
		return logical.ErrorResponse("approver is not authorized by the control group policy"), logical.ErrPermissionDenied
	}
	capable, err := c.actorHoldsCapability(ctx, req, state)
	if err != nil {
		return nil, ErrInternalError
	}
	if !capable {
		return logical.ErrorResponse("approver does not hold the policy capability for this request"), logical.ErrPermissionDenied
	}

	now := time.Now().UTC()

	if deny {
		state.Denial = &controlGroupApproval{
			EntityID:      actor.ID,
			EntityName:    actor.Name,
			TokenAccessor: tokenAccessor(actorTE),
			Time:          now,
		}
		state.AuditTrail = append(state.AuditTrail, controlGroupAuditEvent{
			Time: now, ActorID: actor.ID, ActorName: actor.Name, Action: "denied",
		})
		if err := c.persistControlGroupState(ctx, ns, state); err != nil {
			return nil, ErrInternalError
		}
		c.revokeControlGroupToken(ns, state)
		c.auditControlGroupEvent(ctx, req, nil, "control-group/denied", map[string]interface{}{
			"accessor":     accessor,
			"actor_id":     actor.ID,
			"actor_name":   actor.Name,
			"request_path": state.Path,
		})
		return logical.ErrorResponse(ErrControlGroupDenied.Error()), logical.ErrInvalidRequest
	}

	// Count only toward factors that still need approvals.
	useful := controlGroupUsefulFactors(state, matched)
	if len(useful) == 0 {
		return logical.ErrorResponse("control group request already has enough approvals from the approver's groups"), logical.ErrInvalidRequest
	}

	state.Approvals = append(state.Approvals, controlGroupApproval{
		EntityID:      actor.ID,
		EntityName:    actor.Name,
		TokenAccessor: tokenAccessor(actorTE),
		Factors:       useful,
		Time:          now,
	})
	state.AuditTrail = append(state.AuditTrail, controlGroupAuditEvent{
		Time: now, ActorID: actor.ID, ActorName: actor.Name, Action: "approved", Detail: strings.Join(useful, ","),
	})

	remaining := controlGroupRemainingApprovals(state)
	if remaining == 0 && !state.Approved {
		state.Approved = true
		state.ApprovedAt = now
		state.AuditTrail = append(state.AuditTrail, controlGroupAuditEvent{
			Time: now, Action: "threshold_reached",
		})
	}

	// Persist the approval together with the approved flag in one write. On
	// failure nothing is recorded and the request cannot proceed.
	if err := c.persistControlGroupState(ctx, ns, state); err != nil {
		return nil, ErrInternalError
	}

	return &logical.Response{Data: map[string]interface{}{
		"accessor":     accessor,
		"request_path": state.Path,
		"approved":     state.Approved,
		"remaining":    remaining,
		"factors":      controlGroupFactorStatus(state),
	}}, nil
}

// controlGroupStatus builds the status response for a pending request.
func (c *Core) controlGroupStatus(ctx context.Context, state *controlGroupState) (*logical.Response, error) {
	requestEntity := map[string]interface{}{}
	if state.RequesterEntityID != "" {
		requestEntity["id"] = state.RequesterEntityID
		requestEntity["name"] = state.RequesterEntityName
	}
	return &logical.Response{Data: map[string]interface{}{
		"accessor":            state.Accessor,
		"request_path":        state.Path,
		"operation":           string(state.Operation),
		"approved":            state.Approved,
		"remaining":           controlGroupRemainingApprovals(state),
		"factors":             controlGroupFactorStatus(state),
		"authorizations":      controlGroupAuthorizations(state),
		"requester_entity_id": state.RequesterEntityID,
		"request_entity":      requestEntity,
		"request_time":        state.CreationTime.Format(time.RFC3339Nano),
		"expiration_time":     state.ExpirationTime.Format(time.RFC3339Nano),
		"cancelled":           state.Cancelled,
		"denied":              state.Denial != nil,
		"completed":           state.Completed,
		"expired":             controlGroupIsExpired(state),
		"audit_trail":         controlGroupAuditTrail(state),
	}}, nil
}

// cancelControlGroup withdraws a pending request. The requester may always
// cancel; an approver authorized by the policy may also cancel, for example
// when the threshold has become unreachable.
func (c *Core) cancelControlGroup(ctx context.Context, req *logical.Request, actor *identity.Entity, accessor, reason string) (*logical.Response, error) {
	if actor == nil || actor.ID == "" {
		return logical.ErrorResponse("control group cancellation requires an entity-backed token"), logical.ErrPermissionDenied
	}

	lock := c.controlGroup.requestLock(accessor)
	lock.Lock()
	defer lock.Unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	state, err := c.loadControlGroupState(ctx, accessor)
	if err != nil {
		return nil, ErrInternalError
	}
	if state == nil {
		return logical.ErrorResponse("control group request not found"), logical.ErrNotFound
	}
	if state.Completed {
		return logical.ErrorResponse("control group request has already been completed"), logical.ErrInvalidRequest
	}
	if state.Cancelled {
		return logical.ErrorResponse(ErrControlGroupCancelled.Error()), logical.ErrInvalidRequest
	}

	if actor.ID != state.RequesterEntityID {
		matched, err := c.controlGroupFactorsSatisfiedBy(ctx, ns, state, actor)
		if err != nil {
			return nil, ErrInternalError
		}
		if len(matched) == 0 {
			return logical.ErrorResponse("only the requester or an authorized approver may cancel this request"), logical.ErrPermissionDenied
		}
	}

	now := time.Now().UTC()
	state.Cancelled = true
	state.CancelledAt = now
	state.CancelReason = reason
	state.AuditTrail = append(state.AuditTrail, controlGroupAuditEvent{
		Time: now, ActorID: actor.ID, ActorName: actor.Name, Action: "cancelled", Detail: reason,
	})
	if err := c.persistControlGroupState(ctx, ns, state); err != nil {
		return nil, ErrInternalError
	}
	c.revokeControlGroupToken(ns, state)

	c.auditControlGroupEvent(ctx, req, nil, "control-group/cancelled", map[string]interface{}{
		"accessor":     accessor,
		"actor_id":     actor.ID,
		"actor_name":   actor.Name,
		"request_path": state.Path,
		"reason":       reason,
	})
	return &logical.Response{Data: map[string]interface{}{
		"accessor":  accessor,
		"cancelled": true,
		"reason":    reason,
	}}, nil
}

// completeControlGroup replays an approved request exactly once and returns the
// marshaled HTTP response, matching what a direct call would have produced. It
// is invoked from sys/wrapping/unwrap.
func (c *Core) completeControlGroup(ctx context.Context, ns *namespace.Namespace, accessor string) (string, error) {
	lock := c.controlGroup.requestLock(accessor)
	lock.Lock()
	defer lock.Unlock()

	state, err := c.loadControlGroupState(ctx, accessor)
	if err != nil {
		return "", ErrInternalError
	}
	if state == nil {
		return "", fmt.Errorf("control group request not found: %w", consts.ErrInvalidWrappingToken)
	}

	if controlGroupIsExpired(state) {
		if err := c.expireControlGroup(ctx, ns, state, "expired"); err != nil {
			return "", ErrInternalError
		}
		return "", fmt.Errorf("%w: %w", ErrControlGroupExpired, consts.ErrInvalidWrappingToken)
	}
	switch {
	case state.Cancelled:
		return "", fmt.Errorf("%w: %w", ErrControlGroupCancelled, consts.ErrInvalidWrappingToken)
	case state.Denial != nil:
		return "", fmt.Errorf("%w: %w", ErrControlGroupDenied, consts.ErrInvalidWrappingToken)
	case state.Completed:
		// One-time: a replayed token neither re-runs nor reveals anything.
		return "", fmt.Errorf("control group request has already been completed: %w", consts.ErrInvalidWrappingToken)
	case !state.Approved:
		return "", logical.ErrMultiAuthzPending
	}

	replayNS := ns
	if state.RequesterNamespaceID != "" {
		if byID, err := NamespaceByID(ctx, state.RequesterNamespaceID, c); err == nil && byID != nil {
			replayNS = byID
		}
	}
	replayCtx := namespace.ContextWithNamespace(ctx, replayNS)

	// Claim the request durably before running it. Marking it completed in a
	// single write is the write-ahead record: if this write fails nothing has
	// run, and if it succeeds a concurrent or retried completion will see the
	// claim and refuse. The effect is therefore never applied without a record.
	if err := c.claimControlGroupCompletion(ctx, replayNS, state); err != nil {
		return "", ErrInternalError
	}

	// The replayed request is built only from the stored record. Nothing from
	// the completion call is copied in.
	replayReq := &logical.Request{
		Operation:    state.Operation,
		Path:         state.Path,
		Data:         deepCopyData(state.Data),
		Headers:      cloneHeaders(state.Headers),
		ClientToken:  state.TokenID,
		ControlGroup: controlGroupLogical(state),
	}
	// Present the requester's identity to the backend. The pending token was
	// minted with the requester's entity and namespace, so looking it up yields
	// the identity the original request ran as. This matters for backends that
	// key behavior off the token entry (cubbyhole, identity templating).
	if te, err := c.tokenStore.lookupTainted(ctx, state.TokenID); err == nil && te != nil {
		replayReq.SetTokenEntry(te)
		replayReq.EntityID = te.EntityID
	}

	resp, routeErr := c.doRouting(replayCtx, replayReq)
	if routeErr != nil {
		// The operation did not complete. Release the claim so the request can
		// be retried once the underlying problem is resolved; the audit trail
		// records the failed attempt.
		if releaseErr := c.releaseControlGroupCompletion(ctx, replayNS, state); releaseErr != nil {
			c.logger.Error("failed to release control group completion claim", "accessor", state.Accessor, "error", releaseErr)
		}
		return "", routeErr
	}
	if resp == nil {
		resp = &logical.Response{}
	}

	httpResp := logical.LogicalResponseToHTTPResponse(resp)
	marshaled, err := json.Marshal(httpResp)
	if err != nil {
		return "", fmt.Errorf("failed to marshal control group result: %w", err)
	}

	// Record the executed request and its final response in the audit log so the
	// outcome is traceable end to end. The replay is marked as a control group
	// run, so the normal request/response audit cannot produce this record.
	c.auditControlGroupResult(ctx, replayReq, resp, "control-group/completed", map[string]interface{}{
		"accessor":     state.Accessor,
		"request_path": state.Path,
		"approved_by":  controlGroupApproverNames(state),
	})

	return string(marshaled), nil
}

// controlGroupApproverNames lists the entities that approved a request.
func controlGroupApproverNames(state *controlGroupState) []string {
	names := make([]string, 0, len(state.Approvals))
	for _, ap := range state.Approvals {
		names = append(names, ap.EntityName)
	}
	return names
}

// claimControlGroupCompletion durably marks a request as completed before its
// effect runs. This is the write-ahead record: the effect is never applied
// unless this write succeeds, and once it succeeds a retry cannot run again.
func (c *Core) claimControlGroupCompletion(ctx context.Context, ns *namespace.Namespace, state *controlGroupState) error {
	now := time.Now().UTC()
	state.Completed = true
	state.CompletedAt = now
	state.AuditTrail = append(state.AuditTrail, controlGroupAuditEvent{
		Time: now, Action: "completed",
	})
	return c.persistControlGroupState(ctx, ns, state)
}

// releaseControlGroupCompletion undoes a completion claim after the underlying
// operation failed, so the request can be retried. It records the failed
// attempt in the trail.
func (c *Core) releaseControlGroupCompletion(ctx context.Context, ns *namespace.Namespace, state *controlGroupState) error {
	state.Completed = false
	state.CompletedAt = time.Time{}
	state.AuditTrail = append(state.AuditTrail, controlGroupAuditEvent{
		Time: time.Now().UTC(), Action: "completion_failed",
	})
	return c.persistControlGroupState(ctx, ns, state)
}

// controlGroupLogical builds the ControlGroup carried by the replayed request.
func controlGroupLogical(state *controlGroupState) *logical.ControlGroup {
	authz := make([]*logical.Authz, 0, len(state.Approvals))
	for _, ap := range state.Approvals {
		authz = append(authz, &logical.Authz{
			Token:             ap.TokenAccessor,
			AuthorizationTime: ap.Time,
		})
	}
	return &logical.ControlGroup{
		Approved:       true,
		RequestTime:    state.CreationTime,
		NamespaceID:    state.RequesterNamespaceID,
		Authorizations: authz,
	}
}

// revokeControlGroupToken revokes the pending token, if any.
func (c *Core) revokeControlGroupToken(ns *namespace.Namespace, state *controlGroupState) {
	if state.TokenID == "" || c.tokenStore == nil {
		return
	}
	ctx := namespace.ContextWithNamespace(c.activeContext, ns)
	if err := c.tokenStore.revokeOrphan(ctx, state.TokenID); err != nil {
		c.logger.Warn("failed to revoke control group token", "accessor", state.Accessor, "error", err)
	}
}

// expireControlGroup marks a request expired, revokes its token and persists
// the record so the trail remains.
func (c *Core) expireControlGroup(ctx context.Context, ns *namespace.Namespace, state *controlGroupState, reason string) error {
	now := time.Now().UTC()
	state.ExpiredAt = now
	state.Cancelled = true
	state.CancelledAt = now
	if state.CancelReason == "" {
		state.CancelReason = reason
	}
	state.AuditTrail = append(state.AuditTrail, controlGroupAuditEvent{
		Time: now, Action: "expired", Detail: reason,
	})
	if err := c.persistControlGroupState(ctx, ns, state); err != nil {
		return err
	}
	c.revokeControlGroupToken(ns, state)
	return nil
}

// controlGroupIsExpired reports whether the request is past its deadline.
func controlGroupIsExpired(state *controlGroupState) bool {
	return !state.ExpirationTime.IsZero() && time.Now().After(state.ExpirationTime)
}

// actorHoldsCapability reports whether the calling token is allowed by policy
// to perform the frozen operation on the frozen path. The control group itself
// is ignored here (using capCheckOnly) so that holding the capability — not
// having already satisfied a nested control group — is what is tested.
func (c *Core) actorHoldsCapability(ctx context.Context, req *logical.Request, state *controlGroupState) (bool, error) {
	probe := &logical.Request{
		Operation:   state.Operation,
		Path:        state.Path,
		Data:        deepCopyData(state.Data),
		ClientToken: req.ClientToken,
		Headers:     cloneHeaders(req.Headers),
	}
	probe.SetTokenEntry(req.TokenEntry())

	acl, _, _, _, err := c.fetchACLTokenEntryAndEntity(ctx, probe)
	if err != nil {
		return false, err
	}
	if acl == nil {
		return false, nil
	}
	results := acl.AllowOperation(ctx, probe, false)
	return results != nil && results.Allowed, nil
}

// controlGroupFactorsSatisfiedBy returns the factor names the actor belongs to.
func (c *Core) controlGroupFactorsSatisfiedBy(ctx context.Context, ns *namespace.Namespace, state *controlGroupState, actor *identity.Entity) ([]string, error) {
	if c.identityStore == nil || actor == nil {
		return nil, nil
	}
	// Include membership inherited through nested groups, so that an approver
	// in a sub-group of a named group qualifies.
	groups, more, err := c.identityStore.groupsByEntityID(actor.ID)
	if err != nil {
		return nil, err
	}
	groups = append(groups, more...)

	memberIDs := make(map[string]struct{}, len(groups))
	memberNames := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		memberIDs[g.ID] = struct{}{}
		memberNames[g.Name] = struct{}{}
	}

	var matched []string
	for _, factor := range state.Factors {
		member := false
		for _, id := range factor.GroupIDs {
			if _, ok := memberIDs[id]; ok {
				member = true
				break
			}
		}
		if !member {
			for _, name := range factor.GroupNames {
				if _, ok := memberNames[name]; ok {
					member = true
					break
				}
			}
		}
		if member {
			matched = append(matched, factor.Name)
		}
	}
	return matched, nil
}

// controlGroupFactorsFromPolicy snapshots the policy factors.
func controlGroupFactorsFromPolicy(cg *ControlGroup) []controlGroupFactorState {
	if cg == nil {
		return nil
	}
	factors := make([]controlGroupFactorState, 0, len(cg.Factors))
	for _, f := range cg.Factors {
		if f == nil || f.Identity == nil {
			continue
		}
		factors = append(factors, controlGroupFactorState{
			Name:                   f.Name,
			GroupIDs:               append([]string{}, f.Identity.GroupIDs...),
			GroupNames:             append([]string{}, f.Identity.GroupNames...),
			ApprovalsRequired:      f.Identity.ApprovalsRequired,
			ControlledCapabilities: append([]string{}, f.ControlledCapabilities...),
		})
	}
	return factors
}

// firstGrantingPolicy names the policy that granted the operation.
func firstGrantingPolicy(results *ACLResults) string {
	if results == nil || len(results.GrantingPolicies) == 0 {
		return ""
	}
	return results.GrantingPolicies[0].Name
}

// controlGroupApprovalsForFactor counts distinct approvals for a factor.
func controlGroupApprovalsForFactor(state *controlGroupState, factorName string) int {
	seen := map[string]struct{}{}
	for _, ap := range state.Approvals {
		for _, f := range ap.Factors {
			if f == factorName {
				seen[ap.EntityID] = struct{}{}
				break
			}
		}
	}
	return len(seen)
}

// controlGroupRemainingApprovals returns approvals still needed across factors.
func controlGroupRemainingApprovals(state *controlGroupState) int {
	if state == nil {
		return 0
	}
	remaining := 0
	for _, f := range state.Factors {
		if n := f.ApprovalsRequired - controlGroupApprovalsForFactor(state, f.Name); n > 0 {
			remaining += n
		}
	}
	return remaining
}

// controlGroupUsefulFactors returns matched factors that still need approvals.
func controlGroupUsefulFactors(state *controlGroupState, matched []string) []string {
	var useful []string
	for _, name := range matched {
		for _, f := range state.Factors {
			if f.Name == name && controlGroupApprovalsForFactor(state, name) < f.ApprovalsRequired {
				useful = append(useful, name)
			}
		}
	}
	return useful
}

// controlGroupFactorStatus renders per-factor progress.
func controlGroupFactorStatus(state *controlGroupState) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(state.Factors))
	for _, f := range state.Factors {
		got := controlGroupApprovalsForFactor(state, f.Name)
		remaining := f.ApprovalsRequired - got
		if remaining < 0 {
			remaining = 0
		}
		out = append(out, map[string]interface{}{
			"name":               f.Name,
			"approvals_required": f.ApprovalsRequired,
			"approvals":          got,
			"remaining":          remaining,
		})
	}
	return out
}

// controlGroupAuthorizations renders approvals for status responses.
func controlGroupAuthorizations(state *controlGroupState) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(state.Approvals))
	for _, ap := range state.Approvals {
		out = append(out, map[string]interface{}{
			"entity_id":   ap.EntityID,
			"entity_name": ap.EntityName,
			"factors":     ap.Factors,
			"time":        ap.Time.Format(time.RFC3339Nano),
		})
	}
	return out
}

// controlGroupAuditTrail renders the lifecycle trail for export.
func controlGroupAuditTrail(state *controlGroupState) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(state.AuditTrail))
	for _, ev := range state.AuditTrail {
		out = append(out, map[string]interface{}{
			"time":       ev.Time.Format(time.RFC3339Nano),
			"actor_id":   ev.ActorID,
			"actor_name": ev.ActorName,
			"action":     ev.Action,
			"detail":     ev.Detail,
		})
	}
	return out
}

// auditControlGroupEvent emits a dedicated audit record for a lifecycle event.
// A failure here is logged but never fails the request; the persisted record
// carries the same trail and the normal request/response audit is written by
// the main pipeline.
func (c *Core) auditControlGroupEvent(ctx context.Context, req *logical.Request, auth *logical.Auth, path string, data map[string]interface{}) {
	if c.auditBroker == nil {
		return
	}
	logReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Data:      data,
	}
	if req != nil {
		logReq.ClientToken = req.ClientToken
		logReq.ID = req.ID
	}
	if err := c.auditBroker.LogRequest(ctx, &logical.LogInput{Auth: auth, Request: logReq}); err != nil {
		c.logger.Error("failed to audit control group event", "path", path, "error", err)
	}
}

// auditControlGroupResult writes both the request and the response of a
// control-group lifecycle event, so the final outcome is captured alongside the
// action that produced it.
func (c *Core) auditControlGroupResult(ctx context.Context, req *logical.Request, resp *logical.Response, path string, data map[string]interface{}) {
	if c.auditBroker == nil {
		return
	}
	logReq := &logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        path,
		Data:        data,
		ClientToken: req.ClientToken,
		ID:          req.ID,
	}
	if err := c.auditBroker.LogResponse(ctx, &logical.LogInput{Request: logReq, Response: resp}); err != nil {
		c.logger.Error("failed to audit control group result", "path", path, "error", err)
	}
}

// sweepControlGroups reclaims expired records until ctx is cancelled.
func (c *Core) sweepControlGroups(ctx context.Context) {
	ticker := time.NewTicker(controlGroupSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.cleanupExpiredControlGroups(ctx)
		}
	}
}

// cleanupExpiredControlGroups deletes records well past their deadline. Expired
// requests are already refused on access; this only reclaims storage.
func (c *Core) cleanupExpiredControlGroups(ctx context.Context) {
	view := c.controlGroupView()
	if view == nil {
		return
	}
	keys, err := view.List(ctx, controlGroupStoragePrefix)
	if err != nil {
		c.logger.Error("failed to list control group requests", "error", err)
		return
	}
	now := time.Now()
	for _, key := range keys {
		entry, err := view.Get(ctx, controlGroupStoragePrefix+key)
		if err != nil || entry == nil {
			continue
		}
		state := new(controlGroupState)
		if err := jsonutil.DecodeJSON(entry.Value, state); err != nil {
			continue
		}
		if state.ExpirationTime.IsZero() || now.Before(state.ExpirationTime.Add(controlGroupGracePeriod)) {
			continue
		}
		if err := view.Delete(ctx, controlGroupStoragePrefix+key); err != nil {
			c.logger.Error("failed to delete expired control group request", "accessor", key, "error", err)
		}
	}
}

// loadControlGroupConfig reads the cluster configuration into memory.
func (c *Core) loadControlGroupConfig(ctx context.Context) {
	view := c.controlGroupView()
	if view == nil {
		return
	}
	entry, err := view.Get(ctx, controlGroupConfigStoragePath)
	if err != nil {
		c.logger.Error("failed to read control group config", "error", err)
		return
	}
	cfg := new(controlGroupConfig)
	if entry != nil {
		if err := jsonutil.DecodeJSON(entry.Value, cfg); err != nil {
			c.logger.Error("failed to decode control group config", "error", err)
			cfg = new(controlGroupConfig)
		}
	}
	c.controlGroup.setConfig(cfg)
}

// storeControlGroupConfig persists the cluster configuration.
func (c *Core) storeControlGroupConfig(ctx context.Context, cfg *controlGroupConfig) error {
	view := c.controlGroupView()
	if view == nil {
		return errors.New("control group storage is unavailable")
	}
	if cfg.MaxTTL < 0 {
		return errors.New("max_ttl cannot be negative")
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := view.Put(ctx, &logical.StorageEntry{Key: controlGroupConfigStoragePath, Value: raw}); err != nil {
		return err
	}
	c.controlGroup.setConfig(cfg)
	return nil
}

// controlGroupView returns the system barrier view used for control group
// state, or nil when the system backend is not mounted.
func (c *Core) controlGroupView() *BarrierView {
	return c.systemBarrierView
}

// parseControlGroupTTL converts an API value into a duration.
func parseControlGroupTTL(v interface{}) (time.Duration, error) {
	if v == nil {
		return 0, nil
	}
	d, err := parseutil.ParseDurationSecond(v)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, errors.New("max_ttl cannot be negative")
	}
	return d, nil
}

// tokenAccessor returns a token entry's accessor if present.
func tokenAccessor(te *logical.TokenEntry) string {
	if te == nil {
		return ""
	}
	return te.Accessor
}

// deepCopyData copies request data so later caller mutation cannot change the
// frozen request.
func deepCopyData(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	copied, err := copystructure.Copy(in)
	if err != nil {
		out := make(map[string]interface{}, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	return copied.(map[string]interface{})
}

// controlGroupUnwrap completes a pending request when the caller presents its
// control-group token to sys/wrapping/unwrap.
// controlGroupUnwrap completes a pending request when the caller presents its
// control-group token to sys/wrapping/unwrap.
func (b *SystemBackend) controlGroupUnwrap(ctx context.Context, token string, thirdParty bool) (string, error) {
	te, err := b.Core.tokenStore.lookupTainted(ctx, token)
	if err != nil {
		return "", err
	}
	if te == nil {
		return "", fmt.Errorf("control group token not found: %w", consts.ErrInvalidWrappingToken)
	}

	// Map the token back to its pending request through the accessor store.
	state, err := b.Core.controlGroupStateForToken(ctx, te)
	if err != nil {
		return "", err
	}
	if state == nil {
		return "", fmt.Errorf("control group request not found: %w", consts.ErrInvalidWrappingToken)
	}

	ns, err := NamespaceByID(ctx, te.NamespaceID, b.Core)
	if err != nil {
		return "", err
	}
	if ns == nil {
		return "", fmt.Errorf("control group token is not from a valid namespace: %w", consts.ErrInvalidWrappingToken)
	}
	nsCtx := namespace.ContextWithNamespace(ctx, ns)

	if thirdParty {
		// Third-party completion consumes the token's single use up front so a
		// concurrent completion cannot also use it.
		if _, err := b.Core.tokenStore.UseTokenByID(ctx, te.ID); err != nil {
			return "", fmt.Errorf("error decrementing control group token's use-count: %w", err)
		}
	}

	result, completeErr := b.Core.completeControlGroup(ctx, ns, state.Accessor)
	// Revoke the token once the request has reached a terminal state, or once it
	// has actually run. A not-yet-approved request leaves the token usable so the
	// requester can present it again after approvals complete; the token's own
	// TTL is the backstop.
	switch {
	case completeErr == nil:
		_ = b.Core.tokenStore.revokeOrphan(nsCtx, te.ID)
	case errors.Is(completeErr, ErrControlGroupExpired),
		errors.Is(completeErr, ErrControlGroupCancelled),
		errors.Is(completeErr, ErrControlGroupDenied):
		_ = b.Core.tokenStore.revokeOrphan(nsCtx, te.ID)
	}
	return result, completeErr
}

// controlGroupStateForToken finds the pending request completed by a
// control-group token.
func (c *Core) controlGroupStateForToken(ctx context.Context, te *logical.TokenEntry) (*controlGroupState, error) {
	if te == nil || te.Accessor == "" {
		return nil, nil
	}
	return c.loadControlGroupState(ctx, te.Accessor)
}

// cloneHeaders copies headers.
func cloneHeaders(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string{}, v...)
	}
	return out
}

// controlGroupCaller resolves the entity and token entry for the authenticated
// caller of an API request.
func (b *SystemBackend) controlGroupCaller(ctx context.Context, req *logical.Request) (*identity.Entity, *logical.TokenEntry, error) {
	_, te, entity, _, err := b.Core.fetchACLTokenEntryAndEntity(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	if te == nil {
		return nil, nil, logical.ErrPermissionDenied
	}
	if entity != nil && entity.Disabled {
		return nil, nil, logical.ErrPermissionDenied
	}
	if te.EntityID != "" && entity == nil {
		return nil, nil, logical.ErrPermissionDenied
	}
	return entity, te, nil
}

// handleControlGroupAuthorize implements sys/control-group/authorize.
func (b *SystemBackend) handleControlGroupAuthorize(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accessor := strings.TrimSpace(data.Get("accessor").(string))
	if accessor == "" {
		return logical.ErrorResponse("missing accessor"), logical.ErrInvalidRequest
	}
	deny := data.Get("deny").(bool)

	entity, te, err := b.controlGroupCaller(ctx, req)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return logical.ErrorResponse("control group approval requires an entity-backed token"), logical.ErrPermissionDenied
	}
	return b.Core.authorizeControlGroup(ctx, req, entity, te, accessor, deny)
}

// handleControlGroupRequest implements sys/control-group/request: a status read.
func (b *SystemBackend) handleControlGroupRequest(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accessor := strings.TrimSpace(data.Get("accessor").(string))
	if accessor == "" {
		return logical.ErrorResponse("missing accessor"), logical.ErrInvalidRequest
	}
	state, err := b.Core.loadControlGroupState(ctx, accessor)
	if err != nil {
		return nil, ErrInternalError
	}
	if state == nil {
		return logical.ErrorResponse("control group request not found"), logical.ErrNotFound
	}
	if controlGroupIsExpired(state) && !state.Completed {
		// Reflect expiry without mutating on a read.
		resp, _ := b.Core.controlGroupStatus(ctx, state)
		resp.Data["expired"] = true
		resp.AddWarning(ErrControlGroupExpired.Error())
		return resp, nil
	}
	return b.Core.controlGroupStatus(ctx, state)
}

// handleControlGroupCancel implements sys/control-group/cancel.
func (b *SystemBackend) handleControlGroupCancel(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	accessor := strings.TrimSpace(data.Get("accessor").(string))
	if accessor == "" {
		return logical.ErrorResponse("missing accessor"), logical.ErrInvalidRequest
	}
	reason := data.Get("reason").(string)

	entity, _, err := b.controlGroupCaller(ctx, req)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return logical.ErrorResponse("control group cancellation requires an entity-backed token"), logical.ErrPermissionDenied
	}
	return b.Core.cancelControlGroup(ctx, req, entity, accessor, reason)
}

// handleControlGroupConfigUpdate implements sys/config/control-group.
func (b *SystemBackend) handleControlGroupConfigUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	raw, ok := data.GetOk("max_ttl")
	if !ok {
		return nil, nil
	}
	ttl, err := parseControlGroupTTL(raw)
	if err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	cfg := &controlGroupConfig{MaxTTL: ttl}
	if err := b.Core.storeControlGroupConfig(ctx, cfg); err != nil {
		return nil, err
	}
	return nil, nil
}

// handleControlGroupConfigRead implements sys/config/control-group.
func (b *SystemBackend) handleControlGroupConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	view := b.Core.controlGroupView()
	if view == nil {
		return logical.ErrorResponse("control group storage is unavailable"), nil
	}
	cfg := &controlGroupConfig{}
	entry, err := view.Get(ctx, controlGroupConfigStoragePath)
	if err != nil {
		return nil, ErrInternalError
	}
	if entry != nil {
		if err := jsonutil.DecodeJSON(entry.Value, cfg); err != nil {
			return nil, ErrInternalError
		}
	}
	return &logical.Response{Data: map[string]interface{}{
		"max_ttl": int64(cfg.MaxTTL.Seconds()),
	}}, nil
}

// handleControlGroupConfigDelete implements sys/config/control-group.
func (b *SystemBackend) handleControlGroupConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	view := b.Core.controlGroupView()
	if view == nil {
		return logical.ErrorResponse("control group storage is unavailable"), nil
	}
	if err := view.Delete(ctx, controlGroupConfigStoragePath); err != nil {
		return nil, err
	}
	b.Core.controlGroup.setConfig(new(controlGroupConfig))
	return nil, nil
}

// controlGroupPaths returns the sys/control-group/* endpoints.
func controlGroupPaths(b *SystemBackend) []*framework.Path {
	fieldsAccessor := map[string]*framework.FieldSchema{
		"accessor": {
			Type:        framework.TypeString,
			Description: "Accessor of the control group request.",
		},
	}
	return []*framework.Path{
		{
			Pattern: "control-group/authorize$",
			Fields: map[string]*framework.FieldSchema{
				"accessor": {
					Type:        framework.TypeString,
					Description: "Accessor of the control group request to authorize.",
				},
				"deny": {
					Type:        framework.TypeBool,
					Description: "Reject the request instead of approving it.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleControlGroupAuthorize,
					Summary:  "Authorize a control group request.",
				},
			},
			HelpSynopsis:    "Approve or deny a pending control group request.",
			HelpDescription: "Records the caller's approval or denial of a pending control group request.",
		},
		{
			Pattern: "control-group/request$",
			Fields:  fieldsAccessor,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleControlGroupRequest,
					Summary:  "Read the status of a control group request.",
				},
			},
			HelpSynopsis:    "Read a pending control group request.",
			HelpDescription: "Returns the remaining approvals and lifecycle trail for a control group request.",
		},
		{
			Pattern: "control-group/cancel$",
			Fields: map[string]*framework.FieldSchema{
				"accessor": {
					Type:        framework.TypeString,
					Description: "Accessor of the control group request to cancel.",
				},
				"reason": {
					Type:        framework.TypeString,
					Description: "Optional reason for cancelling.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleControlGroupCancel,
					Summary:  "Cancel a control group request.",
				},
			},
			HelpSynopsis:    "Cancel a pending control group request.",
			HelpDescription: "Withdraws a pending request or aborts an approved one before completion.",
		},
		{
			Pattern: "config/control-group$",
			Fields: map[string]*framework.FieldSchema{
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lifetime of a control group request.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleControlGroupConfigUpdate,
					Summary:  "Configure control groups.",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleControlGroupConfigRead,
					Summary:  "Read the control group configuration.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleControlGroupConfigDelete,
					Summary:  "Remove the control group configuration.",
				},
			},
			HelpSynopsis:    "Configure cluster-wide control group behavior.",
			HelpDescription: "Sets a cluster-wide maximum lifetime for control group requests.",
		},
	}
}
