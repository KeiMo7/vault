// Copyright IBM Corp. 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"sync"
	"time"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

// Renew gate lifecycle states.
const (
	// RenewGateSealed indicates the gate (and Vault) is sealed. No renewal may
	// begin or commit while the gate is in this state.
	RenewGateSealed RenewGateState = iota
	// RenewGateRestoring indicates the expiration manager is restoring lease
	// state from storage after an unseal. Renewals are permitted while restore
	// is in progress.
	RenewGateRestoring
	// RenewGateOpen indicates restore has completed and normal renewal
	// processing is permitted.
	RenewGateOpen
)

// Per-attempt renewal states.
const (
	// RenewPending marks an attempt that has begun but not yet committed or
	// aborted.
	RenewPending RenewState = iota
	// RenewApplied marks an attempt whose result has been durably committed.
	RenewApplied
	// RenewAborted marks an attempt that was abandoned before commit.
	RenewAborted
)

const (
	// renewDedupTTL is how long a successful renewal response is retained in
	// the idempotency cache.
	renewDedupTTL = 5 * time.Minute
	// renewDedupMax is the maximum number of entries held in the idempotency
	// cache before the oldest entry is evicted.
	renewDedupMax = 4096
)

var (
	// ErrRenewTransition is returned when a RenewAttempt is asked to move
	// between two states that are not a permitted transition.
	ErrRenewTransition = errors.New("invalid renewal state transition")

	// ErrRenewEpochStale is returned by Commit when the attempt was begun in a
	// different gate epoch than the one currently active. This happens when a
	// seal or restore boundary is crossed while a renewal is in flight.
	ErrRenewEpochStale = errors.New("renewal attempted against a stale gate epoch")

	// ErrRenewGateUnavailable is returned when renewal processing is required
	// but no RenewGate is wired up. Callers may match it with errors.Is.
	ErrRenewGateUnavailable = errors.New("renewal gate is unavailable")
)

// RenewGateState describes the lifecycle state of a RenewGate.
type RenewGateState uint32

// String returns a human readable representation of the gate state.
func (s RenewGateState) String() string {
	switch s {
	case RenewGateSealed:
		return "sealed"
	case RenewGateRestoring:
		return "restoring"
	case RenewGateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// RenewState describes the lifecycle state of a single RenewAttempt.
type RenewState uint32

// String returns a human readable representation of the attempt state.
func (s RenewState) String() string {
	switch s {
	case RenewPending:
		return "pending"
	case RenewApplied:
		return "applied"
	case RenewAborted:
		return "aborted"
	default:
		return "unknown"
	}
}

// renewKey identifies a renewal request for the purposes of idempotent
// de-duplication. It is a comparable value type safe to use as a map key. The
// namespace ID and caller accessor are part of the key so leases which share a
// lease ID shape across namespaces or callers can never collide.
type renewKey struct {
	NamespaceID    string
	LeaseID        string
	RenewalID      string
	CallerAccessor string
}

// renewCacheEntry stores a deep-copied renewal response together with the time
// it was written so that stale entries can expire and the oldest entry can be
// evicted once the cache reaches its size cap.
type renewCacheEntry struct {
	response  *logical.Response
	writtenAt time.Time
}

// RenewAttempt tracks a single in-flight renewal as it moves through the gate.
type RenewAttempt struct {
	// AttemptID uniquely identifies the attempt within the gate.
	AttemptID uint64
	// LeaseID is the lease being renewed.
	LeaseID string
	// NamespaceID is the namespace the lease belongs to.
	NamespaceID string
	// TokenAccessor is the accessor of the token performing the renewal.
	TokenAccessor string
	// RequestID is the logical request ID associated with the renewal.
	RequestID string
	// Epoch is the gate epoch captured when the attempt began.
	Epoch uint64
	// Increment is the requested renewal increment.
	Increment time.Duration
	// Started is when the attempt began.
	Started time.Time
	// PrevExpireTime is the lease expiration time before the renewal.
	PrevExpireTime time.Time
	// NextExpireTime is the lease expiration time produced by the renewal.
	NextExpireTime time.Time
	// State is the current lifecycle state of the attempt.
	State RenewState

	// key is the de-duplication key associated with the attempt, used to
	// populate the idempotency cache on a successful commit. It may be the zero
	// value when caching is disabled for the request.
	key renewKey
	// cacheable reports whether the attempt should populate the de-duplication
	// cache on commit.
	cacheable bool
}

// RenewGateSnapshot is the read-only projection of gate state exposed through
// the renewal status endpoint. It deliberately contains no lease IDs, token
// IDs, or accessors.
type RenewGateSnapshot struct {
	// State is the current gate state rendered as a string.
	State string
	// Epoch is the current gate epoch.
	Epoch uint64
	// Inflight is the number of renewal attempts currently in flight.
	Inflight int
	// SealedRejections counts attempts rejected because the gate was sealed.
	SealedRejections uint64
	// StaleCommits counts commits rejected because of an epoch mismatch.
	StaleCommits uint64
	// RestoreCompletedAt is when the most recent restore completed and the gate
	// opened. It is the zero value until that happens.
	RestoreCompletedAt time.Time
}

// RenewGate serializes and guards lease and token renewal across seal and
// restore boundaries. It tracks the gate epoch, in-flight attempts and an
// idempotency cache keyed by renewal identifiers. The gate is intentionally
// mounted on Core so that its epoch and counters survive the recreation of the
// ExpirationManager that happens on every seal/unseal cycle.
type RenewGate struct {
	// mu guards every mutable field below. It is only ever held briefly; the
	// per-lease mutex, pendingLock and storage/backend calls are never invoked
	// while mu is held.
	mu sync.Mutex

	// epoch is bumped on every seal, restore-begin and restore-open boundary.
	epoch uint64
	// nextAttemptID assigns a unique ID to each begun attempt.
	nextAttemptID uint64
	// state is the current lifecycle state of the gate.
	state RenewGateState

	// inflight tracks attempts that have begun but not reached a terminal
	// state.
	inflight map[uint64]*RenewAttempt
	// dedup caches successful renewal responses for idempotent retries.
	dedup map[renewKey]renewCacheEntry

	// now is the clock used for all timestamps and cache expiry decisions. It
	// defaults to time.Now and may be replaced in tests.
	now func() time.Time
	// dedupTTL is how long cache entries remain valid.
	dedupTTL time.Duration
	// dedupMax is the cap on cached entries.
	dedupMax int

	// sealedRejections counts Begin/CheckSealed rejections while sealed.
	sealedRejections uint64
	// staleCommits counts Commit rejections due to an epoch mismatch.
	staleCommits uint64
	// restoreCompletedAt records when the gate most recently opened.
	restoreCompletedAt time.Time

	// metricSink, when non-nil, receives renew counters and gauges.
	metricSink renewMetrics
}

// renewMetrics is the subset of the metrics sink the gate depends on.
type renewMetrics interface {
	IncrCounterWithLabels(key []string, val float32, labels []metrics.Label)
	SetGaugeWithLabels(key []string, val float32, labels []metrics.Label)
}

// NewRenewGate constructs a RenewGate in the sealed state. The gate starts
// sealed because a freshly constructed Core has not yet unsealed its barrier.
func NewRenewGate(metricSink renewMetrics) *RenewGate {
	return &RenewGate{
		state:      RenewGateSealed,
		inflight:   make(map[uint64]*RenewAttempt),
		dedup:      make(map[renewKey]renewCacheEntry),
		now:        time.Now,
		dedupTTL:   renewDedupTTL,
		dedupMax:   renewDedupMax,
		metricSink: metricSink,
	}
}

// CheckSealed returns consts.ErrSealed when the gate is currently sealed. It is
// a cheap read-side guard used by renewal entry points before any work begins.
func (g *RenewGate) CheckSealed() error {
	if g == nil {
		return ErrRenewGateUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == RenewGateSealed {
		g.sealedRejections++
		g.incrCounter([]string{"expire", "renew", "sealed"})
		return consts.ErrSealed
	}
	return nil
}

// Begin registers a new renewal attempt after validating that the gate is not
// sealed. The req supplies the request ID and caller accessor, leaseID and
// increment describe the renewal, and tokenAccessor identifies the caller. It
// returns ErrRenewGateUnavailable if the gate is nil and consts.ErrSealed if
// the gate is sealed; otherwise it returns a pending attempt that must
// eventually be completed with Commit or Abort. The namespace ID and previous
// expiration time are backfilled on the attempt once the lease entry loads.
func (g *RenewGate) Begin(ctx context.Context, req *logical.Request, leaseID string, increment time.Duration, tokenAccessor string) (*RenewAttempt, error) {
	if g == nil {
		return nil, ErrRenewGateUnavailable
	}

	requestID := ""
	if req != nil {
		requestID = req.ID
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.state == RenewGateSealed {
		g.sealedRejections++
		g.incrCounter([]string{"expire", "renew", "sealed"})
		return nil, consts.ErrSealed
	}

	g.nextAttemptID++
	attempt := &RenewAttempt{
		AttemptID:     g.nextAttemptID,
		LeaseID:       leaseID,
		TokenAccessor: tokenAccessor,
		RequestID:     requestID,
		Epoch:         g.epoch,
		Increment:     increment,
		Started:       g.now(),
		State:         RenewPending,
	}
	g.inflight[attempt.AttemptID] = attempt
	g.setInflightGauge(len(g.inflight))
	g.incrCounter([]string{"expire", "renew", "attempt"})
	return attempt, nil
}

// Commit finalizes a pending attempt, recording the new expiration time and,
// when the attempt is cacheable, storing the response for idempotent retries.
// It returns consts.ErrSealed if the gate is sealed, ErrRenewEpochStale if the
// gate is open but in a newer epoch, and ErrRenewTransition for any attempt not
// in the pending state. A failed commit never mutates pending state, emits no
// lease.renewed event and rolls back nothing already written to the barrier.
func (g *RenewGate) Commit(attempt *RenewAttempt, resp *logical.Response) error {
	if g == nil {
		return ErrRenewGateUnavailable
	}
	if attempt == nil {
		return ErrRenewTransition
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// A sealed gate takes precedence: any attempt being committed after a seal
	// (including one already aborted by the Seal call) reports ErrSealed.
	if g.state == RenewGateSealed {
		g.sealedRejections++
		g.incrCounter([]string{"expire", "renew", "sealed"})
		if attempt.State == RenewPending {
			g.finishAbortedLocked(attempt)
		}
		return consts.ErrSealed
	}

	if attempt.State != RenewPending {
		return ErrRenewTransition
	}

	if attempt.Epoch != g.epoch {
		g.staleCommits++
		g.incrCounter([]string{"expire", "renew", "stale_epoch"})
		g.finishAbortedLocked(attempt)
		return ErrRenewEpochStale
	}

	attempt.State = RenewApplied
	delete(g.inflight, attempt.AttemptID)
	g.setInflightGauge(len(g.inflight))

	if attempt.cacheable && resp != nil {
		g.putDedupLocked(attempt.key, resp)
	}
	return nil
}

// Abort abandons a pending attempt, for example because persistence or the
// logical backend failed. It is safe to call on a nil gate or an attempt that
// has already reached a terminal state, in which case it is a no-op. The
// provided error is only used to classify the abort for callers; it is not
// retained by the gate.
func (g *RenewGate) Abort(attempt *RenewAttempt, err error) {
	if g == nil || attempt == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if attempt.State != RenewPending {
		return
	}
	g.finishAbortedLocked(attempt)
}

// LookupDedup returns a deep copy of a cached renewal response for the given
// key together with whether an entry was found. Expired entries are purged and
// reported as misses. The returned response is independent of the cached value
// so callers may mutate it freely.
func (g *RenewGate) LookupDedup(key renewKey) (*logical.Response, bool) {
	if g == nil {
		return nil, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	entry, ok := g.dedup[key]
	if !ok {
		return nil, false
	}
	if g.now().Sub(entry.writtenAt) > g.dedupTTL {
		delete(g.dedup, key)
		return nil, false
	}
	g.incrCounter([]string{"expire", "renew", "dedup_hit"})
	return cloneResponse(entry.response), true
}

// Seal moves the gate into the sealed state, bumps the epoch and aborts every
// in-flight attempt. It is idempotent: sealing an already sealed gate does not
// bump the epoch again. The idempotency and in-flight maps are cleared so that
// pre-seal results are never served after unseal.
func (g *RenewGate) Seal() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.state == RenewGateSealed {
		return
	}

	g.state = RenewGateSealed
	g.epoch++
	for _, attempt := range g.inflight {
		if attempt.State == RenewPending {
			attempt.State = RenewAborted
		}
	}
	g.inflight = make(map[uint64]*RenewAttempt)
	g.dedup = make(map[renewKey]renewCacheEntry)
	g.setInflightGauge(0)
}

// BeginRestore transitions the gate into the restoring state, bumps the epoch
// and clears the idempotency and in-flight maps. Renewals are permitted while
// the gate is restoring.
func (g *RenewGate) BeginRestore() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	g.epoch++
	g.state = RenewGateRestoring
	g.inflight = make(map[uint64]*RenewAttempt)
	g.dedup = make(map[renewKey]renewCacheEntry)
	g.setInflightGauge(0)
}

// OpenAfterRestore transitions the gate from restoring to open, bumps the
// epoch again, clears the idempotency and in-flight maps and records the
// completion time. It may run while Core is still finishing its unseal work; a
// subsequent seal will move the gate back to sealed.
func (g *RenewGate) OpenAfterRestore() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	g.epoch++
	g.state = RenewGateOpen
	g.inflight = make(map[uint64]*RenewAttempt)
	g.dedup = make(map[renewKey]renewCacheEntry)
	g.setInflightGauge(0)
	g.restoreCompletedAt = g.now()
}

// Snapshot returns a read-only projection of gate state for the renewal
// status endpoint. No identifying lease or token data is included.
func (g *RenewGate) Snapshot() RenewGateSnapshot {
	if g == nil {
		return RenewGateSnapshot{State: RenewGateSealed.String()}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return RenewGateSnapshot{
		State:              g.state.String(),
		Epoch:              g.epoch,
		Inflight:           len(g.inflight),
		SealedRejections:   g.sealedRejections,
		StaleCommits:       g.staleCommits,
		RestoreCompletedAt: g.restoreCompletedAt,
	}
}

// finishAbortedLocked transitions a pending attempt to aborted and removes it
// from the in-flight map. The caller must hold g.mu.
func (g *RenewGate) finishAbortedLocked(attempt *RenewAttempt) {
	attempt.State = RenewAborted
	delete(g.inflight, attempt.AttemptID)
	g.setInflightGauge(len(g.inflight))
}

// putDedupLocked stores a deep-copied response under key and enforces the size
// cap by evicting the oldest entry when the cache is full. The caller must
// hold g.mu.
func (g *RenewGate) putDedupLocked(key renewKey, resp *logical.Response) {
	// Opportunistically drop expired entries first.
	now := g.now()
	for k, entry := range g.dedup {
		if now.Sub(entry.writtenAt) > g.dedupTTL {
			delete(g.dedup, k)
		}
	}

	if len(g.dedup) >= g.dedupMax {
		var oldestKey renewKey
		var oldestAt time.Time
		first := true
		for k, entry := range g.dedup {
			if first || entry.writtenAt.Before(oldestAt) {
				oldestKey = k
				oldestAt = entry.writtenAt
				first = false
			}
		}
		if !first {
			delete(g.dedup, oldestKey)
		}
	}

	g.dedup[key] = renewCacheEntry{
		response:  cloneResponse(resp),
		writtenAt: now,
	}
}

// incrCounter emits a counter metric when a sink is configured.
func (g *RenewGate) incrCounter(key []string) {
	if g.metricSink != nil {
		g.metricSink.IncrCounterWithLabels(key, 1, nil)
	}
}

// setInflightGauge emits the in-flight gauge when a sink is configured.
func (g *RenewGate) setInflightGauge(n int) {
	if g.metricSink != nil {
		g.metricSink.SetGaugeWithLabels([]string{"expire", "renew", "inflight"}, float32(n), nil)
	}
}

// markCacheable associates a de-duplication key with an attempt and enables
// caching of its committed response. Caching is only enabled when the key
// carries a non-empty renewal identifier.
func (a *RenewAttempt) markCacheable(key renewKey) {
	if key.RenewalID == "" {
		a.cacheable = false
		return
	}
	a.key = key
	a.cacheable = true
}

// cloneResponse returns a deep copy of resp covering the Data, Auth, Secret and
// Warnings fields returned to renewal clients. A nil response yields nil.
func cloneResponse(resp *logical.Response) *logical.Response {
	if resp == nil {
		return nil
	}
	clone := &logical.Response{
		Redirect:  resp.Redirect,
		MountType: resp.MountType,
	}
	if resp.Data != nil {
		clone.Data = cloneMap(resp.Data)
	}
	if resp.Warnings != nil {
		clone.Warnings = append([]string(nil), resp.Warnings...)
	}
	if resp.Auth != nil {
		clone.Auth = cloneAuth(resp.Auth)
	}
	if resp.Secret != nil {
		clone.Secret = cloneSecret(resp.Secret)
	}
	return clone
}

// cloneMap performs a shallow copy of a response data map. The values produced
// by renewal responses are treated as opaque payloads and copied by reference
// within the map, matching how Vault already round-trips Data through storage.
func cloneMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// cloneAuth returns a value copy of auth. logical.Auth is a struct without
// reference fields that the renewal path mutates, so a dereference copy is
// sufficient to isolate the cached value.
func cloneAuth(auth *logical.Auth) *logical.Auth {
	if auth == nil {
		return nil
	}
	clone := *auth
	if auth.Policies != nil {
		clone.Policies = append([]string(nil), auth.Policies...)
	}
	if auth.Metadata != nil {
		metadata := make(map[string]string, len(auth.Metadata))
		for k, v := range auth.Metadata {
			metadata[k] = v
		}
		clone.Metadata = metadata
	}
	if auth.GroupAliases != nil {
		clone.GroupAliases = append([]*logical.Alias(nil), auth.GroupAliases...)
	}
	return &clone
}

// cloneSecret returns a value copy of secret. logical.Secret is a struct whose
// InternalData map is copied so the cached secret cannot be mutated through the
// original.
func cloneSecret(secret *logical.Secret) *logical.Secret {
	if secret == nil {
		return nil
	}
	clone := *secret
	if secret.InternalData != nil {
		clone.InternalData = cloneMap(secret.InternalData)
	}
	return &clone
}

// RenewStore abstracts the persistence operations a renewal needs so that
// tests can inject a counting or blocking implementation. The production
// implementation delegates to ExpirationManager.loadEntry and persistEntry.
type RenewStore interface {
	// Load reads a lease entry by ID. It returns a nil entry and nil error when
	// no entry exists.
	Load(ctx context.Context, leaseID string) (*leaseEntry, error)
	// Persist writes a lease entry durably.
	Persist(ctx context.Context, le *leaseEntry) error
}

// expirationStore is the production RenewStore, adapting the expiration
// manager's load and persist helpers.
type expirationStore struct {
	m *ExpirationManager
}

// Load implements RenewStore by delegating to loadEntry.
func (s expirationStore) Load(ctx context.Context, leaseID string) (*leaseEntry, error) {
	return s.m.loadEntry(ctx, leaseID)
}

// Persist implements RenewStore by delegating to persistEntry.
func (s expirationStore) Persist(ctx context.Context, le *leaseEntry) error {
	return s.m.persistEntry(ctx, le)
}

// renewStoreFor returns the configured RenewStore for the manager, falling
// back to the default expirationStore adapter when none has been injected. It
// never returns nil and never panics.
func (m *ExpirationManager) renewStoreFor() RenewStore {
	if m.renewStore != nil {
		return m.renewStore
	}
	return expirationStore{m}
}

// gate returns the Core-mounted RenewGate, or nil if the core reference is not
// available. Callers must tolerate a nil gate via ErrRenewGateUnavailable.
func (m *ExpirationManager) gate() *RenewGate {
	if m == nil || m.core == nil {
		return nil
	}
	return m.core.renewGate
}

// nowForRenew returns the current time according to the gate's clock, falling
// back to the standard library clock when no gate is wired up. All new renewal
// timestamps must flow through here so tests can control time via the gate.
func (g *RenewGate) nowForRenew() time.Time {
	if g == nil || g.now == nil {
		return time.Now()
	}
	return g.now()
}

// renewalIDFromRequest resolves the idempotency key's renewal identifier,
// preferring an explicit renewal_id field and falling back to the request ID.
func renewalIDFromRequest(req *logical.Request) string {
	if req == nil {
		return ""
	}
	if req.Data != nil {
		if raw, ok := req.Data["renewal_id"]; ok {
			if s, ok := raw.(string); ok && s != "" {
				return s
			}
		}
	}
	return req.ID
}

// renewKeyFor builds the de-duplication key for a renewal.
func renewKeyFor(namespaceID, leaseID, renewalID, callerAccessor string) renewKey {
	return renewKey{
		NamespaceID:    namespaceID,
		LeaseID:        leaseID,
		RenewalID:      renewalID,
		CallerAccessor: callerAccessor,
	}
}
