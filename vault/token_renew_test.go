// Copyright IBM Corp. 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/internalshared/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// countingRenewStore is a test RenewStore that counts load/persist calls and
// optionally blocks persistence until a channel is released.
type countingRenewStore struct {
	loadCalls    int64
	persistCalls int64
	mu           sync.Mutex
	blockPersist chan struct{}
	entries      map[string]*leaseEntry
}

func newCountingRenewStore() *countingRenewStore {
	return &countingRenewStore{entries: make(map[string]*leaseEntry)}
}

func (s *countingRenewStore) Load(ctx context.Context, leaseID string) (*leaseEntry, error) {
	atomic.AddInt64(&s.loadCalls, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	le, ok := s.entries[leaseID]
	if !ok {
		return nil, nil
	}
	return le, nil
}

func (s *countingRenewStore) Persist(ctx context.Context, le *leaseEntry) error {
	if s.blockPersist != nil {
		select {
		case <-s.blockPersist:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	atomic.AddInt64(&s.persistCalls, 1)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[le.LeaseID] = le
	return nil
}

func (s *countingRenewStore) loads() int64    { return atomic.LoadInt64(&s.loadCalls) }
func (s *countingRenewStore) persists() int64 { return atomic.LoadInt64(&s.persistCalls) }

// delegatingCountingStore counts Load/Persist invocations while forwarding the
// actual work to another RenewStore, so end-to-end barrier behavior is retained.
type delegatingCountingStore struct {
	inner        RenewStore
	loadCalls    int64
	persistCalls int64
}

func (s *delegatingCountingStore) Load(ctx context.Context, leaseID string) (*leaseEntry, error) {
	atomic.AddInt64(&s.loadCalls, 1)
	return s.inner.Load(ctx, leaseID)
}

func (s *delegatingCountingStore) Persist(ctx context.Context, le *leaseEntry) error {
	atomic.AddInt64(&s.persistCalls, 1)
	return s.inner.Persist(ctx, le)
}

func (s *delegatingCountingStore) persists() int64 { return atomic.LoadInt64(&s.persistCalls) }

// newTestGate builds an open gate with a controllable clock for unit tests.
func newTestGate() (*RenewGate, *time.Time) {
	now := time.Now()
	g := NewRenewGate(nil)
	g.now = func() time.Time { return now }
	g.BeginRestore()
	g.OpenAfterRestore()
	return g, &now
}

// TestRenewGate_Transitions covers the two legal terminal transitions and the
// illegal ones, asserting errors.Is(ErrRenewTransition) and that an illegal
// transition leaves the attempt state untouched.
func TestRenewGate_Transitions(t *testing.T) {
	g, _ := newTestGate()

	attempt, err := g.Begin(context.Background(), &logical.Request{ID: "req-1"}, "lease/1", time.Minute, "accessor")
	require.NoError(t, err)
	require.Equal(t, RenewPending, attempt.State)

	t.Run("legal_commit", func(t *testing.T) {
		a, err := g.Begin(context.Background(), &logical.Request{ID: "req-2"}, "lease/2", time.Minute, "accessor")
		require.NoError(t, err)
		require.NoError(t, g.Commit(a, &logical.Response{}))
		require.Equal(t, RenewApplied, a.State)
	})

	t.Run("legal_abort", func(t *testing.T) {
		a, err := g.Begin(context.Background(), &logical.Request{ID: "req-3"}, "lease/3", time.Minute, "accessor")
		require.NoError(t, err)
		g.Abort(a, errors.New("boom"))
		require.Equal(t, RenewAborted, a.State)
	})

	t.Run("illegal_double_commit", func(t *testing.T) {
		applied, err := g.Begin(context.Background(), &logical.Request{ID: "req-4"}, "lease/4", time.Minute, "accessor")
		require.NoError(t, err)
		require.NoError(t, g.Commit(applied, &logical.Response{}))
		before := applied.State
		err = g.Commit(applied, &logical.Response{})
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrRenewTransition), "expected ErrRenewTransition, got %v", err)
		require.Equal(t, before, applied.State, "illegal transition must not change state")
	})

	t.Run("illegal_abort_then_commit", func(t *testing.T) {
		aborted, err := g.Begin(context.Background(), &logical.Request{ID: "req-5"}, "lease/5", time.Minute, "accessor")
		require.NoError(t, err)
		g.Abort(aborted, nil)
		before := aborted.State
		err = g.Commit(aborted, &logical.Response{})
		require.Error(t, err)
		require.True(t, errors.Is(err, ErrRenewTransition))
		require.Equal(t, before, aborted.State)
	})

	// The original attempt is still pending and can still commit.
	require.NoError(t, g.Commit(attempt, &logical.Response{}))
	require.Equal(t, RenewApplied, attempt.State)
}

// TestRenewGate_SealAbortsInflight verifies sealing aborts in-flight attempts,
// that a subsequent commit returns ErrSealed, the inflight map is drained, and
// a repeated seal does not bump the epoch again.
func TestRenewGate_SealAbortsInflight(t *testing.T) {
	g, _ := newTestGate()

	attempt, err := g.Begin(context.Background(), &logical.Request{ID: "req-seal"}, "lease/seal", time.Minute, "accessor")
	require.NoError(t, err)

	epochBefore := g.Snapshot().Epoch
	g.Seal()

	// Inflight must be empty and the attempt must have been aborted.
	snap := g.Snapshot()
	require.Equal(t, 0, snap.Inflight)
	require.Equal(t, RenewAborted, attempt.State)
	require.Equal(t, RenewGateSealed.String(), snap.State)

	// A commit against the sealed gate must surface ErrSealed.
	err = g.Commit(attempt, &logical.Response{})
	require.True(t, errors.Is(err, consts.ErrSealed), "expected ErrSealed, got %v", err)

	// Repeated seal is idempotent and does not bump the epoch.
	g.Seal()
	require.Equal(t, epochBefore+1, g.Snapshot().Epoch)
}

// TestRenewGate_StaleEpochCommit verifies that an attempt begun in one epoch
// cannot commit after the gate moves to a newer (but still open) epoch. The
// commit returns ErrRenewEpochStale, aborts the attempt and bumps the stale
// commit counter.
func TestRenewGate_StaleEpochCommit(t *testing.T) {
	g, _ := newTestGate()

	attempt, err := g.Begin(context.Background(), &logical.Request{ID: "req-stale"}, "lease/stale", time.Minute, "accessor")
	require.NoError(t, err)

	// A restore boundary bumps the epoch but leaves the gate non-sealed.
	g.BeginRestore()
	g.OpenAfterRestore()

	snap := g.Snapshot()
	require.NotEqual(t, attempt.Epoch, snap.Epoch)
	require.Equal(t, RenewGateOpen.String(), snap.State)

	err = g.Commit(attempt, &logical.Response{})
	require.True(t, errors.Is(err, ErrRenewEpochStale), "expected ErrRenewEpochStale, got %v", err)
	require.Equal(t, RenewAborted, attempt.State)
	require.Equal(t, uint64(1), g.Snapshot().StaleCommits)
	require.Equal(t, 0, g.Snapshot().Inflight)
}

// TestRenewGate_NilSafe verifies a nil gate never panics and reports the
// package-level unavailable error.
func TestRenewGate_NilSafe(t *testing.T) {
	var g *RenewGate
	require.True(t, errors.Is(g.CheckSealed(), ErrRenewGateUnavailable))
	_, err := g.Begin(context.Background(), nil, "x", 0, "")
	require.True(t, errors.Is(err, ErrRenewGateUnavailable))
	require.True(t, errors.Is(g.Commit(&RenewAttempt{}, nil), ErrRenewGateUnavailable))
	g.Abort(&RenewAttempt{}, nil) // must not panic
	g.Seal()
	g.BeginRestore()
	g.OpenAfterRestore()
}

// TestRenewGate_DedupLifecycle verifies cache hits, TTL expiry, eviction and
// clearing on seal/restore, and that cached responses are independent copies.
func TestRenewGate_DedupLifecycle(t *testing.T) {
	g, now := newTestGate()
	g.dedupTTL = time.Minute
	g.dedupMax = 2

	key := renewKey{NamespaceID: "root", LeaseID: "lease/d", RenewalID: "renew-1", CallerAccessor: "acc"}
	resp := &logical.Response{
		Data:     map[string]interface{}{"k": "v"},
		Warnings: []string{"w"},
		Auth:     &logical.Auth{ClientToken: "tok", Metadata: map[string]string{"m": "n"}},
	}

	attempt, err := g.Begin(context.Background(), &logical.Request{ID: "r"}, "lease/d", 0, "acc")
	require.NoError(t, err)
	attempt.markCacheable(key)
	require.NoError(t, g.Commit(attempt, resp))

	cached, ok := g.LookupDedup(key)
	require.True(t, ok)
	require.Equal(t, "v", cached.Data["k"])

	// Mutating the returned response must not affect the cache.
	cached.Data["k"] = "changed"
	cached.Auth.ClientToken = "changed"
	again, ok := g.LookupDedup(key)
	require.True(t, ok)
	require.Equal(t, "v", again.Data["k"])
	require.Equal(t, "tok", again.Auth.ClientToken)

	// TTL expiry.
	*now = now.Add(g.dedupTTL + time.Second)
	_, ok = g.LookupDedup(key)
	require.False(t, ok)

	// Size cap evicts the oldest entry.
	for i := 0; i < 3; i++ {
		*now = now.Add(time.Second)
		k := renewKey{NamespaceID: "root", LeaseID: fmt.Sprintf("lease/%d", i), RenewalID: fmt.Sprintf("r%d", i), CallerAccessor: "acc"}
		a, err := g.Begin(context.Background(), &logical.Request{}, k.LeaseID, 0, "acc")
		require.NoError(t, err)
		a.markCacheable(k)
		require.NoError(t, g.Commit(a, &logical.Response{}))
	}
	require.LessOrEqual(t, len(g.dedup), 2)

	// Seal clears the cache so pre-seal results cannot be served after.
	g.Seal()
	require.Equal(t, 0, len(g.dedup))
}

// TestRenewGate_KeyIsolation verifies that identical lease IDs and renewal
// IDs in different namespaces or from different callers never share a cached
// response.
func TestRenewGate_KeyIsolation(t *testing.T) {
	g, _ := newTestGate()

	base := renewKey{LeaseID: "lease/x", RenewalID: "rid", NamespaceID: "ns-a", CallerAccessor: "acc-1"}
	otherNS := renewKey{LeaseID: "lease/x", RenewalID: "rid", NamespaceID: "ns-b", CallerAccessor: "acc-1"}
	otherCaller := renewKey{LeaseID: "lease/x", RenewalID: "rid", NamespaceID: "ns-a", CallerAccessor: "acc-2"}

	a, err := g.Begin(context.Background(), &logical.Request{}, "lease/x", 0, "acc-1")
	require.NoError(t, err)
	a.markCacheable(base)
	require.NoError(t, g.Commit(a, &logical.Response{Data: map[string]interface{}{"who": "a"}}))

	for _, key := range []renewKey{otherNS, otherCaller} {
		_, ok := g.LookupDedup(key)
		require.False(t, ok, "key %+v must not collide with %+v", key, base)
	}
	if cached, ok := g.LookupDedup(base); !ok || cached.Data["who"] != "a" {
		t.Fatalf("original key must still hit, ok=%v", ok)
	}
}

// TestRenewToken_SealedNoWrite verifies that after sealing, RenewToken returns
// ErrSealed without invoking the store at all and leaves pending untouched.
func TestRenewToken_SealedNoWrite(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	exp := core.expiration

	store := newCountingRenewStore()
	exp.renewStore = store

	require.NoError(t, TestCoreSeal(core))

	te := &logical.TokenEntry{
		ID:          "doesnotmatter",
		Path:        "auth/token/login",
		NamespaceID: namespace.RootNamespaceID,
	}
	_, err := exp.RenewToken(namespace.RootContext(nil), &logical.Request{}, te, 0)
	require.True(t, errors.Is(err, consts.ErrSealed), "expected ErrSealed, got %v", err)
	require.Equal(t, int64(0), store.loads())
	require.Equal(t, int64(0), store.persists())
	require.Equal(t, 0, exp.leaseCount)
}

// TestRenewToken_CanceledBeforePersist verifies that a request context
// canceled before any durable work aborts the attempt without writing to the
// barrier.
func TestRenewToken_CanceledBeforePersist(t *testing.T) {
	exp := mockExpiration(t)
	root, err := exp.tokenStore.rootToken(context.Background())
	require.NoError(t, err)

	auth := &logical.Auth{
		ClientToken: root.ID,
		LeaseOptions: logical.LeaseOptions{
			TTL:       time.Hour,
			Renewable: true,
		},
	}
	te := &logical.TokenEntry{ID: root.ID, Path: "auth/token/login", NamespaceID: namespace.RootNamespaceID}
	require.NoError(t, exp.RegisterAuth(namespace.RootContext(nil), te, auth, ""))

	store := newCountingRenewStore()
	exp.renewStore = store

	ctx, cancel := context.WithCancel(namespace.RootContext(nil))
	cancel()

	_, err = exp.RenewToken(ctx, &logical.Request{}, te, 0)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, int64(0), store.persists(), "a canceled request must not persist")

	// The attempt must have been removed from the in-flight map.
	require.Equal(t, 0, exp.core.renewGate.Snapshot().Inflight)
}

// TestRenewAccessor_ThreadsRenewalID verifies the renew-accessor handler
// propagates an explicit renewal_id through its synthetic FieldData into the
// request, so the idempotency cache is keyed on it.
func TestRenewAccessor_ThreadsRenewalID(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	ts := core.tokenStore

	ent := &logical.TokenEntry{
		Path:        "auth/token/create",
		Policies:    []string{"root"},
		TTL:         time.Hour,
		NamespaceID: namespace.RootNamespaceID,
	}
	require.NoError(t, ts.create(namespace.RootContext(nil), ent))

	// Register a renewable lease for the token so renewal can load it.
	auth := &logical.Auth{
		ClientToken: ent.ID,
		LeaseOptions: logical.LeaseOptions{
			TTL:       time.Hour,
			Renewable: true,
		},
	}
	require.NoError(t, core.expiration.RegisterAuth(namespace.RootContext(nil), ent, auth, ""))

	data := &framework.FieldData{
		Raw: map[string]interface{}{
			"accessor":   ent.Accessor,
			"renewal_id": "accessor-renewal-key",
		},
		Schema: map[string]*framework.FieldSchema{
			"accessor":   {Type: framework.TypeString},
			"renewal_id": {Type: framework.TypeString},
			"increment":  {Type: framework.TypeDurationSecond, Default: 0},
		},
	}
	resp, err := ts.handleUpdateRenewAccessor(namespace.RootContext(nil), &logical.Request{}, data)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Empty(t, resp.Auth.ClientToken, "accessor renewal must not return the token")

	// The cache should contain an entry keyed by the supplied renewal id.
	found := false
	for key := range core.renewGate.DedupForTest() {
		if key.RenewalID == "accessor-renewal-key" {
			found = true
			break
		}
	}
	require.True(t, found, "renew-accessor must populate the dedup cache with the renewal_id")
}

// TestRenewToken_UsesGateClock verifies that when the gate clock is faked, the
// renewed lease's LastRenewalTime follows the fake clock rather than wall
// clock, proving renewal timestamps are sourced from the gate.
func TestRenewToken_UsesGateClock(t *testing.T) {
	exp := mockExpiration(t)

	// Install a controllable clock on the gate.
	fake := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	exp.core.renewGate.mu.Lock()
	exp.core.renewGate.now = func() time.Time { return fake }
	exp.core.renewGate.mu.Unlock()

	root, err := exp.tokenStore.rootToken(context.Background())
	require.NoError(t, err)
	auth := &logical.Auth{
		ClientToken: root.ID,
		LeaseOptions: logical.LeaseOptions{
			TTL:       time.Hour,
			Renewable: true,
		},
	}
	te := &logical.TokenEntry{ID: root.ID, Path: "auth/token/login", NamespaceID: namespace.RootNamespaceID}
	require.NoError(t, exp.RegisterAuth(namespace.RootContext(nil), te, auth, ""))

	_, err = exp.RenewToken(namespace.RootContext(nil), &logical.Request{}, te, 0)
	require.NoError(t, err)

	le, err := exp.FetchLeaseTimesByToken(namespace.RootContext(nil), te)
	require.NoError(t, err)
	require.True(t, le.LastRenewalTime.Equal(fake), "LastRenewalTime %v must follow fake clock %v", le.LastRenewalTime, fake)
}

// TestRenewToken_RestoreStaleTimer verifies the monotonic restore guarantee: a
// stale snapshot cannot shorten an already-extended lease, while a normal
// updatePending remains authoritative and may shorten the TTL.
func TestRenewToken_RestoreStaleTimer(t *testing.T) {
	exp := mockExpiration(t)
	leaseID := "lease/monotonic"
	ns := namespace.RootNamespace

	base := time.Now()
	later := base.Add(time.Hour)
	earlier := base.Add(time.Minute)

	extended := &leaseEntry{
		LeaseID:    leaseID,
		namespace:  ns,
		ExpireTime: later,
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{Renewable: true},
		},
	}

	// Authoritative renewal writes the later expiration.
	exp.updatePending(extended)
	infoRaw, ok := exp.pending.Load(leaseID)
	require.True(t, ok)
	cached := infoRaw.(pendingInfo).cachedLeaseInfo
	require.Equal(t, later, cached.ExpireTime)
	originalTimer := infoRaw.(pendingInfo).timer

	// A stale restore snapshot with an earlier expiration must be ignored.
	stale := &leaseEntry{
		LeaseID:    leaseID,
		namespace:  ns,
		ExpireTime: earlier,
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{Renewable: true},
		},
	}
	exp.updatePendingRestore(stale)
	infoRaw, ok = exp.pending.Load(leaseID)
	require.True(t, ok)
	require.Equal(t, later, infoRaw.(pendingInfo).cachedLeaseInfo.ExpireTime)
	require.Equal(t, originalTimer, infoRaw.(pendingInfo).timer, "timer must be retained")

	// A normal updatePending may shorten the TTL to match the backend.
	shorter := &leaseEntry{
		LeaseID:    leaseID,
		namespace:  ns,
		ExpireTime: earlier,
		Secret: &logical.Secret{
			LeaseOptions: logical.LeaseOptions{Renewable: true},
		},
	}
	exp.updatePending(shorter)
	infoRaw, ok = exp.pending.Load(leaseID)
	require.True(t, ok)
	require.Equal(t, earlier, infoRaw.(pendingInfo).cachedLeaseInfo.ExpireTime)
}

// TestRenewToken_PeriodicExplicitMax verifies periodic tokens are capped by the
// period regardless of increment, and explicit-max-TTL tokens stop at
// IssueTime + ExplicitMaxTTL.
func TestRenewToken_PeriodicExplicitMax(t *testing.T) {
	exp := mockExpiration(t)

	t.Run("periodic_capped_by_period", func(t *testing.T) {
		root := &logical.TokenEntry{
			Policies:     []string{"root"},
			Path:         "auth/token/root",
			DisplayName:  "root-periodic",
			CreationTime: time.Now().Unix(),
			Period:       time.Minute,
			NamespaceID:  namespace.RootNamespaceID,
		}
		require.NoError(t, exp.tokenStore.create(namespace.RootContext(nil), root))

		auth := &logical.Auth{
			ClientToken: root.ID,
			LeaseOptions: logical.LeaseOptions{
				TTL:       time.Hour,
				Renewable: true,
			},
			Period: time.Minute,
		}
		te := &logical.TokenEntry{ID: root.ID, Path: "auth/token/login", NamespaceID: namespace.RootNamespaceID}
		require.NoError(t, exp.RegisterAuth(namespace.RootContext(nil), te, auth, ""))

		for _, inc := range []time.Duration{0, time.Minute, time.Hour} {
			out, err := exp.RenewToken(namespace.RootContext(nil), &logical.Request{}, te, inc)
			require.NoError(t, err)
			require.LessOrEqual(t, int64(out.Auth.TTL), int64(time.Minute))
		}
	})

	t.Run("explicit_max_ttl_ceiling", func(t *testing.T) {
		root, err := exp.tokenStore.rootToken(context.Background())
		require.NoError(t, err)

		explicitMax := 30 * time.Second
		auth := &logical.Auth{
			ClientToken: root.ID,
			LeaseOptions: logical.LeaseOptions{
				TTL:       10 * time.Second,
				Renewable: true,
			},
			ExplicitMaxTTL: explicitMax,
		}
		te := &logical.TokenEntry{ID: root.ID, Path: "auth/token/login", NamespaceID: namespace.RootNamespaceID}
		require.NoError(t, exp.RegisterAuth(namespace.RootContext(nil), te, auth, ""))

		var lastExpiry time.Time
		for i := 0; i < 5; i++ {
			out, err := exp.RenewToken(namespace.RootContext(nil), &logical.Request{}, te, 10*time.Second)
			if err != nil {
				// Reaching the explicit max may surface as a non-renewable error;
				// either way, the ceiling must never be crossed.
				break
			}
			require.NotNil(t, out.Auth)
			le, lerr := exp.FetchLeaseTimesByToken(namespace.RootContext(nil), te)
			require.NoError(t, lerr)
			lastExpiry = le.ExpireTime
			require.LessOrEqual(t, le.ExpireTime.Sub(le.IssueTime), explicitMax+time.Second)
			time.Sleep(5 * time.Millisecond)
		}
		require.False(t, lastExpiry.IsZero())
	})
}

// TestRenew_DedupAndConcurrent verifies that 32 concurrent renewals with the
// same renewal_id result in a single persistence, that 16 distinct ids run
// without races and the final expiration equals the last successful renewal.
func TestRenew_DedupAndConcurrent(t *testing.T) {
	exp := mockExpiration(t)
	ctx := namespace.RootContext(nil)

	noop := &NoopBackend{}
	_, barrier, _ := mockBarrier(t)
	view := NewBarrierView(barrier, "logical/")
	meUUID, err := uuid.GenerateUUID()
	require.NoError(t, err)
	require.NoError(t, exp.router.Mount(noop, "prod/aws/", &MountEntry{Path: "prod/aws/", Type: "noop", UUID: meUUID, Accessor: "noop-accessor-dedup", namespace: namespace.RootNamespace}, view))

	registerReq := &logical.Request{Operation: logical.ReadOperation, Path: "prod/aws/foo", ClientToken: "foobar"}
	registerReq.SetTokenEntry(&logical.TokenEntry{ID: "foobar", NamespaceID: "root"})
	registerResp := &logical.Response{
		Secret: &logical.Secret{LeaseOptions: logical.LeaseOptions{TTL: time.Hour, Renewable: true}},
		Data:   map[string]interface{}{"access_key": "xyz"},
	}
	leaseID, err := exp.Register(ctx, registerReq, registerResp, "")
	require.NoError(t, err)

	noop.Response = &logical.Response{
		Secret: &logical.Secret{LeaseOptions: logical.LeaseOptions{TTL: time.Hour, Renewable: true}},
		Data:   map[string]interface{}{"access_key": "renewed"},
	}

	// Wrap the default store with a counting delegate to assert persistence counts.
	counting := &delegatingCountingStore{inner: expirationStore{exp}}
	exp.renewStore = counting

	t.Run("same_renewal_id_single_persist", func(t *testing.T) {
		before := counting.persists()
		const n = 32
		var wg sync.WaitGroup
		results := make([]*logical.Response, n)
		errs := make([]error, n)
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				defer wg.Done()
				req := &logical.Request{ID: "shared-req", Data: map[string]interface{}{"renewal_id": "same-renewal"}}
				results[idx], errs[idx] = exp.RenewWithRequest(ctx, req, leaseID, 0)
			}(i)
		}
		wg.Wait()
		for i := 0; i < n; i++ {
			require.NoError(t, errs[i])
			require.NotNil(t, results[i])
			require.Equal(t, "renewed", results[i].Data["access_key"])
		}
		// Exactly one entry should be cached and all others served from it.
		require.Equal(t, 1, len(exp.core.renewGate.dedup))
		// Only a single persistence may occur for 32 identical retries.
		require.Equal(t, int64(1), counting.persists()-before, "expected exactly one persistEntry for identical renewal_id retries")
	})

	t.Run("distinct_renewal_ids_serialized", func(t *testing.T) {
		const n = 16
		var wg sync.WaitGroup
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				defer wg.Done()
				req := &logical.Request{ID: fmt.Sprintf("req-%d", idx), Data: map[string]interface{}{"renewal_id": fmt.Sprintf("renew-%d", idx)}}
				_, _ = exp.RenewWithRequest(ctx, req, leaseID, 0)
			}(i)
		}
		wg.Wait()

		le, err := exp.loadEntry(ctx, leaseID)
		require.NoError(t, err)
		require.NotNil(t, le)
		// The pending timer must reflect the final stored expiration. Compare
		// instants (not monotonic readings), since the stored and in-memory
		// clocks produce different monotonic offsets.
		infoRaw, ok := exp.pending.Load(leaseID)
		require.True(t, ok)
		require.True(t, le.ExpireTime.Equal(infoRaw.(pendingInfo).cachedLeaseInfo.ExpireTime),
			"pending expiration %v must equal stored expiration %v", infoRaw.(pendingInfo).cachedLeaseInfo.ExpireTime, le.ExpireTime)
	})
}

// TestRenewStatus_Sudo verifies the endpoint response shape and that it never
// includes identifying material. The sudo/root enforcement is asserted at the
// HTTP layer in TestRenewStatus_HTTP; here we validate the handler projection.
func TestRenewStatus_Sudo(t *testing.T) {
	core, _, _ := TestCoreUnsealed(t)
	b := core.systemBackend

	// Wait for restore to complete and the gate to open.
	deadline := time.Now().Add(10 * time.Second)
	for core.renewGate.Snapshot().State != RenewGateOpen.String() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	resp, err := b.handleRenewalStatus(context.Background(), &logical.Request{}, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	expected := []string{"state", "epoch", "inflight", "sealed_rejections", "stale_commits", "restore_completed_at"}
	for _, key := range expected {
		_, ok := resp.Data[key]
		require.True(t, ok, "missing field %s", key)
	}
	require.Equal(t, RenewGateOpen.String(), resp.Data["state"])

	// No identifying material may appear anywhere in the response.
	for k, v := range resp.Data {
		switch val := v.(type) {
		case string:
			require.NotContains(t, val, "token", "field %s leaks identifier", k)
		}
	}
}

// TestRenew_ExpiredDuringSeal verifies a lease whose expiration is in the past
// is removed from pending after a seal/unseal restore cycle and renewal reports
// the lease as expired.
func TestRenew_ExpiredDuringSeal(t *testing.T) {
	core, keys, root := TestCoreUnsealed(t)
	exp := core.expiration

	// Register a renewable token lease.
	te := &logical.TokenEntry{ID: root, Path: "auth/token/login", NamespaceID: namespace.RootNamespaceID}
	auth := &logical.Auth{
		ClientToken: root,
		LeaseOptions: logical.LeaseOptions{
			TTL:       time.Hour,
			Renewable: true,
		},
	}
	require.NoError(t, exp.RegisterAuth(namespace.RootContext(nil), te, auth, ""))

	saltedID, err := exp.tokenStore.SaltID(namespace.RootContext(nil), root)
	require.NoError(t, err)
	leaseID := pathJoinForTest(te.Path, saltedID)

	le, err := exp.loadEntry(namespace.RootContext(nil), leaseID)
	require.NoError(t, err)
	require.NotNil(t, le)

	// Force the stored lease into the past, then seal and unseal so restore
	// observes the already-expired lease.
	le.ExpireTime = time.Now().Add(-time.Hour)
	require.NoError(t, exp.persistEntry(namespace.RootContext(nil), le))

	require.NoError(t, TestCoreSeal(core))

	// Re-unseal the same core using the existing key shares.
	for _, key := range keys {
		unsealed, err := TestCoreUnseal(core, key)
		require.NoError(t, err)
		if unsealed {
			break
		}
	}
	require.False(t, core.Sealed())

	// The expiration manager is recreated on unseal.
	newExp := core.expiration
	require.NotNil(t, newExp)

	// Wait for the new expiration manager to finish restoring.
	deadline := time.Now().Add(15 * time.Second)
	for newExp.inRestoreMode() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	// Allow the expiration timer to fire for the back-dated lease.
	require.Eventually(t, func() bool {
		_, ok := newExp.pending.Load(leaseID)
		return !ok
	}, 10*time.Second, 50*time.Millisecond, "expired lease should be removed from pending after restore")

	// Renewal must now report the lease as expired.
	_, err = newExp.RenewToken(namespace.RootContext(nil), &logical.Request{}, te, 0)
	require.Error(t, err)
}

// pathJoinForTest mirrors the lease ID construction used by RenewToken.
func pathJoinForTest(parts ...string) string {
	return path.Join(parts...)
}
