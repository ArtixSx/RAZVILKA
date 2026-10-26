package app

import (
	"context"
	"errors"
	"log"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/auditlog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// The router's NDM rewrites a whole netfilter table after many of its own
// events and so drops the owned first-start NFQWS2 mangle graph while the
// stock process keeps running. This round re-creates only that graph for the
// plan already applied. It never chooses or changes a route, consumes drafts,
// starts, stops or restarts a component, and never waits for a busy gate.
// Its limits and audit deduplication live in memory only: the reconciler
// journal keeps exactly its five operation kinds.
const (
	nfqws2HookRoundTimeout   = 70 * time.Second // observation 20 s + restoration 45 s
	nfqws2HookRetryBase      = 30 * time.Second
	nfqws2HookRetryMax       = 30 * time.Minute
	nfqws2HookReviewRetry    = 30 * time.Minute
	nfqws2HookQuickLoss      = time.Minute
	nfqws2HookQuickLossLimit = 3
	// A firmware rewrite racing one attempt is retried at the base delay;
	// only a persistent race grows the backoff and is audited.
	nfqws2HookChangedLimit = 3
)

// Fixed application codes beside the dataplane's own refusal vocabulary.
const (
	nfqws2HookReasonRepeated  = "repeated-loss"
	nfqws2HookReasonUncertain = "cleanup-uncertain"
	nfqws2HookReasonTimeout   = "timeout"
	nfqws2HookReasonFailed    = "failed"
)

var errNFQWS2HookAuthority = errors.Join(dataplane.ErrReviewChanged, errors.New("applied NFQWS2 hook repair authority changed"))

// nfqws2HookBudget is the memory-only schedule of one key K = (PlanID,
// Digest, lease transaction, running receipt). A new key starts over.
type nfqws2HookBudget struct {
	key      string
	failures int       // consecutive failures since the last success
	changed  int       // consecutive kernel-changed refusals
	next     time.Time // no admission before this time
	review   bool      // requires review; retried at the slow review pace
	restored time.Time // last success, consumed by the next observed loss
	quick    int       // consecutive losses within a minute of a success
	audited  map[string]bool
}

type nfqws2HookRecoveryState struct {
	mu     sync.Mutex
	budget nfqws2HookBudget
	// Deterministic models of the two Manager entry points for tests;
	// production leaves them nil and binds the Manager.
	observe, restore func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error)
}

func (b *nfqws2HookBudget) bind(key string) {
	if b.key != key {
		*b = nfqws2HookBudget{key: key}
	}
}

// observed accounts one observation of a graph that is not FULL. It reports
// whether an attempt may take admission now and a review code to audit.
func (b *nfqws2HookBudget) observed(class string, now time.Time) (bool, string) {
	reason := ""
	if class == dataplane.NFQWS2HooksLoss && !b.restored.IsZero() {
		if now.Sub(b.restored) < nfqws2HookQuickLoss {
			b.quick++
		} else {
			b.quick = 0
		}
		b.restored = time.Time{}
		if b.quick >= nfqws2HookQuickLossLimit && !b.review {
			b.review, b.next, reason = true, now.Add(nfqws2HookReviewRetry), nfqws2HookReasonRepeated
		}
	}
	return !now.Before(b.next), reason
}

// settle records one attempt. It reports a success and a failure code that
// the caller audits; busy, cancelled or superseded authority is not counted.
func (b *nfqws2HookBudget) settle(result dataplane.NFQWS2HookRestore, err error, now time.Time) (bool, string) {
	switch {
	case err == nil && len(result.Restored) != 0:
		*b = nfqws2HookBudget{key: b.key, restored: now, quick: b.quick}
		return true, ""
	case err == nil, errors.Is(err, dataplane.ErrNFQWS2HookBusy):
		return false, ""
	case result.Uncertain || errors.Is(err, dataplane.ErrNFQWS2HookUncertain):
		b.changed, b.review, b.next = 0, true, now.Add(nfqws2HookReviewRetry)
		return false, nfqws2HookReasonUncertain
	case errors.Is(err, context.DeadlineExceeded):
		b.changed = 0
		return false, b.fail(nfqws2HookReasonTimeout, now)
	case errors.Is(err, context.Canceled) || slices.Contains([]string{dataplane.NFQWS2HookReasonGuard, dataplane.NFQWS2HookReasonPlan, dataplane.NFQWS2HookReasonContext, dataplane.NFQWS2HookReasonOwner, dataplane.NFQWS2HookReasonLease}, result.Reason):
		// Stop, a user operation or a new plan owns the router now; the
		// next round observes again under that new authority.
		return false, ""
	case result.Reason == dataplane.NFQWS2HookReasonChanged:
		if b.changed = min(b.changed+1, nfqws2HookChangedLimit); b.changed < nfqws2HookChangedLimit {
			b.next = now.Add(nfqws2HookRetryBase)
			if b.review {
				b.next = now.Add(nfqws2HookReviewRetry)
			}
			return false, ""
		}
		return false, b.fail(dataplane.NFQWS2HookReasonChanged, now)
	}
	b.changed = 0
	return false, b.fail(nfqws2HookAuditReason(result.Reason), now)
}

func (b *nfqws2HookBudget) fail(reason string, now time.Time) string {
	b.failures = min(b.failures+1, 32)
	delay := nfqws2HookRetryMax
	if b.failures <= 6 {
		delay = min(nfqws2HookRetryBase<<(b.failures-1), nfqws2HookRetryMax)
	}
	if b.review {
		delay = nfqws2HookReviewRetry
	}
	b.next = now.Add(delay)
	return reason
}

// once passes a code through only the first time for this key, so one
// refusal is audited once per (key, reason); a success clears the record.
func (b *nfqws2HookBudget) once(reason string) string {
	if reason == "" || b.audited[reason] {
		return ""
	}
	if b.audited == nil {
		b.audited = map[string]bool{}
	}
	b.audited[reason] = true
	return reason
}

// Only fixed lowercase codes reach the audit path.
func nfqws2HookAuditReason(reason string) string {
	if reason == "" || len(reason) > 32 || strings.Trim(reason, "abcdefghijklmnopqrstuvwxyz-") != "" {
		return nfqws2HookReasonFailed
	}
	return reason
}

func nfqws2HookKey(plan dataplane.Plan, instance string) string {
	return plan.PlanID + "/" + plan.Digest + "/" + instance
}

// nfqws2HookAppliedPlan admits only the committed plan of the applied
// revision whose NFQWS2 runs without a LAN owner (first start).
func nfqws2HookAppliedPlan(cfg config.Config, plan dataplane.Plan) bool {
	return plan.State == "committed" && plan.Ready && !plan.Noop && !plan.SafeMode && plan.Revision == cfg.AppliedRevision &&
		plan.LAN == nil && slices.Contains(plan.Adapters, "nfqws2") && len(plan.Routes) != 0
}

// Component and application update states are read once per admission: a
// component update cannot start while this repair holds exclusive admission,
// and a self-update Stop written outside the gate is rechecked by the guard.
func (a *App) nfqws2HookSuspended(ctx context.Context, cfg config.Config) bool {
	return cfg.SafeMode || cfg.ServiceControl.Stopped || a.PendingComponentRecovery() || a.PendingSelfUpdateRecovery() ||
		a.SelfUpdate != nil && a.SelfUpdate.InstallationLocked() || a.SelfUpdateFiles.controlAuthority(ctx, true) != nil
}

// nfqws2HookGuard re-proves the caller's authority before and after every
// effect: the same live exclusive admission (never fenced), the applied
// intent admitted with cfg, no due Stop and no self-update Stop.
func (a *App) nfqws2HookGuard(cfg config.Config) func(context.Context) error {
	return func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.Operations.WithExclusiveContext(ctx, func() error { return nil }); err != nil {
			return err
		}
		current := a.Store.Get()
		if current.SafeMode || current.ServiceControl.Stopped || current.AppliedRevision != cfg.AppliedRevision || !reflect.DeepEqual(current.AppliedServices, cfg.AppliedServices) || a.hasDueRuntimeStop(time.Now()) {
			return errNFQWS2HookAuthority
		}
		return a.SelfUpdateFiles.controlAuthority(ctx, true)
	}
}

func (a *App) nfqws2HookRuntime() (observe, restore func(context.Context, dataplane.Plan) (dataplane.NFQWS2HookRestore, error)) {
	a.nfqws2Hooks.mu.Lock()
	observe, restore = a.nfqws2Hooks.observe, a.nfqws2Hooks.restore
	a.nfqws2Hooks.mu.Unlock()
	if observe == nil {
		observe = a.Dataplane.ObserveCommittedNFQWS2Hooks
	}
	if restore == nil {
		restore = a.Dataplane.RestoreCommittedNFQWS2Hooks
	}
	return observe, restore
}

// restoreNFQWS2HooksRound runs inside the reconciler's node-recovery task,
// also while Autopilot is paused or in manual mode: it maintains the route
// already applied and never selects one. A cheap shared observation comes
// first; only a graph that is not FULL takes exclusive admission, and the
// dataplane then repeats its whole admission and fresh kernel reads.
func (a *App) restoreNFQWS2HooksRound(ctx context.Context, now time.Time) error {
	if a.Store == nil || a.Dataplane == nil || ctx == nil || a.hasDueRuntimeStop(now) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, nfqws2HookRoundTimeout)
	defer cancel()
	cfg := a.Store.Get()
	if a.nfqws2HookSuspended(ctx, cfg) {
		return nil
	}
	plan, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || !nfqws2HookAppliedPlan(cfg, plan) {
		return err
	}
	observe, restore := a.nfqws2HookRuntime()
	release, err := a.Operations.Enter(ctx)
	if err != nil {
		return nil // A user operation wins; the next round observes again.
	}
	observed, err := observe(ctx, plan)
	release()
	if err != nil {
		// An unknown graph is neither a loss nor a refusal to report.
		return err
	}
	key := nfqws2HookKey(plan, observed.Instance)
	s := &a.nfqws2Hooks
	s.mu.Lock()
	s.budget.bind(key)
	if observed.Class == dataplane.NFQWS2HooksFull {
		s.mu.Unlock()
		return nil
	}
	attempt, review := s.budget.observed(observed.Class, now)
	review = s.budget.once(review)
	s.mu.Unlock()
	a.auditNFQWS2Hooks(review, 0)
	if !attempt {
		return nil
	}
	admitted, releaseExclusive, err := a.Operations.ExclusiveContext(ctx)
	if err != nil {
		return nil // Busy: a user operation wins. Fenced: journal review owns admission.
	}
	defer releaseExclusive()
	cfg = a.Store.Get()
	if a.nfqws2HookSuspended(admitted, cfg) || a.hasDueRuntimeStop(time.Now()) {
		return nil
	}
	current, exists, err := a.Dataplane.Committed()
	if err != nil || !exists || !reflect.DeepEqual(current, plan) || !nfqws2HookAppliedPlan(cfg, current) {
		return err
	}
	started := time.Now()
	result, err := restore(dataplane.WithReviewGuard(admitted, a.nfqws2HookGuard(cfg)), plan)
	if result.Instance != "" {
		key = nfqws2HookKey(plan, result.Instance)
	}
	s.mu.Lock()
	s.budget.bind(key)
	restored, reason := s.budget.settle(result, err, now)
	reason = s.budget.once(reason)
	s.mu.Unlock()
	if restored {
		log.Printf("NFQWS2 owned hooks restored families=%v", result.Restored)
		if a.Audit != nil {
			_ = a.Audit.Append(auditlog.Event{Action: "RESTORE", Path: "/runtime/nfqws2", Outcome: "ok", Actor: "router", RemoteIP: "local", DurationMS: time.Since(started).Milliseconds()})
		}
	}
	a.auditNFQWS2Hooks(reason, time.Since(started))
	return err
}

// auditNFQWS2Hooks records one refused or failed repair under its fixed code.
func (a *App) auditNFQWS2Hooks(reason string, duration time.Duration) {
	if reason == "" {
		return
	}
	log.Printf("NFQWS2 owned hooks were not restored reason=%s", reason)
	if a.Audit != nil {
		_ = a.Audit.Append(auditlog.Event{Action: "RESTORE", Path: "/runtime/nfqws2/" + reason, Outcome: "failed", Actor: "router", RemoteIP: "local", DurationMS: duration.Milliseconds()})
	}
}
