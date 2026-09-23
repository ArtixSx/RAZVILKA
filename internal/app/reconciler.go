package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const reconcilerOwner = "razvilka-service-reconciler-v1"
const maxReconcilerBytes = 256 << 10

// The journal stores bounded references and scheduling intent, never credentials,
// endpoints, probe bodies or authority to replay an old transaction.
type automationOperation struct {
	ID                 uint64            `json:"id"`
	Kind               string            `json:"kind"`
	State              string            `json:"state"`
	Reason             string            `json:"reason"`
	ConfigGeneration   uint64            `json:"config_generation"`
	ConfigFingerprint  string            `json:"config_fingerprint"`
	PolicyRevisions    map[string]uint64 `json:"policy_revisions"`
	NodeGeneration     uint64            `json:"node_generation"`
	NetworkFingerprint string            `json:"network_fingerprint,omitempty"`
	Deadline           time.Time         `json:"deadline"`
	Attempts           int               `json:"attempts"`
	NextRun            time.Time         `json:"next_run"`
}
type fallbackCheckpoint struct {
	Status         nodeAutofallbackService `json:"status"`
	Key            string                  `json:"key"`
	Cursor         int                     `json:"cursor"`
	LastSwitched   time.Time               `json:"last_switched"`
	SwitchAttempts []time.Time             `json:"switch_attempts"`
}
type reconcilerDocument struct {
	Schema      int                           `json:"schema"`
	Owner       string                        `json:"owner"`
	Sequence    uint64                        `json:"sequence"`
	Operations  []automationOperation         `json:"operations"`
	Fallback    map[string]fallbackCheckpoint `json:"fallback"`
	ManualUntil time.Time                     `json:"manual_until"`
	Jobs        []durableServiceJob           `json:"jobs,omitempty"`
}
type serviceReconciler struct {
	mu           sync.Mutex
	once         sync.Once
	doc          reconcilerDocument
	image        restorejournal.Image
	path         string
	started      bool
	blocked      bool
	cancel       context.CancelFunc
	activeJobID  uint64
	durableBurst int
	dnsResults   map[uint64]json.RawMessage // Bounded diagnostics, never persisted/replayed proof.
	stop         context.CancelFunc
	wake         chan struct{}
	done         chan struct{}
}

func automationConfigFingerprint(cfg config.Config) string {
	data, _ := json.Marshal(cfg)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (a *App) reconcilerSnapshot() map[string]any {
	a.reconciler.mu.Lock()
	defer a.reconciler.mu.Unlock()
	state := "stopped"
	if a.reconciler.started {
		state = "running"
	}
	if a.reconciler.blocked {
		state = "blocked"
	}
	ops := append([]automationOperation{}, a.reconciler.doc.Operations...)
	return map[string]any{"state": state, "operations": ops, "manual_until": a.reconciler.doc.ManualUntil, "persistent": a.reconciler.path != "", "note": "Очередь использует существующие проверки и транзакции. Незавершённое действие после запуска оценивается заново."}
}

func (a *App) wakeReconciler() {
	a.reconciler.mu.Lock()
	for i := range a.reconciler.doc.Operations {
		if a.reconciler.doc.Operations[i].Kind == "node-recovery" || a.reconciler.doc.Operations[i].Kind == "node-fallback" || a.reconciler.doc.Operations[i].Kind == "service-checks" || a.reconciler.doc.Operations[i].Kind == "feeds" {
			a.reconciler.doc.Operations[i].NextRun = time.Time{}
		}
		if a.reconciler.doc.Operations[i].Kind == "node-recovery" && a.reconciler.doc.Operations[i].State != "running" {
			// This wakes observation only. The applied-plan/epoch recovery
			// state still owns its bounded probe attempts and retry delays.
			a.reconciler.doc.Operations[i].Attempts = 0
		}
	}
	wake := a.reconciler.wake
	a.reconciler.mu.Unlock()
	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (a *App) managedReconcilerActive() bool {
	a.reconciler.mu.Lock()
	defer a.reconciler.mu.Unlock()
	return a.reconciler.started
}

// Cancel is memory-only and happens before Store admission, so a manual request
// can revoke an active automatic intent while that intent owns exclusive access.
// It never releases the worker's lease or reports the pending manual write saved.
func (a *App) interruptAutomation(r *http.Request) {
	// These POST endpoints are pure conversions, not routing/installation intents.
	if r.URL.Path == "/api/v1/extension-lab/mihomo" || r.URL.Path == "/api/v1/extension-lab/hev" {
		return
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead || strings.HasPrefix(r.URL.Path, "/api/v1/auth/") || !strings.HasPrefix(r.URL.Path, "/api/v1/") {
		return
	}
	// These handlers own job admission/cancellation. A stale cancel token or a
	// competing start must not revoke the currently admitted job as a side effect.
	if isNodeApplyPath(r) || r.URL.Path == "/api/v1/community/source-preview" || r.URL.Path == "/api/v1/dns/service-compare" || r.URL.Path == "/api/v1/service-control/current" || r.URL.Path == "/api/v1/service-control/jobs" || r.URL.Path == "/api/v1/service-control/runtime" || r.URL.Path == "/api/v1/node-checks" || r.URL.Path == "/api/v1/node-checks/current" {
		return
	}
	a.reconciler.mu.Lock()
	if a.reconciler.started {
		a.reconciler.doc.ManualUntil = time.Now().Add(15 * time.Second)
		if a.reconciler.cancel != nil {
			a.reconciler.cancel()
		}
	}
	a.reconciler.mu.Unlock()
	a.nodeAutofallback.mu.Lock()
	if a.nodeAutofallback.attemptCancel != nil {
		a.nodeAutofallback.attemptCancel()
	}
	a.nodeAutofallback.mu.Unlock()
	// A manual mutation also revokes a scheduled/service-dashboard check. The
	// worker keeps its exclusive admission until exact-check cleanup has joined.
	// Memory-only cancel has its own job-id fence and must not cancel here.
	if r.URL.Path != "/api/v1/service-control/current" {
		a.nodeChecks.mu.Lock()
		if a.nodeChecks.cancel != nil && a.nodeChecks.job != nil && strings.HasPrefix(a.nodeChecks.job.Mode, "service-") {
			a.nodeChecks.cancel()
		}
		a.nodeChecks.mu.Unlock()
	}
}

// StartServiceReconciler runs after transaction/checker boot recovery and HTTP
// readiness. Legacy standalone Start methods remain available to existing tests;
// production has one scheduling loop for these adapters and feed due events.
func (a *App) StartServiceReconciler(ctx context.Context) {
	a.reconciler.once.Do(func() {
		_ = a.loadAutonomy(ctx)
		ctx, stop := context.WithCancel(ctx)
		r := &a.reconciler
		r.mu.Lock()
		r.stop = stop
		r.started = true
		r.done = make(chan struct{})
		r.wake = make(chan struct{}, 1)
		if a.Store == nil {
			r.blocked = true
		} else {
			r.path = a.Store.AutomationStatePath()
			if a.loadReconcilerLocked(ctx) != nil {
				r.blocked = true
				r.doc = reconcilerDocument{Schema: 1, Owner: reconcilerOwner, Fallback: map[string]fallbackCheckpoint{}}
			}
		}
		done := r.done
		r.mu.Unlock()
		go func() {
			defer close(done)
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				case <-r.wake:
				}
				a.reconcileRound(ctx, time.Now())
				timer.Reset(5 * time.Second)
			}
		}()
	})
}

func (a *App) WaitServiceReconciler(ctx context.Context) error {
	a.reconciler.mu.Lock()
	done := a.reconciler.done
	if a.reconciler.stop != nil {
		a.reconciler.stop()
	}
	if a.reconciler.cancel != nil {
		a.reconciler.cancel()
	}
	a.reconciler.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *App) loadReconcilerLocked(ctx context.Context) error {
	r := &a.reconciler
	image, err := restorejournal.ReadFileImage(ctx, r.path)
	if err != nil {
		return err
	}
	r.image = image
	r.doc = reconcilerDocument{Schema: 1, Owner: reconcilerOwner, Fallback: map[string]fallbackCheckpoint{}}
	if image.Exists {
		if len(image.Data) > maxReconcilerBytes {
			return restorejournal.ErrInvalid
		}
		dec := json.NewDecoder(bytes.NewReader(image.Data))
		dec.DisallowUnknownFields()
		if dec.Decode(&r.doc) != nil || dec.Decode(&struct{}{}) != io.EOF || validateReconcilerDocument(r.doc) != nil {
			return restorejournal.ErrInvalid
		}
		// Boot recovery has already reconciled the dataplane journal. Do not
		// replay saved work or restore cached Healthy/PASS in a new network epoch.
		recoverDurableServiceJobs(&r.doc, time.Now())
		for i := range r.doc.Operations {
			op := &r.doc.Operations[i]
			if op.State == "running" {
				op.State = "interrupted"
				op.Reason = "startup-reconcile"
				op.NextRun = time.Now().Add(30 * time.Second)
			}
			if op.Kind == "node-recovery" {
				op.NextRun = time.Time{}
				op.Attempts = 0
			}
		}
		for id, checkpoint := range r.doc.Fallback {
			checkpoint.Status.Healthy = false
			checkpoint.Status.Failures = 0
			checkpoint.Status.State = "pending"
			checkpoint.Status.NextCheckAt = time.Time{}
			checkpoint.Status.Message = "После запуска требуется свежая проверка."
			checkpoint.Key = ""
			r.doc.Fallback[id] = checkpoint
		}
	}
	if r.doc.Fallback == nil {
		r.doc.Fallback = map[string]fallbackCheckpoint{}
	}
	a.nodeAutofallback.mu.Lock()
	a.nodeAutofallback.entries = map[string]nodeAutofallbackEntry{}
	for id, c := range r.doc.Fallback {
		a.nodeAutofallback.entries[id] = nodeAutofallbackEntry{status: c.Status, key: c.Key, cursor: c.Cursor, lastSwitched: c.LastSwitched}
	}
	a.nodeAutofallback.mu.Unlock()
	return a.persistReconcilerLocked(ctx)
}

func validateReconcilerDocument(d reconcilerDocument) error {
	if err := validateDurableServiceJobs(d.Jobs); err != nil {
		return err
	}
	if d.Schema != 1 || d.Owner != reconcilerOwner || d.Sequence == ^uint64(0) || len(d.Operations) > 5 || len(d.Fallback) > config.MaxServicePolicies {
		return restorejournal.ErrInvalid
	}
	seen := map[string]bool{}
	for _, op := range d.Operations {
		if !slices.Contains([]string{"node-recovery", "node-fallback", "legacy-routes", "feeds", "service-checks"}, op.Kind) || seen[op.Kind] || !slices.Contains([]string{"running", "completed", "backoff", "interrupted"}, op.State) || op.Attempts < 0 || op.Attempts > 32 || len(op.ConfigFingerprint) != 64 || strings.Trim(op.ConfigFingerprint, "0123456789abcdef") != "" || len(op.PolicyRevisions) > config.MaxServicePolicies || len(op.NetworkFingerprint) > 128 || !slices.Contains([]string{"scheduled", "startup-reconcile", "settings-changed", "operation-retry"}, op.Reason) {
			return restorejournal.ErrInvalid
		}
		seen[op.Kind] = true
	}
	for id, c := range d.Fallback {
		if len(id) > 128 || id != c.Status.ServiceID || c.Cursor < 0 || c.Cursor > 1000000 || len(c.Key) > 1024 || len(c.Status.Message) > 512 || len(c.SwitchAttempts) > 60 {
			return restorejournal.ErrInvalid
		}
	}
	return nil
}

func (a *App) persistReconcilerLocked(ctx context.Context) error {
	r := &a.reconciler
	if r.path == "" {
		return nil
	}
	data, err := json.Marshal(r.doc)
	if err != nil || len(data) > maxReconcilerBytes {
		return restorejournal.ErrInvalid
	}
	target, err := restorejournal.OpenFileTarget(r.path)
	if err != nil {
		return err
	}
	defer target.Close()
	after := restorejournal.Image{Exists: true, Data: data}
	if err = target.CompareAndSwap(ctx, r.image, after); err != nil {
		r.blocked = true
		return err
	}
	r.image = after
	return nil
}

func (a *App) reconcileRound(ctx context.Context, now time.Time) {
	// Stop needs neither DNS nor a node inventory. Join any previous cleanup,
	// then dispatch it before background recovery can reactivate an owned path.
	if a.hasDueRuntimeStop(now) && a.runDurableServiceJob(ctx, now) {
		return
	}
	r := &a.reconciler
	r.mu.Lock()
	blocked := r.blocked || now.Before(r.doc.ManualUntil)
	due := len(r.doc.Operations) < 5
	for _, job := range r.doc.Jobs {
		due = due || !job.terminal() && !now.Before(job.NotBefore)
	}
	for _, op := range r.doc.Operations {
		due = due || !now.Before(op.NextRun)
	}
	r.mu.Unlock()
	if blocked || !due || ctx.Err() != nil || a.Store == nil {
		return
	}
	release, err := a.Operations.Enter(ctx)
	if err != nil {
		return
	}
	err = a.preserveLegacyServicePolicies(ctx)
	cfg := a.Store.Get()
	var nodeGeneration uint64
	if a.Nodes != nil {
		if snapshot, snapshotErr := a.Nodes.Snapshot(ctx, now); snapshotErr == nil {
			nodeGeneration = snapshot.Generation
		}
	}
	profile, _ := a.freshNetworkProfile(ctx)
	release()
	if err != nil {
		return
	}
	legacyInterval := 15 * time.Minute
	if a.Warp != nil {
		health := a.Warp.Health()
		if health.Policy.Enabled {
			legacyInterval = min(legacyInterval, health.Policy.CheckInterval())
		}
	}
	tasks := []struct {
		kind     string
		interval time.Duration
	}{{"node-recovery", 30 * time.Second}, {"node-fallback", time.Minute}, {"legacy-routes", legacyInterval}, {"feeds", 30 * time.Second}, {"service-checks", time.Duration(max(60, cfg.ServiceControl.Schedule.IntervalSeconds)) * time.Second}}
	for _, task := range tasks {
		if ctx.Err() != nil {
			return
		}
		// Cleanup/manual Stop can interrupt admission. Existing path recovery
		// runs before queued observations; they share this scheduler and checker.
		if task.kind == "node-fallback" && a.runDurableServiceJob(ctx, time.Now()) {
			return
		}
		r.mu.Lock()
		if r.blocked || now.Before(r.doc.ManualUntil) {
			r.mu.Unlock()
			return
		}
		index := -1
		for i, op := range r.doc.Operations {
			if op.Kind == task.kind {
				index = i
				break
			}
		}
		if index >= 0 && now.Before(r.doc.Operations[index].NextRun) {
			r.mu.Unlock()
			continue
		}
		if index < 0 {
			r.doc.Operations = append(r.doc.Operations, automationOperation{Kind: task.kind})
			index = len(r.doc.Operations) - 1
		}
		r.doc.Sequence++
		op := &r.doc.Operations[index]
		op.ID = r.doc.Sequence
		op.State = "running"
		op.Reason = "scheduled"
		op.ConfigGeneration = cfg.Revision
		op.ConfigFingerprint = automationConfigFingerprint(cfg)
		op.PolicyRevisions = map[string]uint64{}
		for id, p := range cfg.ServicePolicies {
			op.PolicyRevisions[id] = p.Revision
		}
		op.NodeGeneration = nodeGeneration
		op.NetworkFingerprint = profile
		// Earlier jobs can outlive the round timestamp. Each dispatched job
		// receives its own bounded budget, still limited by the parent context.
		dispatchedAt := time.Now()
		op.Deadline = dispatchedAt.Add(defaultDataplaneApplyTimeout)
		if task.kind == "service-checks" {
			op.Deadline = dispatchedAt.Add(time.Duration(len(cfg.ServiceControl.Schedule.ServiceIDs)+1) * time.Minute)
		}
		op.Attempts = min(op.Attempts+1, 32)
		attempt, cancel := context.WithDeadline(ctx, op.Deadline)
		r.cancel = cancel
		if err = a.persistReconcilerLocked(ctx); err != nil {
			cancel()
			r.cancel = nil
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()
		var forwardingErr error
		switch task.kind {
		case "node-recovery":
			forwardingErr = a.restoreForwardingRound(attempt)
			a.nodeRecoveryRound(attempt, now)
			// A stale committed epoch is the reason to revalidate the exact
			// applied targets, not a failed scheduler dispatch. Recovery owns
			// its own bounded retries; do not back off again while it waits.
			// Match only the plain refusal: a joined cleanup/ownership error
			// must remain visible as a failed forwarding operation.
			if forwardingErr == dataplane.ErrNetworkChanged {
				forwardingErr = nil
			}
		case "node-fallback":
			a.nodeAutofallbackRound(attempt, now)
		case "legacy-routes":
			a.backgroundRound(attempt, 1)
		case "feeds":
			if a.NodeFeeds != nil {
				a.NodeFeeds.ScheduleDue(now)
			}
			// Share the existing due-event and cancellation journal; no sixth
			// operation kind is written into the rc.2 journal format.
			a.autonomyRound(attempt, time.Now())
		case "service-checks":
			if cfg.ServiceControl.Schedule.Enabled && !cfg.ServiceControl.Stopped {
				done, startErr := a.startServiceControlJob(attempt, serviceControlJobRequest{Kind: "check", ServiceIDs: cfg.ServiceControl.Schedule.ServiceIDs}, true)
				if startErr == nil {
					<-done
				}
			}
		}
		attemptErr := errors.Join(attempt.Err(), forwardingErr)
		cancel()
		r.mu.Lock()
		r.cancel = nil
		op = &r.doc.Operations[index]
		op.State = "completed"
		op.NextRun = now.Add(task.interval)
		if task.kind == "service-checks" || task.kind == "feeds" {
			op.NextRun = time.Now().Add(task.interval)
		}
		if attemptErr != nil {
			op.State = "backoff"
			op.Reason = "operation-retry"
			op.NextRun = time.Now().Add(time.Duration(1<<min(op.Attempts-1, 5)) * 30 * time.Second)
			if task.kind == "node-recovery" {
				// Keep observing changed applied authority/network promptly,
				// even when forwarding repair has a persistent real failure.
				// Exact checks still obey nodeRecoveryRound's per-plan limits.
				op.NextRun = now.Add(task.interval)
			}
		} else {
			op.Attempts = 0
		}
		a.nodeAutofallback.mu.Lock()
		for id, e := range a.nodeAutofallback.entries {
			c := r.doc.Fallback[id]
			c.Status = e.status
			c.Key = e.key
			c.Cursor = e.cursor
			c.LastSwitched = e.lastSwitched
			r.doc.Fallback[id] = c
		}
		a.nodeAutofallback.mu.Unlock()
		// Keep only current service permissions; deleted services cannot grow the journal.
		for id := range r.doc.Fallback {
			if _, exists := cfg.ServicePolicies[id]; !exists {
				delete(r.doc.Fallback, id)
			}
		}
		_ = a.persistReconcilerLocked(context.WithoutCancel(ctx))
		r.mu.Unlock()
	}
}

// Reserve a rate-limit slot BEFORE activation. A crash after activation cannot
// erase the hourly cap; failed attempts deliberately also consume one slot.
func (a *App) reserveFallbackSwitch(ctx context.Context, p config.ServicePolicy, now time.Time) error {
	r := &a.reconciler
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return nil
	}
	if r.blocked {
		return restorejournal.ErrRecovery
	}
	c := r.doc.Fallback[p.ServiceID]
	c.Status.ServiceID = p.ServiceID
	recent := []time.Time{}
	for _, at := range c.SwitchAttempts {
		if at.After(now.Add(-time.Hour)) {
			recent = append(recent, at)
		}
	}
	if len(recent) >= p.MaxSwitchesPerHour {
		return errors.New("service switch budget exhausted")
	}
	c.SwitchAttempts = append(recent, now)
	r.doc.Fallback[p.ServiceID] = c
	return a.persistReconcilerLocked(ctx)
}
