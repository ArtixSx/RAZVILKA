package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/startuptools"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

type strategyProbeState struct {
	mu   sync.Mutex
	held *strategyProbeRetention
}

// An unknown operation retains its actual consumer, lease and exclusive
// release. No serialized tuple or later request can reconstruct this owner.
type strategyProbeRetention struct {
	runtime     *ManagedNFQWSListRuntime
	lease       *components.ManagedNFQWSRuntimeLease
	source      *strategylab.CandidateProbeReview
	epoch       *strategylab.ManagedProbeEpoch
	environment *managedStrategyProbeEnvironment
	completion  *dataplane.ManagedNFQWSProbeCompletion
	release     func()
	done        chan struct{}
	entered     bool
}

func (a *App) managedStrategyProbePending() bool {
	a.strategyProbe.mu.Lock()
	defer a.strategyProbe.mu.Unlock()
	return a.strategyProbe.held != nil
}

func (a *App) managedStrategyProbeRuntime() *ManagedNFQWSListRuntime {
	if a == nil || a.ExecutionHistory == nil || a.Components == nil || a.StrategyLab == nil || a.Dataplane == nil || a.Dataplane.StateRoot != filepath.Join(installpath.State, "dataplane") {
		return nil
	}
	a.managedNFQListMu.Lock()
	r := a.managedNFQList
	a.managedNFQListMu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.original() || r.closed || r.probe == nil || r.panel.Err() != nil {
		return nil
	}
	return r
}

func managedStrategyProbeScope(ctx context.Context, service catalog.Service, family string) (strategylab.CandidateProbeScope, error) {
	var zero strategylab.CandidateProbeScope
	if family == "" {
		family = "ipv4"
	}
	u, err := url.Parse(service.ProbeURL)
	if err != nil || family != "ipv4" || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Port() != "" && u.Port() != "443" {
		return zero, dataplane.ErrReviewChanged
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", u.Hostname())
	if err != nil {
		return zero, err
	}
	var selected netip.Addr
	for _, address := range addresses {
		address = address.Unmap()
		if address.Is4() && address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() {
			selected = address
			break
		}
	}
	if !selected.IsValid() {
		return zero, dataplane.ErrReviewChanged
	}
	criteria, err := strategylab.ManagedProbeCriteriaDigest(service)
	if err != nil {
		return zero, err
	}
	return strategylab.CandidateProbeScope{Target: strategylab.ProbeTarget{ServiceID: service.ID, ProbeURL: service.ProbeURL, Protocol: "tcp", IPFamily: "ipv4"}, Address: selected, CriteriaDigest: criteria}, nil
}

func writeManagedStrategyProbeError(w http.ResponseWriter, recovery bool) {
	w.Header().Set("Cache-Control", "no-store")
	status, code := http.StatusConflict, "MANAGED_STRATEGY_PROBE_REFUSED"
	if recovery {
		status, code = http.StatusServiceUnavailable, "MANAGED_STRATEGY_PROBE_RECOVERY_REQUIRED"
	}
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "recovery_required": recovery, "live_applied": false, "error": "Проверка стратегии не подтверждена. Обновите состояние лаборатории; повторный запуск автоматически не выполняется."})
}

func (a *App) probeManagedStrategyCandidate(w http.ResponseWriter, parent context.Context, id string, service catalog.Service, family string) {
	r := a.managedStrategyProbeRuntime()
	if r == nil {
		writeManagedStrategyProbeError(w, false)
		return
	}
	ctx, release, err := a.privateExclusiveOperation(parent)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	held := &strategyProbeRetention{runtime: r, release: release, done: make(chan struct{})}
	r.mu.Lock()
	a.strategyProbe.mu.Lock()
	if a.strategyProbe.held != nil || r.closed || !r.original() {
		a.strategyProbe.mu.Unlock()
		r.mu.Unlock()
		release()
		writeManagedStrategyProbeError(w, true)
		return
	}
	a.strategyProbe.held = held
	a.strategyProbe.mu.Unlock()
	r.mu.Unlock()
	retain := false
	defer func() {
		// An exceptional unwind must not release a live original lease/slot.
		// Normal completion clears lease only after acknowledged cleanup.
		if !retain && held.lease != nil {
			retain = true
			a.Operations.FenceJournal()
			if held.epoch != nil {
				_ = held.epoch.Finish(ctx, nil, dataplane.ErrNFQWSManagedProcessUnknown)
			}
		}
		if !retain {
			a.strategyProbe.mu.Lock()
			if a.strategyProbe.held == held {
				a.strategyProbe.held = nil
			}
			a.strategyProbe.mu.Unlock()
			release()
		}
		close(held.done)
	}()
	// Run the complete fleet reader review before taking a component leaf
	// lease. The actual exclusive operation prevents an updater racing it.
	if a.ExecutionHistory.CheckWrite(ctx) != nil {
		writeManagedStrategyProbeError(w, false)
		return
	}
	scope, err := managedStrategyProbeScope(ctx, service, family)
	if err != nil {
		writeManagedStrategyProbeError(w, false)
		return
	}
	lease, err := a.Components.AcquireCurrentManagedNFQWSRuntime(ctx)
	if err != nil {
		writeManagedStrategyProbeError(w, false)
		return
	}
	held.lease = lease
	source, err := a.StrategyLab.RetainCandidateProbeReview(ctx, id, scope, lease)
	if err == nil {
		held.source = source
		held.environment, err = newManagedStrategyProbeEnvironment(ctx, a, r.control, lease, service, scope)
	}
	if err == nil {
		held.epoch, err = a.StrategyLab.BeginManagedProbe(ctx, source, held.environment, held.environment.networkID, held.environment.policyHash)
	}
	var evidence strategylab.Evidence
	if err == nil {
		probeCtx, cancel := context.WithTimeout(ctx, 14*time.Second)
		probeCtx = startuptools.WithCommandAdmission(probeCtx, r)
		held.entered = true
		evidence, held.completion, err = r.probe.Execute(probeCtx, source, held.epoch, lease, service, held.environment.expected.Revision, held.environment.Current)
		cancel()
	}
	if held.entered && held.completion == nil {
		_ = held.epoch.Finish(ctx, nil, errors.Join(dataplane.ErrNFQWSManagedProcessUnknown, err))
		a.Operations.FenceJournal()
		retain = true
		writeManagedStrategyProbeError(w, true)
		return
	}
	if held.epoch != nil {
		observed := managedStrategyProbeObservation(id, evidence, err)
		err = errors.Join(err, held.epoch.Finish(ctx, observed, nil))
	}
	cleanupErr := held.closeKnownRuntime()
	if cleanupErr != nil {
		a.Operations.FenceJournal()
		retain = true
		writeManagedStrategyProbeError(w, true)
		return
	}
	if err != nil {
		writeManagedStrategyProbeError(w, false)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, evidence)
}

// Confirmed cleanup releases the native slot; it never waives a separate
// helper/closing error or authorizes publication of an earlier successful read.
func managedStrategyProbeObservation(id string, evidence strategylab.Evidence, runErr error) *strategylab.Evidence {
	if runErr != nil || evidence.CandidateID != id || len(evidence.Stages) == 0 {
		return nil
	}
	return &evidence
}

func (held *strategyProbeRetention) closeKnownRuntime() error {
	if held.lease == nil {
		return nil
	}
	var err error
	if held.entered {
		if held.completion == nil {
			return dataplane.ErrNFQWSManagedProcessUnknown
		}
		err = held.completion.CloseRuntime()
	} else {
		err = held.lease.Close()
	}
	if err != nil {
		return err
	}
	if held.environment != nil {
		if err := held.environment.runtimeRetired(); err != nil {
			return err
		}
		held.environment = nil
	}
	if held.source != nil {
		if err := held.source.Close(); err != nil {
			return err
		}
		held.source = nil
	}
	held.lease = nil
	return nil
}

// Only shutdown joins a retained unknown attempt. It cannot restart a probe,
// publish delayed evidence or clear a durable StrategyLab/recovery fence.
func (a *App) WaitManagedStrategyProbes(ctx context.Context) error {
	a.strategyProbe.mu.Lock()
	held := a.strategyProbe.held
	a.strategyProbe.mu.Unlock()
	if held == nil {
		return nil
	}
	select {
	case <-held.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	a.strategyProbe.mu.Lock()
	defer a.strategyProbe.mu.Unlock()
	if a.strategyProbe.held != held {
		return nil
	}
	if held.entered && held.completion == nil {
		if held.runtime == nil || held.runtime.probe == nil {
			return dataplane.ErrNFQWSManagedProcessUnknown
		}
		cleanupCtx := startuptools.WithCommandAdmission(ctx, held.runtime)
		completion, err := held.runtime.probe.RetryKnownCleanup(cleanupCtx)
		if err != nil {
			return err
		}
		held.completion = completion
	}
	if err := held.closeKnownRuntime(); err != nil {
		return err
	}
	held.release()
	a.strategyProbe.held = nil
	return nil
}
