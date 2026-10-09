package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Compare the original writer's exact wire image, not a permissive decode that
// can discard duplicate/unknown fields and silently repair an unknown journal.
// The caller holds the original scope metadata mutex.
func nfqws2UnlaunchedJournalsCurrent(s *executionResourceScope) error {
	var expected []byte
	var err error
	if executionHasNetworkIdentity(*s.execution) {
		expected, err = json.Marshal(*s.execution)
	} else {
		expected, err = json.MarshalIndent(*s.execution, "", "  ")
	}
	if err != nil {
		return errors.Join(ErrExecutionJournal, err)
	}
	for _, path := range []string{filepath.Join(s.root, "execution.json"), filepath.Join(s.managerRoot, "latest-execution.json")} {
		recorded, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(recorded, expected) {
			return errors.Join(ErrExecutionJournal, err)
		}
	}
	return nil
}

// This proof exists only before the actual native producer has ever been
// invoked. Missing prepared/PID/receipt alone is never an unused permission.
func (e *nfqws2ActiveExecution) observeUnlaunched(ctx context.Context) error {
	if err := e.cleanupCurrent(ctx); err != nil {
		return err
	}
	nfqws2ActiveAdapterMu.Lock()
	absent := e.material.adapter.activeExecution == e && e.material.adapter.activeProcess == nil
	nfqws2ActiveAdapterMu.Unlock()
	if !absent {
		return ErrNFQWSScopedOwner
	}
	if _, err := os.Lstat(filepath.Join(e.material.command.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrNFQWSScopedOwner, err)
	}
	plan, err := CompileNFQWSScopedPlan(e.plan, e.spec.Clone())
	if err != nil {
		return err
	}
	if e.resource != nil && plan.Digest() != e.resource.Plan().Digest() {
		return ErrNFQWSScopedOwner
	}
	if err := e.checkOriginalQueueAbsent(ctx); err != nil {
		return err
	}
	if err := e.observeBackendAbsent(ctx, plan); err != nil {
		return err
	}
	if err := e.checkOriginalQueueAbsent(ctx); err != nil {
		return err
	}
	return e.cleanupCurrent(ctx)
}

// observe is the concrete queue/whole-backend/owner observer above; package
// tests model only that native leaf. This private method cannot issue a Start,
// COMMON receipt or deletion. It closes only the original unused reservation.
func (e *nfqws2ActiveExecution) settleUnlaunched(ctx context.Context, observe func(context.Context) error) error {
	if e == nil || e.self != e || e.material == nil || e.material.self != e.material || e.cleanup == nil || e.material.control == nil || observe == nil {
		return ErrNFQWSScopedOwner
	}
	e.mu.Lock()
	valid := e.started && !e.launchInvoked && !e.retired && e.prepared == nil && e.preparationErr != nil && !errors.Is(e.preparationErr, ErrExecutionJournal)
	e.mu.Unlock()
	if !valid {
		return ErrNFQWSScopedOwner
	}
	return e.cleanup.WithCurrent(ctx, func() error {
		if err := e.material.control.CurrentForCleanup(ctx); err != nil {
			return err
		}
		release := func() error {
			if err := e.material.control.CurrentForCleanup(ctx); err != nil {
				return err
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.launchInvoked || e.retired || e.prepared != nil {
				return ErrNFQWSScopedOwner
			}
			nfqws2ActiveAdapterMu.Lock()
			defer nfqws2ActiveAdapterMu.Unlock()
			if e.material.adapter == nil || e.material.adapter.activeExecution != e || e.material.adapter.activeProcess != nil {
				return ErrNFQWSScopedOwner
			}
			e.material.adapter.activeExecution, e.retired = nil, true
			return nil
		}
		r := e.resource
		if r == nil {
			// The original issuer tags EVERY possibly partial filesystem/journal
			// failure ErrExecutionJournal. A known pre-mutation refusal still
			// needs fresh actual namespace/process absence around control.
			if err := observe(ctx); err != nil {
				return err
			}
			if err := observe(ctx); err != nil {
				return err
			}
			return release()
		}
		if r.scope == nil {
			return ErrNFQWSScopedOwner
		}
		check := func() (int, error) {
			e.mu.Lock()
			unused := e.started && !e.launchInvoked && !e.retired && e.prepared == nil
			e.mu.Unlock()
			if !unused || r.beforeUsed || r.startReady || r.startUsed || r.startACK || r.preparedUsed || r.transferUsed || r.preparedOwner != nil || r.finalOwner != nil || r.scope.failure != nil ||
				r.scope.manager != e.material.manager || r.scope.adapterOwner != e.material.adapter || r.scope.plan.PlanID != e.plan.PlanID || r.scope.plan.Digest != e.plan.Digest {
				return -1, ErrNFQWSScopedOwner
			}
			i, err := r.matching(r.binding)
			if err != nil || r.scope.execution.Resources[i].Phase != "planned" {
				return -1, errors.Join(ErrNFQWSScopedOwner, err)
			}
			if err := r.scope.checkOriginalOwner(ctx, &executionTransitResource{relative: r.relative, anchor: r.anchor}, false, false); err != nil {
				return -1, err
			}
			if r.scope.networkIdentity == nil || r.scope.networkIdentity.check(ctx) != nil {
				return -1, ErrNetworkPolicyIdentity
			}
			if err := e.material.control.CurrentForCleanup(ctx); err != nil {
				return -1, err
			}
			for _, name := range []string{policyAdditionFile, policyAdditionLock} {
				if _, err := r.scope.owned.Stat(filepath.Join(r.relative, name)); !errors.Is(err, os.ErrNotExist) {
					return -1, errors.Join(ErrNFQWSScopedOwner, err)
				}
			}
			if err := nfqws2UnlaunchedJournalsCurrent(r.scope); err != nil {
				return -1, err
			}
			return i, nil
		}
		if err := func() error { r.scope.mu.Lock(); defer r.scope.mu.Unlock(); _, err := check(); return err }(); err != nil {
			return err
		}
		if err := observe(ctx); err != nil {
			return err
		}
		if err := func() error {
			r.scope.mu.Lock()
			defer r.scope.mu.Unlock()
			i, err := check()
			if err != nil {
				return err
			}
			// Positively unused, physically absent; no mixed-receipt grant is
			// invented. Both existing records must durably close before release.
			r.scope.execution.Resources[i].State, r.scope.execution.Resources[i].Phase = "removed", "removed"
			return r.scope.persist()
		}(); err != nil {
			return err
		}
		if err := observe(ctx); err != nil {
			return err
		}
		if err := func() error {
			r.scope.mu.Lock()
			defer r.scope.mu.Unlock()
			if r.scope.failure != nil {
				return ErrExecutionJournal
			}
			if err := r.scope.checkOriginalOwner(ctx, &executionTransitResource{relative: r.relative, anchor: r.anchor}, false, false); err != nil {
				return err
			}
			if err := nfqws2UnlaunchedJournalsCurrent(r.scope); err != nil {
				return err
			}
			return release()
		}(); err != nil {
			return err
		}
		return nil
	})
}
