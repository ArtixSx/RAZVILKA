//go:build linux && razvilka_native_fixture

package dataplane

import (
	"errors"
	"log"
	"os"
	"sync"
	"sync/atomic"
)

var nfqNeverIssuedNativeCuts sync.Map
var errNFQNeverIssuedNativeCut = errors.New("original native never-issued intent cut")
var errNFQNeverIssuedNativeSyncCut = errors.New("original native settlement publication cut")

type nfqNeverIssuedNativeCut struct {
	mode     string
	intent   atomic.Bool
	sync     atomic.Bool
	released atomic.Bool
}

// Test binary only. This arms one real writer fault, never a receipt, ACK,
// native child result, inventory, permission, or successful cleanup result.
func ArmNFQWSNeverIssuedNativeFixture(manager *Manager, mode string) (func() (bool, bool), func(), error) {
	if manager == nil || os.Getenv("RAZVILKA_NFQWS_NEVER_ISSUED_NATIVE") != mode || (mode != "intent" && mode != "settlement-sync" && mode != "pre-ledger" && mode != "prepared-active") {
		return nil, nil, ErrNFQWSScopedOwner
	}
	cut := &nfqNeverIssuedNativeCut{mode: mode}
	if _, loaded := nfqNeverIssuedNativeCuts.LoadOrStore(manager, cut); loaded {
		return nil, nil, ErrNFQWSScopedOwner
	}
	return func() (bool, bool) { return cut.intent.Load(), cut.sync.Load() }, func() { cut.released.Store(true) }, nil
}

func nfqwsOriginalRecoveryOptions(e *nfqws2ActiveExecution, options policyAdditionOptions) policyAdditionOptions {
	if e == nil || e.material == nil {
		return options
	}
	raw, found := nfqNeverIssuedNativeCuts.LoadAndDelete(e.material.manager)
	if !found {
		return options
	}
	cut := raw.(*nfqNeverIssuedNativeCut)
	original := options.fault
	options.fault = func(point string, index int) error {
		if original != nil {
			if err := original(point, index); err != nil {
				return err
			}
		}
		if cut.mode == "pre-ledger" && point == "nfq-original-pre-ledger" && index == -1 {
			c := e.partialRecovery
			if c == nil || !c.preLedgerArmed() || c.index != -1 || c.publication != 0 || c.renameAttempted || c.entered {
				return ErrPolicyAdditionUnknown
			}
			if cut.intent.CompareAndSwap(false, true) {
				log.Print("actual_preledger_native_cut armed=true publications=0 rename_attempted=false entered=false common_run_entry=false")
				return errNFQNeverIssuedNativeCut
			}
		}
		if cut.mode == "prepared-active" && point == "nfq-original-prepared-absence" && index == -1 {
			c := e.partialRecovery
			if c == nil || !c.preLedgerArmed() || c.index != -1 || c.publication != 0 || c.renameAttempted || c.entered || c.preparedPolicy == nil || e.resource == nil || e.resource.scope == nil {
				return ErrPolicyAdditionUnknown
			}
			s := c.preparedPolicy
			s.mu.RLock()
			original := s.self == s && s.open && s.used && s.custody == c && s.resource == e.resource
			s.mu.RUnlock()
			r := e.resource
			r.scope.mu.Lock()
			resourceIndex, err := r.matching(r.Binding())
			beforeCapture := err == nil && r.preparedUsed && r.activeObservation == nil && r.scope.execution.Resources[resourceIndex].Phase == "process-pending"
			r.scope.mu.Unlock()
			if !original || !beforeCapture {
				return ErrPolicyAdditionUnknown
			}
			if cut.intent.CompareAndSwap(false, true) {
				log.Print("actual_prepared_active_native_cut armed=true publications=0 rename_attempted=false entered=false common_run_entry=false prepared_used=true capture_ready=false")
				return errNFQNeverIssuedNativeCut
			}
		}
		if (cut.mode == "intent" || cut.mode == "settlement-sync") && point == "intent" && index == 1 && cut.intent.CompareAndSwap(false, true) {
			return errNFQNeverIssuedNativeCut
		}
		if cut.mode == "settlement-sync" && point == "nfq-original-after-sync" && index == 1 && e.partialRecovery != nil && e.partialRecovery.session != nil && e.partialRecovery.session.doc.Steps[index].State == "removed" && !cut.released.Load() {
			cut.sync.Store(true)
			return errNFQNeverIssuedNativeSyncCut
		}
		return nil
	}
	return options
}
