//go:build linux && razvilka_native_fixture

package dataplane

import (
	"errors"
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
	if manager == nil || os.Getenv("RAZVILKA_NFQWS_NEVER_ISSUED_NATIVE") != mode || (mode != "intent" && mode != "settlement-sync") {
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
		if point == "intent" && index == 1 && cut.intent.CompareAndSwap(false, true) {
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
