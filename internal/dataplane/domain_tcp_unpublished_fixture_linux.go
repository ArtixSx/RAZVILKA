//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
)

var ErrNativeDomainPreparationCut = errors.New("native fixture stopped after original capture preparation before kernel issuance")

// Refusal only after genuine capture preparation and original journal ACKs.
// No caller rows, callbacks, source, success result or deadline are accepted.
func ConfigureNativeDomainPreparationCut(ctx context.Context, o *DomainTCPOriginalScope) error {
	if o == nil || o.self != o || o.baseCurrent(ctx) != nil {
		return ErrDomainPolicyTCPConsumer
	}
	for _, name := range []string{"net", "mnt"} {
		current, e1 := os.Readlink("/proc/self/ns/" + name)
		initial, e2 := os.Readlink("/proc/1/ns/" + name)
		if os.Geteuid() != 0 || e1 != nil || e2 != nil || current == initial {
			return ErrDomainPolicyTCPConsumer
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.process != nil || o.preparationFault != nil || o.closed || o.publicationOpen || o.kernel != nil {
		return ErrDomainPolicyTCPConsumer
	}
	var used atomic.Bool
	o.preparationFault = func() error {
		if used.CompareAndSwap(false, true) {
			return ErrNativeDomainPreparationCut
		}
		return ErrDomainPolicyTCPConsumer
	}
	return nil
}
