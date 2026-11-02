//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
)

var ErrNativeDomainInitialACK = errors.New("native fixture lost original initial domain publication ACK")

// This CI-only seam can return one error AFTER an actual original writer FD
// and directory sync. It cannot supply a positive owner, receipt or result.
func ConfigureNativeDomainInitialACK(ctx context.Context, d *DomainTCPDetachedStandby, stage string) error {
	if d == nil || d.self != d || (stage != "transaction" && stage != "global") || xraySelectedTCPFinite(ctx) != nil || d.owner == nil || d.owner.self != d.owner || d.owner.process == nil || d.owner.process.material == nil || d.owner.process.material.control == nil {
		return ErrPolicyAdditionUnknown
	}
	for _, name := range []string{"net", "mnt"} {
		current, err := os.Readlink("/proc/self/ns/" + name)
		initial, e2 := os.Readlink("/proc/1/ns/" + name)
		if os.Geteuid() != 0 || err != nil || e2 != nil || current == initial {
			return ErrPolicyAdditionUnknown
		}
	}
	if err := d.owner.process.material.control.Current(ctx); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.finished || !d.registryDone || d.failure != nil || d.initialFault != nil {
		return ErrPolicyAdditionUnknown
	}
	var used atomic.Bool
	d.initialFault = func(actual string) error {
		if actual == stage && used.CompareAndSwap(false, true) {
			return ErrNativeDomainInitialACK
		}
		return nil
	}
	return nil
}
