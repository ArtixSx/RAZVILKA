//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
)

var ErrNativeDomainFailureACK = errors.New("native fixture lost original failed-domain cleanup ACK")

// Error only after the SAME original cleanup's actual writer/alias ACK. No
// caller callback, native success, source, receipt or deadline can be supplied.
func ConfigureNativeDomainFailureACK(ctx context.Context, f *DomainTCPCleanupFailure, stage string) error {
	if ctx == nil || f == nil || f.self != f || f.cursor == nil || stage != "process" && stage != "capture" && stage != "standby" && stage != "alias" && stage != "capture-transaction" && stage != "standby-transaction" {
		return ErrPolicyAdditionUnknown
	}
	for _, name := range []string{"net", "mnt"} {
		current, e1 := os.Readlink("/proc/self/ns/" + name)
		initial, e2 := os.Readlink("/proc/1/ns/" + name)
		if os.Geteuid() != 0 || e1 != nil || e2 != nil || current == initial {
			return ErrPolicyAdditionUnknown
		}
	}
	c := f.cursor
	if err := c.original(); err != nil {
		return err
	}
	s := c.scope
	s.mu.Lock()
	var p *XrayDomainTCPExecutionResource
	valid := s.pending && s.open && !s.observationOpen.Load() && s.ctx.Err() != nil && c.failedCustody.Load() && len(s.xrayDomainTCP) == 1
	for _, original := range s.xrayDomainTCP {
		p = original
	}
	s.mu.Unlock()
	if !valid || p == nil || p.self != p || p.material == nil || p.material.control == nil {
		return ErrPolicyAdditionUnknown
	}
	if err := p.material.control.Current(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cleanupIssued.Load() || c.cleanupFault != nil {
		return ErrPolicyAdditionUnknown
	}
	var used atomic.Bool
	c.cleanupFault = func(actual string) error {
		if actual == stage && used.CompareAndSwap(false, true) {
			return ErrNativeDomainFailureACK
		}
		return nil
	}
	return nil
}
