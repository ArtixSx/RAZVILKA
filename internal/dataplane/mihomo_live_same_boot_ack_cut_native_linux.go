//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"os"
	"sync"
)

type mihomoSameBootNativeACKKey struct{}
type mihomoSameBootNativeACKCut struct {
	mu          sync.Mutex
	self        *mihomoSameBootNativeACKCut
	cursor      *mihomoSameBootRetirementCursor
	stage       string
	active, hit bool
}

// Refusal-only cut AFTER an actual original publisher acknowledged its file.
// It cannot skip a source/command check or synthesize a durable acknowledgment.
func WithMihomoSameBootNativeACKCut(ctx context.Context, stage string, use func(context.Context) error) (resultErr error) {
	if ctx == nil || use == nil || os.Geteuid() != 0 {
		return ErrMihomoLiveRetirement
	}
	switch stage {
	case "retirement.json", "runtime-history", "completed.json", "terminal-transaction", "terminal-global":
	default:
		return ErrMihomoLiveRetirement
	}
	for _, kind := range []string{"net", "mnt"} {
		self, e1 := os.Readlink("/proc/self/ns/" + kind)
		parent, e2 := os.Readlink("/proc/1/ns/" + kind)
		if e1 != nil || e2 != nil || self == parent {
			return ErrMihomoLiveRetirement
		}
	}
	f := &mihomoSameBootNativeACKCut{stage: stage, active: true}
	f.self = f
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.active = false
		if !f.hit {
			resultErr = errors.Join(resultErr, errors.New("actual requested postpublication cut was not reached"))
		}
	}()
	return use(context.WithValue(ctx, mihomoSameBootNativeACKKey{}, f))
}

func installMihomoSameBootNativeACKCut(ctx context.Context, c *mihomoSameBootRetirementCursor) error {
	raw := ctx.Value(mihomoSameBootNativeACKKey{})
	if raw == nil {
		return nil
	}
	f, ok := raw.(*mihomoSameBootNativeACKCut)
	if !ok || f == nil || f.self != f || c == nil || c.self != c || c.ctx != ctx || c.manager == nil || c.manager.StateRoot != "/opt/razvilka/state/dataplane" || c.archive == nil {
		return ErrMihomoLiveRetirement
	}
	f.mu.Lock()
	if !f.active || f.cursor != nil {
		f.mu.Unlock()
		return ErrMihomoLiveRetirement
	}
	f.cursor = c
	f.mu.Unlock()
	fail := func(stage string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !f.active || f.self != f || f.cursor != c || c.closed {
			return ErrMihomoLiveRetirement
		}
		if f.stage != stage || f.hit {
			return nil
		}
		f.hit = true
		return errors.New("actual original publication ACK deliberately lost")
	}
	c.archive.fault = fail
	c.terminalFault = func(n int) error {
		if !c.owner.effectsClosed {
			return ErrMihomoLiveRetirement
		}
		if n == 0 {
			return fail("terminal-transaction")
		}
		if n == 1 {
			return fail("terminal-global")
		}
		return ErrMihomoLiveRetirement
	}
	return nil
}
