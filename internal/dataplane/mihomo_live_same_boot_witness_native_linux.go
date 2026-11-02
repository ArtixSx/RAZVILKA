//go:build linux && razvilka_native_fixture

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
)

type mihomoSameBootNativeWitnessKey struct{}
type mihomoSameBootNativeWitness struct {
	mu     sync.Mutex
	self   *mihomoSameBootNativeWitness
	active bool
	use    func(context.Context, string) error
}

// A negative-only observer for actual native acceptance. It can refuse but
// cannot replace any original source/receipt/process/kernel check or command.
// Revocation joins the synchronous observer before returning to the caller.
func WithMihomoSameBootNativeWitness(ctx context.Context, witness func(context.Context, string) error, use func(context.Context) error) (resultErr error) {
	if ctx == nil || ctx.Err() != nil || witness == nil || use == nil || os.Geteuid() != 0 {
		return ErrMihomoLiveRetirement
	}
	for _, kind := range []string{"net", "mnt"} {
		self, e1 := os.Readlink("/proc/self/ns/" + kind)
		host, e2 := os.Readlink("/proc/1/ns/" + kind)
		if e1 != nil || e2 != nil || self == host {
			return ErrMihomoLiveRetirement
		}
	}
	w := &mihomoSameBootNativeWitness{active: true, use: witness}
	w.self = w
	defer func() { w.mu.Lock(); w.active = false; w.mu.Unlock() }()
	return use(context.WithValue(ctx, mihomoSameBootNativeWitnessKey{}, w))
}
func mihomoSameBootNativeStage(ctx context.Context, c *mihomoSameBootRetirementCursor, stage string, book func() error) error {
	if ctx == nil {
		return ErrMihomoLiveRetirement
	}
	raw := ctx.Value(mihomoSameBootNativeWitnessKey{})
	if raw == nil {
		return nil
	}
	w, ok := raw.(*mihomoSameBootNativeWitness)
	if !ok || w == nil || w.self != w || c == nil || c.self != c || c.closed || c.ctx != ctx || c.manager == nil || c.manager.StateRoot != "/opt/razvilka/state/dataplane" || book == nil {
		return ErrMihomoLiveRetirement
	}
	switch stage {
	case "intent", "sidecar", "policy", "forwarding", "archive", "terminal-transaction", "terminal-global":
	default:
		return ErrMihomoLiveRetirement
	}
	if (stage == "terminal-transaction" || stage == "terminal-global") && !c.owner.effectsClosed {
		return ErrMihomoLiveRetirement
	}
	if c.owner != nil && c.owner.inputs != nil {
		for n := 0; n < 2; n++ {
			if bytes.Equal(c.owner.inputs.records[n].data, c.intent.After) && !c.owner.effectsClosed {
				return ErrMihomoLiveRetirement
			}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.active || w.use == nil {
		return ErrMihomoLiveRetirement
	}
	if err := book(); err != nil {
		return err
	}
	err := w.use(ctx, stage)
	return errors.Join(err, book())
}
