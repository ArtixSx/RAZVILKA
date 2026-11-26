//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"os"
	"time"
)

var ErrMihomoLiveNativeCloseCut = errors.New("native fixture original Mihomo pre-close refusal")

// Refusal-only tagged fixture. It can neither issue an owner nor skip a close,
// and is absent from ordinary binaries.
func ArmMihomoLiveClosingNativeFixture(ctx context.Context, m *Manager, step int) error {
	if ctx == nil || ctx.Err() != nil || m == nil || os.Geteuid() != 0 || step < 0 || step > 5 {
		return errMihomoLiveMaterial
	}
	deadline, finite := ctx.Deadline()
	if !finite || time.Until(deadline) > 2*time.Minute {
		return errMihomoLiveMaterial
	}
	for _, kind := range []string{"net", "mnt"} {
		self, err := os.Readlink("/proc/self/ns/" + kind)
		initial, e2 := os.Readlink("/proc/1/ns/" + kind)
		if err != nil || e2 != nil || self == initial {
			return errMihomoLiveMaterial
		}
	}
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	r := m.originalMihomoLive()
	if r == nil || r.self != r || r.scope == nil {
		return errMihomoLiveMaterial
	}
	if err := r.control.Current(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	r.adapter.mu.Lock()
	defer r.adapter.mu.Unlock()
	if r.adapter.liveActive != r || r.adapter.livePending != nil || !r.scope.open || !r.scope.retained || r.scope.pending || r.closed || r.closing != nil || r.nativeCloseCut != nil {
		return errMihomoLiveMaterial
	}
	value := step
	r.nativeCloseCut = &value
	return nil
}

// Caller already holds the actual resource mutex, before the first Close.
func mihomoLiveClosingFixtureFaultLocked(r *mihomoLiveResource) func(int) error {
	if r.nativeCloseCut == nil {
		return nil
	}
	step := *r.nativeCloseCut
	r.nativeCloseCut = nil
	fired := false
	return func(current int) error {
		if !fired && current == step {
			fired = true
			return ErrMihomoLiveNativeCloseCut
		}
		return nil
	}
}
