//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

var ErrMihomoLiveNativeSettlementCut = errors.New("native fixture original Mihomo settlement ACK refusal")

type MihomoLiveHealthSettlementNativeFixture struct {
	self *MihomoLiveHealthSettlementNativeFixture
	cut  *mihomoLiveHealthNativeCut
}

func mihomoHealthFixtureNamespace(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return errMihomoLiveMaterial
	}
	d, finite := ctx.Deadline()
	if !finite || time.Until(d) <= 0 || time.Until(d) > 2*time.Minute {
		return errMihomoLiveMaterial
	}
	for _, kind := range []string{"net", "mnt"} {
		self, err := os.Readlink("/proc/self/ns/" + kind)
		initial, e2 := os.Readlink("/proc/1/ns/" + kind)
		if err != nil || e2 != nil || self == initial {
			return errMihomoLiveMaterial
		}
	}
	return nil
}

// Error-only fixture, absent from ordinary binaries. It retains the genuine
// already-active original handles; it cannot issue a runtime or skip an effect.
func ArmMihomoLiveHealthSettlementNativeFixture(ctx context.Context, m *Manager) (*MihomoLiveHealthSettlementNativeFixture, error) {
	if err := mihomoHealthFixtureNamespace(ctx); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errMihomoLiveMaterial
	}
	if err := m.beginOperation(ctx); err != nil {
		return nil, err
	}
	defer m.endOperation()
	r := m.originalMihomoLive()
	if r == nil || r.self != r || r.scope == nil || r.adapter == nil || !r.adapter.RegisteredWith(m) {
		return nil, errMihomoLiveMaterial
	}
	bound, end, err := r.operation(ctx, nil, true)
	if err != nil {
		return nil, err
	}
	defer end()
	if err := r.liveOwnersReadOnly(bound, nil); err != nil {
		return nil, err
	}
	r.mu.Lock()
	child, sidecar, closed := r.child, r.sidecar, r.closed || r.retired
	r.mu.Unlock()
	digest, err := r.definition.FrozenDigest()
	if err != nil || closed || child == nil || sidecar == nil {
		return nil, errMihomoLiveMaterial
	}
	s := r.scope
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open || !s.retained || s.pending || s.failure != nil || r.healthCheck != nil || r.nativeHealthSettlementCut != nil || s.execution.State != "committed" {
		return nil, errMihomoLiveMaterial
	}
	cut := &mihomoLiveHealthNativeCut{owner: r, child: child, sidecar: sidecar, digest: digest}
	cut.self = cut
	r.nativeHealthSettlementCut = cut
	f := &MihomoLiveHealthSettlementNativeFixture{cut: cut}
	f.self = f
	return f, nil
}

// Full original native/TUN observation under the retained cleanup borrower.
// The returned count is diagnostic only, never a cleanup acknowledgment.
func (f *MihomoLiveHealthSettlementNativeFixture) Observe(ctx context.Context, cleanup *operationgate.ExclusiveCleanupReview) (int, error) {
	if err := mihomoHealthFixtureNamespace(ctx); err != nil {
		return 0, err
	}
	if f == nil || f.self != f || f.cut == nil || f.cut.self != f.cut || f.cut.owner == nil {
		return 0, errMihomoLiveMaterial
	}
	cut, r := f.cut, f.cut.owner
	m := r.scope.manager
	if err := m.beginOperation(ctx); err != nil {
		return 0, err
	}
	defer m.endOperation()
	if m.originalMihomoLive() != r {
		return 0, errMihomoLiveMaterial
	}
	r.mu.Lock()
	same := r.child == cut.child && r.sidecar == cut.sidecar && !r.closed && !r.retired
	r.mu.Unlock()
	digest, err := r.definition.FrozenDigest()
	if err != nil || !same || digest != cut.digest {
		return 0, errMihomoLiveMaterial
	}
	c, end, err := r.operation(ctx, cleanup, false)
	if err != nil {
		return 0, err
	}
	defer end()
	if err := r.liveOwnersReadOnly(c, cleanup); err != nil {
		return 0, err
	}
	r.scope.mu.Lock()
	defer r.scope.mu.Unlock()
	if r.nativeHealthSettlementCut != cut {
		return 0, errMihomoLiveMaterial
	}
	return cut.hits, nil
}

// Scope.mu is held. Only actual original settlement persistence can encounter
// the two fixed errors; ordinary publication/final ACK cannot spend a cut.
func mihomoLiveHealthCheckingFixtureFaultLocked(r *mihomoLiveResource, c *mihomoLiveHealthCheck) {
	cut := r.nativeHealthSettlementCut
	if cut == nil || cut.self != cut || cut.owner != r {
		return
	}
	c.fault = func(step string) error {
		resource := c.settling
		if step != "before-latest" || resource == nil || resource.probe == nil || resource.settlementReadback == "" || resource.finished || cut.hits >= 2 {
			return nil
		}
		if r.scope.issued[filepath.Base(resource.relative)] != resource {
			return errMihomoLiveMaterial
		}
		cut.hits++
		return ErrMihomoLiveNativeSettlementCut
	}
}
