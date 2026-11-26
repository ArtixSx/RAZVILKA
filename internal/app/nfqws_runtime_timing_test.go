package app

import (
	"context"
	"testing"
)

func TestManagedNFQTimingsCountOriginalPhysicalBookendsWithoutRenewingDeadline(t *testing.T) {
	a, binding, physical := listScopeFixture(t, "mac", false)
	listScopeOperation(t, a, func(ctx context.Context) {
		deadline, bounded := ctx.Deadline()
		measured, _ := beginManagedNFQTimings(ctx)
		actualDeadline, actualBounded := measured.Deadline()
		if !bounded || !actualBounded || actualDeadline != deadline {
			t.Fatal("measurement replaced original finite operation deadline")
		}
		before := physical.checks
		if _, err := binding.Observe(measured); err != nil {
			t.Fatal(err)
		}
		timings := measured.Value(managedNFQTimingKey{}).(*managedNFQTimings)
		timings.mu.Lock()
		samples := timings.samples
		timings.mu.Unlock()
		if physical.checks-before != 2 || samples[managedNFQPhysicalVerify].calls != 2 || samples[managedNFQWANProfile].calls != 2 || samples[managedNFQPhysicalAcquire].calls != 0 {
			t.Fatal("measurement omitted an actual original bookend or acquired another physical owner", samples, physical.checks-before)
		}
	})
}
