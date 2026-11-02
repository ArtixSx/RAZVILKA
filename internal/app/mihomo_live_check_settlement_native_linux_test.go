//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestMihomoLiveOriginalFailedCheckSettlementStopRetry(t *testing.T) {
	t.Setenv("RAZVILKA_MIHOMO_CHECK_SETTLEMENT_NATIVE", "1")
	runMihomoLiveOriginalNativeWorkflow(t, false)
}

func mihomoLiveObserveSettlementFixture(t *testing.T, a *App, f *dataplane.MihomoLiveHealthSettlementNativeFixture, wanted int) {
	t.Helper()
	cursor := a.mihomoProbe.liveStop
	if cursor == nil || cursor.cleanup == nil || cursor.context == nil || cursor.release == nil {
		t.Fatal("original cleanup admission missing")
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(cursor.context), 10*time.Second)
	defer cancel()
	if hits, err := f.Observe(ctx, cursor.cleanup); err != nil || hits != wanted {
		t.Fatal("actual original process/sidecar/TUN comparison or expected cuts missing", hits, err)
	}
}
