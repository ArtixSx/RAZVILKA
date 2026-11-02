package dataplane

import (
	"context"
	"errors"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestMihomoProbeInactivityRequiresIdleOriginalSlot(t *testing.T) {
	for _, kind := range []string{"missing", "copied", "busy", "pending", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			a := NewMihomoProbeAdapter(components.New(), netidentity.NewProcProvider())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "missing":
				a = nil
			case "copied":
				a = &MihomoProbeAdapter{self: a, components: a.components, provider: a.provider}
			case "busy":
				a.busy = true
			case "pending":
				a.pending = &mihomoProbeResource{}
			case "cancelled":
				cancel()
			}
			var observer RuntimeInactivityObserver = a
			if !errors.Is(observer.VerifyRuntimeInactive(ctx), ErrRuntimeInactivity) {
				t.Fatal("unavailable original probe slot accepted")
			}
			if kind == "busy" && !a.busy || kind == "pending" && a.pending == nil {
				t.Fatal("refusal released another operation's owner")
			}
		})
	}
}
