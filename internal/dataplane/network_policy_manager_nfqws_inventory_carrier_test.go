package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetworkPolicyNFQInventoryOriginalCarrier(t *testing.T) {
	for _, mode := range []string{"same", "malformed", "typed-nil", "zero", "other-review", "missing", "field-drift", "both-drift", "control-drift", "nil-material", "foreign-material", "stop", "cancel", "rollback", "wg-owner", "closing-drift"} {
		t.Run(mode, func(t *testing.T) {
			c, original, ctx := networkPolicyNFQReadSourcesFixture(t)
			e := original.execution
			c.readSource = &networkPolicyOriginalInventoryReader{inventory: c.inventory}
			direct, err := CompileNFQWSDirectLANPolicyRuntime(e.plan.LAN.Generation, e.plan.LAN.Ingress)
			if err != nil {
				t.Fatal(err)
			}
			e.plan.LAN = direct
			ctx = networkPolicyConsumerContext(ctx, e.plan)
			ctx = WithWGInactivityCleanup(ctx, e.cleanup)
			carrier, err := nfqInventoryOriginalInactivityCleanup(ctx, e.material.control)
			if err != nil || carrier != e.cleanup {
				t.Fatal("original comparison carrier capture", err)
			}
			e.inventoryInactivityCleanup = carrier
			source := c.nfqInventorySources(ctx, direct, false)
			if source == nil || source.current(ctx) != nil {
				t.Fatal("same original forward carrier refused")
			}
			other, err := e.material.control.ReviewExclusiveCleanup(ctx)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "malformed":
				ctx = context.WithValue(ctx, wgInactivityCleanupKey{}, "foreign")
			case "typed-nil":
				ctx = WithWGInactivityCleanup(ctx, nil)
			case "zero":
				ctx = WithWGInactivityCleanup(ctx, &operationgate.ExclusiveCleanupReview{})
			case "other-review":
				ctx = WithWGInactivityCleanup(ctx, other)
			case "missing":
				e.inventoryInactivityCleanup = nil
			case "nil-material":
				source.read.material = nil
			case "foreign-material":
				e.material = &NFQWSActiveMaterial{}
			case "control-drift":
				e.material.control = &operationgate.ControlEpochReview{}
			case "field-drift":
				e.inventoryInactivityCleanup = other
			case "both-drift":
				e.inventoryInactivityCleanup = other
				ctx = WithWGInactivityCleanup(ctx, other)
			case "stop":
				if _, err := operationgate.RequestSelfUpdateStop(ctx, e.material.command.ControlRoot, strings.Repeat("7", 32), 0); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "rollback":
				ctx = context.WithValue(ctx, nfqws2RollbackHookContextKey{}, true)
			case "wg-owner":
				ctx = context.WithValue(ctx, wgOperationOwnerKey{}, true)
			case "closing-drift":
				calls := 0
				err := networkPolicyNFQInventoryReadOnce(ctx, e, func(request context.Context, read func(context.Context) error) error { return read(request) }, source.current, func(context.Context) error { calls++; e.inventoryInactivityCleanup = other; return nil })
				if err == nil || calls != 1 {
					t.Fatal("late carrier drift accepted", err, calls)
				}
				return
			}
			err = source.current(ctx)
			if mode == "same" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("foreign/revoked carrier became an original read")
			}
		})
	}
}

func TestNetworkPolicyNFQInventoryCarrierCaptureLifetime(t *testing.T) {
	for _, mode := range []string{"nil", "same", "foreign-gate", "released", "fresh-operation", "zero", "typed-nil", "stop"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var gate operationgate.Gate
			ctx, release, err := gate.ExclusiveContext(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			root := filepath.Join(t.TempDir(), "control")
			if _, err := operationgate.InitializeSelfUpdateControl(ctx, root); err != nil {
				t.Fatal(err)
			}
			control, err := gate.ReviewControlEpoch(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			cleanup, err := control.ReviewExclusiveCleanup(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ctx = WithWGInactivityCleanup(ctx, cleanup)
			switch mode {
			case "nil":
				ctx = parent
			case "foreign-gate":
				var foreign operationgate.Gate
				foreignCtx, closeForeign, err := foreign.ExclusiveContext(parent)
				if err != nil {
					t.Fatal(err)
				}
				defer closeForeign()
				foreignCleanup, err := foreign.ReviewExclusiveCleanup(foreignCtx)
				if err != nil {
					t.Fatal(err)
				}
				ctx = WithWGInactivityCleanup(ctx, foreignCleanup)
			case "released":
				release()
			case "fresh-operation":
				release()
				fresh, closeFresh, err := gate.ExclusiveContext(parent)
				if err != nil {
					t.Fatal(err)
				}
				defer closeFresh()
				ctx = WithWGInactivityCleanup(fresh, cleanup)
			case "zero":
				ctx = WithWGInactivityCleanup(ctx, &operationgate.ExclusiveCleanupReview{})
			case "typed-nil":
				ctx = WithWGInactivityCleanup(ctx, nil)
			case "stop":
				if _, err := operationgate.RequestSelfUpdateStop(ctx, root, strings.Repeat("7", 32), 0); err != nil {
					t.Fatal(err)
				}
			}
			got, err := nfqInventoryOriginalInactivityCleanup(ctx, control)
			if mode == "nil" {
				if err != nil || got != nil {
					t.Fatal("nil changed original path", err)
				}
				return
			}
			if mode == "same" {
				if err != nil || got != cleanup {
					t.Fatal("original review refused", err)
				}
				return
			}
			if err == nil || got != nil {
				t.Fatal("invalid or revoked carrier captured", got, err)
			}
		})
	}
}
