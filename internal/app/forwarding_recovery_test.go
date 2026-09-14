package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestRestoreForwardingUsesAppliedIntentUnderExclusiveAdmission(t *testing.T) {
	a, _, adapter, checker, plan := nodeRecoveryFixture(t)
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.77/32"}}); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	called := false
	err := a.restoreAppliedForwarding(context.Background(), func(ctx context.Context, got dataplane.Plan) (map[string]bool, error) {
		called = true
		if !reflect.DeepEqual(got, plan) {
			t.Fatal("draft or a new plan reached forwarding repair")
		}
		if release, err := a.Operations.Enter(ctx); !errors.Is(err, operationgate.ErrBusy) {
			if release != nil {
				release()
			}
			t.Fatalf("repair did not retain exclusive admission: %v", err)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 20*time.Second {
			t.Fatal("unbounded forwarding repair")
		}
		return map[string]bool{"sing-box": true}, nil
	})
	if err != nil || !called || !reflect.DeepEqual(before, a.Store.Get()) || len(adapter.calls) != 0 || len(checker.requests) != 0 {
		t.Fatalf("repair changed route intent or used node transactions: called=%v err=%v", called, err)
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal("admission not released", err)
	}
	release()
}

func TestRestoreForwardingRespectsSafeModeStopBusyAndCancellation(t *testing.T) {
	for _, mode := range []string{"safe", "stopped", "busy", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			a, _, _, _, _ := nodeRecoveryFixture(t)
			ctx := context.Background()
			switch mode {
			case "safe":
				if err := a.Store.SetSafeMode(true); err != nil {
					t.Fatal(err)
				}
			case "stopped":
				// Use the same live control store operation as the panel.
				cfg := a.Store.Get()
				if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": cfg.AppliedServices["telegram"].Route}, cfg.Revision); err != nil {
					t.Fatal(err)
				}
			case "busy":
				release, err := a.Operations.Enter(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := a.Store.Get()
			err := a.restoreAppliedForwarding(ctx, func(context.Context, dataplane.Plan) (map[string]bool, error) {
				t.Fatal("blocked repair reached runtime")
				return nil, nil
			})
			if mode == "busy" && !errors.Is(err, operationgate.ErrBusy) || mode == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("admission result: %v", err)
			}
			if !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("blocked repair changed config")
			}
		})
	}
}

func TestAppliedForwardingRejectsUnmatchedScope(t *testing.T) {
	a, _, _, _, plan := nodeRecoveryFixture(t)
	cfg := a.Store.Get()
	if !appliedForwardingMatchesPlan(cfg, plan) {
		t.Fatal("valid applied fixture refused")
	}
	for _, mode := range []string{"destination", "source", "disabled", "duplicate", "extra"} {
		t.Run(mode, func(t *testing.T) {
			current := a.Store.Get()
			candidate := plan
			candidate.Routes = append([]dataplane.Route{}, plan.Routes...)
			service := current.AppliedServices["telegram"]
			switch mode {
			case "destination":
				service.Route = "direct"
			case "source":
				service.Sources = []string{"192.168.1.88/32"}
			case "disabled":
				service.Enabled = false
			case "duplicate":
				candidate.Routes = append(candidate.Routes, candidate.Routes[0])
			case "extra":
				current.AppliedServices["youtube"] = config.ServiceState{Enabled: true, Route: "nfqws2"}
			}
			current.AppliedServices["telegram"] = service
			if appliedForwardingMatchesPlan(current, candidate) {
				t.Fatal("changed applied scope allowed")
			}
		})
	}
}

func TestAppliedForwardingAcceptsDirectAndResolvedGroupRoutes(t *testing.T) {
	a, _, _, _, plan := nodeRecoveryFixture(t)
	cfg := a.Store.Get()
	cfg.AppliedServices["example-direct"] = config.ServiceState{Enabled: true, Route: "direct"}
	plan.Routes = append(plan.Routes, dataplane.Route{ServiceID: "example-direct", Selected: "direct", Resolved: "direct"})
	service := cfg.AppliedServices["telegram"]
	service.Route = "sing-box:group-selected"
	cfg.AppliedServices["telegram"] = service
	plan.Routes[0].Selected = service.Route
	if !appliedForwardingMatchesPlan(cfg, plan) {
		t.Fatal("direct companion or a group resolved to its member blocked restoration")
	}
}
