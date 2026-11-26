package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type recoveryStopAdapter struct {
	*serviceRuntimeAdapter
	inactive     error
	observations int
	afterObserve func() error
}

func (a *recoveryStopAdapter) VerifyRuntimeInactive(context.Context) error {
	a.observations++
	if a.afterObserve != nil {
		return a.afterObserve()
	}
	return a.inactive
}
func recoveryStopFixture(t *testing.T) (*App, *recoveryStopAdapter, config.Config) {
	t.Helper()
	root := t.TempDir()
	s, e := config.Load(filepath.Join(root, "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	s.SetSafeMode(false)
	s.UpdateService("video", config.ServiceState{Enabled: true, Route: "nfqws2"})
	s.ApplyDraft()
	s.UpdateService("pending", config.ServiceState{Enabled: true, Route: "direct"})
	cfg := s.Get()
	m := dataplane.New(filepath.Join(root, "dataplane"))
	adapter := &recoveryStopAdapter{serviceRuntimeAdapter: &serviceRuntimeAdapter{nodeApplyAdapter: &nodeApplyAdapter{}, name: "nfqws2"}}
	m.Register(adapter)
	plan, e := dataplane.Build(dataplane.Input{Revision: cfg.AppliedRevision, Routes: []dataplane.Route{{ServiceID: "video", ServiceName: "Video", Selected: "nfqws2", Resolved: "nfqws2", Domains: []string{"video.example"}}}, Engines: []dataplane.Engine{{ID: "nfqws2", Installed: true, Configured: true, Running: true, Activatable: true}}, Host: dataplane.HostState{IPTables: true, NFQueueTarget: true, NFQWS2Config: true, NFQWS2Init: true}})
	if e != nil {
		t.Fatal(e)
	}
	plan.State = "committed"
	plan.Ready = true
	if _, e = m.Apply(context.Background(), plan, nil); e != nil {
		t.Fatal(e)
	}
	plan, _, _ = m.Committed()
	adapter.calls = nil
	recovery := dataplane.Recovery{PlanID: plan.PlanID, State: "degraded", FailureCount: 1, Steps: []dataplane.RecoveryStep{{Adapter: "dns-scoped", State: "dns-redirects-released"}, {Adapter: "nfqws2", State: "failed", Detail: "active NFQWS2 NFQUEUE rules were not confirmed: post-hook-unreachable"}, {Adapter: "nfqws2", State: "safe-mode-deactivated"}}}
	raw, _ := json.Marshal(recovery)
	os.WriteFile(filepath.Join(m.StateRoot, "latest-recovery.json"), raw, 0600)
	s.SetSafeMode(true)
	a := &App{Store: s, Dataplane: m, Catalog: catalog.Catalog{Services: []catalog.Service{{ID: "video", Name: "Video", Domains: []string{"video.example"}}}}}
	return a, adapter, s.Get()
}
func TestNFQRecoveryStopPublishesStoppedPreservesDesired(t *testing.T) {
	a, ad, b := recoveryStopFixture(t)
	o := a.executeServiceRuntime(context.Background(), "stop", b.Revision)
	if o.Code != "" {
		t.Fatal(o.Code, o.Message)
	}
	cfg := a.Store.Get()
	if cfg.SafeMode || !cfg.ServiceControl.Stopped || !reflect.DeepEqual(cfg.Services, b.Services) {
		t.Fatal("desired/gate state wrong")
	}
	p, ok, e := a.Dataplane.Committed()
	if e != nil || !ok || len(p.Routes) != 0 || p.PlanID == "" {
		t.Fatal("no genuine empty commit")
	}
	for _, c := range ad.calls {
		if c == "activate" {
			t.Fatal("Stop activated runtime")
		}
	}
	if ad.observations < 2 {
		t.Fatal("absence not closed")
	}
}
func TestNFQRecoveryStopRefusesUnknownOrLive(t *testing.T) {
	for _, mode := range []string{"live", "unknown-recovery", "changed-config", "catalog-change"} {
		t.Run(mode, func(t *testing.T) {
			a, ad, b := recoveryStopFixture(t)
			switch mode {
			case "live":
				ad.inactive = errors.New("foreign queue or current process")
			case "unknown-recovery":
				os.WriteFile(filepath.Join(a.Dataplane.StateRoot, "latest-recovery.json"), []byte(`{"state":"unknown"}`), 0600)
			case "changed-config":
				a.Store.UpdateService("pending", config.ServiceState{Route: "auto"})
			case "catalog-change":
				r, e := a.reviewNFQRecoveryStop(context.Background(), b)
				if e != nil {
					t.Fatal(e)
				}
				a.Catalog.Services[0].Name = "changed"
				if r.check(context.Background(), true) == nil {
					t.Fatal("catalog drift accepted")
				}
				return
			}
			before := a.Store.Get()
			o := a.executeServiceRuntime(context.Background(), "stop", b.Revision)
			if o.Code == "" || !reflect.DeepEqual(a.Store.Get(), before) || len(ad.calls) > 0 {
				t.Fatal("refusal mutated state")
			}
		})
	}
}
func TestNFQRecoveryStopFailedCleanupKeepsSafeModeAndNoActivate(t *testing.T) {
	a, ad, b := recoveryStopFixture(t)
	ad.after = func(phase string) error {
		if phase == "deactivate" {
			return errors.New("cleanup refused")
		}
		return nil
	}
	o := a.executeServiceRuntime(context.Background(), "stop", b.Revision)
	if o.Code == "" || !reflect.DeepEqual(a.Store.Get(), b) {
		t.Fatal("failure lost SafeMode/config")
	}
	for _, c := range ad.calls {
		if c == "activate" {
			t.Fatal("failure activated prior runtime")
		}
	}
}

func TestNFQRecoveryStopColdObservationPreservesProof(t *testing.T) {
	a, ad, b := recoveryStopFixture(t)
	path := filepath.Join(a.Dataplane.StateRoot, "latest-recovery.json")
	before, _ := os.ReadFile(path)
	for i := 0; i < 2; i++ {
		r, preserve, e := a.ObservePendingNFQRecoveryStop(context.Background())
		if !preserve || e == nil || r.State != "degraded" {
			t.Fatal("lost explicit recovery proof", r, preserve, e)
		}
	}
	after, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(a.Store.Get(), b) || len(ad.calls) > 0 {
		t.Fatal("cold observation mutated or restarted")
	}
	ad.inactive = errors.New("unknown current process")
	if _, preserve, _ := a.ObservePendingNFQRecoveryStop(context.Background()); preserve {
		t.Fatal("unknown process suppressed normal recovery")
	}
}
func TestNFQRecoveryStopPostConfigFailureUndoesSafeModeAndNeverRestarts(t *testing.T) {
	a, ad, b := recoveryStopFixture(t)
	ad.afterObserve = func() error {
		if !a.Store.Get().SafeMode {
			return errors.New("closing owner observation changed")
		}
		return nil
	}
	o := a.executeServiceRuntime(context.Background(), "stop", b.Revision)
	if o.Code == "" || !reflect.DeepEqual(a.Store.Get(), b) {
		t.Fatal("failed publication lost full safe config", o)
	}
	for _, c := range ad.calls {
		if c == "activate" {
			t.Fatal("failed recovery Stop restarted old runtime")
		}
	}
}
func TestNFQRecoveryStopReviewRejectsRecoveryAndConfigDrift(t *testing.T) {
	for _, kind := range []string{"config", "recovery", "execution", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			a, _, b := recoveryStopFixture(t)
			r, e := a.reviewNFQRecoveryStop(context.Background(), b)
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			switch kind {
			case "config":
				a.Store.UpdateService("pending", config.ServiceState{Enabled: true, Route: "auto"})
			case "recovery":
				os.WriteFile(filepath.Join(a.Dataplane.StateRoot, "latest-recovery.json"), []byte(`{"state":"intent-refused"}`), 0600)
			case "execution":
				os.WriteFile(filepath.Join(a.Dataplane.StateRoot, "latest-execution.json"), []byte(`{"state":"rollback-failed"}`), 0600)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if kind == "execution" {
				if _, preserve, _ := a.ObservePendingNFQRecoveryStop(ctx); preserve {
					t.Fatal("unknown execution preserved")
				}
			} else if r.check(ctx, true) == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}

func TestNFQRecoveryStopDurablePOSTAndWorker(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "revision-changed"}[changed], func(t *testing.T) {
			a, ad, b := recoveryStopFixture(t)
			initReconcilerFixture(t, a, time.Now())
			job := durableRuntimeAccept(t, a, "stop", "reviewed-degraded-nfq-stop", b.Revision)
			if changed {
				a.Store.UpdateService("pending", config.ServiceState{Enabled: true, Route: "auto"})
			}
			a.runDurableServiceJob(context.Background(), time.Now())
			j := durableJobAt(t, a, job.ID)
			if changed {
				if j.State == "completed" || !a.Store.Get().SafeMode || a.Store.Get().ServiceControl.Stopped || len(ad.calls) > 0 {
					t.Fatal("stale queued Stop wrote config", j)
				}
			} else {
				if j.State != "completed" || a.Store.Get().SafeMode || !a.Store.Get().ServiceControl.Stopped || a.Operations.Snapshot().Fenced {
					t.Fatal("durable recovery Stop failed", j)
				}
			}
		})
	}
}
