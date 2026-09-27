package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestDNSRecoveryNewEpochWithoutNodeRegistryPreservesPendingChanges(t *testing.T) {
	a := dnsRuntimeFixture(t)
	a.Nodes, a.NodeChecker = nil, nil
	previous, _, _ := a.Dataplane.Committed()
	if err := a.DNS.SetServiceDraft("telegram", "unfiltered"); err != nil {
		t.Fatal(err)
	}
	if err := a.DNS.SetDraft("security"); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: false, Route: "direct", Sources: []string{"192.168.1.41/32"}}); err != nil {
		t.Fatal(err)
	}
	before := a.Store.Get()
	a.FreshProfile = func(context.Context) (string, error) { return recoveryProfile, nil }
	a.Dataplane.FreshProfile = a.FreshProfile
	now := time.Now()
	a.nodeRecoveryRound(context.Background(), now)
	current, exists, err := a.Dataplane.Committed()
	status := a.nodeRecoverySnapshot()
	if err != nil || !exists || status.State != "recovered" || current.NetworkProfileID != recoveryProfile {
		t.Fatalf("DNS-only recovery: %+v %v", status, err)
	}
	if !reflect.DeepEqual(current.DNS, previous.DNS) || !reflect.DeepEqual(current.Routes, previous.Routes) || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatal("recovery changed scope, applied route or pending configuration")
	}
	if a.DNS.VerifyServiceSelection("telegram", "private") != nil || a.DNS.Snapshot().ServiceDrafts["telegram"] != "unfiltered" || a.DNS.Snapshot().Draft.ProfileID != "security" {
		t.Fatal("DNS choices were replaced")
	}
	// The test adapter intentionally has no native readback implementation.
	// That must not create another repair immediately after a completed repair.
	a.nodeRecoveryRound(context.Background(), now.Add(30*time.Second))
	if got := a.nodeRecoverySnapshot(); got != status {
		t.Fatalf("repair ignored cooldown: %+v", got)
	}
}

func TestDNSRecoveryYieldsToAcceptedStopAfterJoinedRollback(t *testing.T) {
	a := dnsRuntimeFixture(t)
	initReconcilerFixture(t, a, time.Now())
	a.FreshProfile = func(context.Context) (string, error) { return recoveryProfile, nil }
	a.Dataplane.FreshProfile = a.FreshProfile
	adapter := a.Dataplane.Adapters["dns-scoped"].(*dnsReviewAdapter)
	entered, cleaning, allowCleanup, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	// Block the adapter in Health with the actual operation context.
	wrapped := &dnsCancelAdapter{dnsReviewAdapter: adapter, entered: entered, cleaning: cleaning, allowCleanup: allowCleanup}
	a.Dataplane.Adapters["dns-scoped"] = wrapped
	go func() { a.nodeRecoveryRound(context.Background(), time.Now()); close(done) }()
	awaitOperation(t, entered)
	job := durableRuntimeAccept(t, a, "stop", "stop-during-dns-recovery", a.Store.Get().Revision)
	awaitOperation(t, cleaning)
	if release, err := a.Operations.Exclusive(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		t.Fatal("cleanup released recovery admission early", err)
	}
	close(allowCleanup)
	awaitOperation(t, done)
	a.runDurableServiceJob(context.Background(), time.Now())
	if durableJobAt(t, a, job.ID).State != "completed" || !a.Store.Get().ServiceControl.Stopped {
		t.Fatal("accepted Stop not completed after recovery cleanup")
	}
}

type dnsCancelAdapter struct {
	*dnsReviewAdapter
	entered, cleaning, allowCleanup chan struct{}
}

func (a *dnsCancelAdapter) Health(ctx context.Context, _ dataplane.Plan, _ string) error {
	close(a.entered)
	<-ctx.Done()
	return ctx.Err()
}
func (a *dnsCancelAdapter) Rollback(ctx context.Context, p dataplane.Plan, root string) error {
	close(a.cleaning)
	<-a.allowCleanup
	return a.dnsReviewAdapter.Rollback(ctx, p, root)
}

func TestDNSRecoveryRefusesChangedAuthorityAndPreservesAppliedChoice(t *testing.T) {
	for _, change := range []string{"domain", "scenario", "applied-choice", "scope", "health", "network", "cancel"} {
		t.Run(change, func(t *testing.T) {
			a := dnsRuntimeFixture(t)
			previous, _, _ := a.Dataplane.Committed()
			a.FreshProfile = func(context.Context) (string, error) { return recoveryProfile, nil }
			a.Dataplane.FreshProfile = a.FreshProfile
			switch change {
			case "domain":
				a.Catalog.Services[0].Domains = append(a.Catalog.Services[0].Domains, "new.telegram.org")
			case "scenario":
				a.Catalog.Services[0].Probes = []catalog.Probe{{ID: "web", Label: "Web", URL: "https://telegram.org/", Required: true, Expect: catalog.ProbeExpectation{BodyContains: []string{"changed"}}}}
			case "applied-choice":
				if err := a.DNS.SetServiceDraft("telegram", "unfiltered"); err != nil {
					t.Fatal(err)
				}
				r, err := a.DNS.ReviewServiceSelection("telegram", "unfiltered")
				if err != nil {
					t.Fatal(err)
				}
				if err := a.DNS.CommitServiceSelection(r); err != nil {
					t.Fatal(err)
				}
			case "scope":
				if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.41/32"}}); err != nil {
					t.Fatal(err)
				}
				if err := a.Store.ApplyDraft(); err != nil {
					t.Fatal(err)
				}
			}
			adapter := a.Dataplane.Adapters["dns-scoped"].(*dnsReviewAdapter)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			adapter.after = func(phase string) error {
				if phase == "health" {
					switch change {
					case "health":
						return errors.New("injected failed DNS service canary")
					case "network":
						a.FreshProfile = func(context.Context) (string, error) { return "wan-333333333333", nil }
						a.Dataplane.FreshProfile = a.FreshProfile
					case "cancel":
						cancel()
					}
				}
				return nil
			}
			before := a.Store.Get()
			execution, err := a.recoverAppliedNodes(ctx, previous, recoveryProfile)
			if err == nil || execution.State == "committed" || adapter.active != nil {
				t.Fatalf("changed/failed authority activated: %+v %v", execution, err)
			}
			if !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("failed recovery changed settings")
			}
			wanted := "private"
			if change == "applied-choice" {
				wanted = "unfiltered"
			}
			if a.DNS.VerifyServiceSelection("telegram", wanted) != nil {
				t.Fatal("failed recovery replayed old settings")
			}
		})
	}
}

func TestDNSRecoveryUnknownNetworkReleasesOnlyRuntime(t *testing.T) {
	a := dnsRuntimeFixture(t)
	a.FreshProfile = func(context.Context) (string, error) { return "", errors.New("network unavailable") }
	a.Dataplane.FreshProfile = a.FreshProfile
	a.nodeRecoveryRound(context.Background(), time.Now())
	adapter := a.Dataplane.Adapters["dns-scoped"].(*dnsReviewAdapter)
	if adapter.active != nil || a.nodeRecoverySnapshot().State != "network-stale" || a.DNS.VerifyServiceSelection("telegram", "private") != nil {
		t.Fatal("unknown network kept interception or changed selection")
	}
}

func TestDNSRecoveryFailureHasBoundedRetries(t *testing.T) {
	a := dnsRuntimeFixture(t)
	a.FreshProfile = func(context.Context) (string, error) { return recoveryProfile, nil }
	a.Dataplane.FreshProfile = a.FreshProfile
	adapter := a.Dataplane.Adapters["dns-scoped"].(*dnsReviewAdapter)
	checks := 0
	adapter.after = func(phase string) error {
		if phase == "health" {
			checks++
			return errors.New("canary failed")
		}
		return nil
	}
	now := time.Now()
	for i := 0; i < 5; i++ {
		a.nodeRecoveryRound(context.Background(), now.Add(time.Duration(i)*10*time.Minute))
	}
	if checks != maxNodeRecoveryAttempts || a.nodeRecoverySnapshot().State != "requires-review" {
		t.Fatalf("unbounded repair: checks=%d status=%+v", checks, a.nodeRecoverySnapshot())
	}
}
