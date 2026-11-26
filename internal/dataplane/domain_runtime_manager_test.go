package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type domainManagerLegacyAdapter struct {
	fakeAdapter
}

func (a *domainManagerLegacyAdapter) ObserveOwnedRuntime(context.Context) error {
	return a.call("observe")
}

func (a *domainManagerLegacyAdapter) Canary(context.Context, RoutePlan, string) error {
	return a.call("canary")
}

func TestManagerDomainDefinitionRequiresOriginalRuntimeAtEveryEntry(t *testing.T) {
	transport, domain := syntheticTransportModelFixture(t)
	ctx := context.Background()
	manager := New(t.TempDir())
	adapter := &domainManagerLegacyAdapter{fakeAdapter: fakeAdapter{id: "xray"}}
	if err := manager.Register(adapter); err != nil {
		t.Fatal(err)
	}
	plan := journalTestPlan()
	plan.Adapters = []string{"xray"}
	plan.Routes = []Route{{ServiceID: "service", Selected: "xray:one", Resolved: "xray:one", Domains: []string{"service.example.com"}}}
	plan.DomainPolicy, plan.SyntheticDNS = domain, transport
	plan.State = "blocked"
	if err := manager.Record(plan); err != nil {
		t.Fatal("could not retain preview", err)
	}
	plan.State = "committed"
	if err := manager.Record(plan); !errors.Is(err, ErrDomainTransportRuntime) {
		t.Fatalf("public writer accepted committed domain metadata: %v", err)
	}
	if _, exists, err := manager.Committed(); err != nil || exists {
		t.Fatalf("preview or refused write created committed state: %v, %v", exists, err)
	}
	// A saved plan can arrive from older state without this process ever
	// owning the listener, resolver, process or kernel resource it names.
	writeJournalFile(t, filepath.Join(manager.StateRoot, "latest-committed-plan.json"), plan)
	if recovery, err := manager.Recover(ctx); !errors.Is(err, ErrDomainTransportRuntime) || !recovery.Guarded || recovery.PlanID != plan.PlanID {
		t.Fatalf("startup took domain metadata as live authority: %+v, %v", recovery, err)
	}
	if _, err := manager.RefreshCommitted(ctx); !errors.Is(err, ErrDomainTransportRuntime) {
		t.Fatalf("legacy refresh accepted domain plan: %v", err)
	}
	if err := manager.ObserveCommittedRuntime(ctx, plan); !errors.Is(err, ErrDomainTransportRuntime) {
		t.Fatalf("legacy presence accepted domain plan: %v", err)
	}
	if err := manager.CheckComponentLive(ctx, plan, "xray"); !errors.Is(err, ErrDomainTransportRuntime) {
		t.Fatalf("legacy component health accepted domain plan: %v", err)
	}
	if err := manager.ProbeCandidate(ctx, plan, "xray"); !errors.Is(err, ErrDomainTransportRuntime) {
		t.Fatalf("legacy candidate probe accepted domain plan: %v", err)
	}
	if _, err := manager.Apply(ctx, plan, nil); !errors.Is(err, ErrDomainTransportRuntime) {
		t.Fatalf("legacy apply accepted domain plan: %v", err)
	}
	if len(adapter.calls) != 0 || adapter.recovered || adapter.refreshed {
		t.Fatalf("unsupported plan reached an adapter: %+v", adapter)
	}
	if _, err := manager.Deactivate(ctx); err != nil || !adapter.deactivated {
		t.Fatalf("original adapter cleanup was refused: %v", err)
	}
}

func TestManagerDomainMetadataCannotSettleInterruptedCommit(t *testing.T) {
	transport, domain := syntheticTransportModelFixture(t)
	manager, _, execution := committedFixture(t)
	plan, exists, err := manager.Committed()
	if err != nil || !exists {
		t.Fatal("missing normal fixture commit", err)
	}
	plan.DomainPolicy, plan.SyntheticDNS = domain, transport
	for _, name := range []string{"latest-plan.json", "latest-committed-plan.json"} {
		writeJournalFile(t, filepath.Join(manager.StateRoot, name), plan)
	}
	execution.State, execution.FinishedAt = "committing", ""
	for _, name := range []string{"latest-execution.json", filepath.Join("transactions", execution.PlanID, "execution.json")} {
		writeJournalFile(t, filepath.Join(manager.StateRoot, name), execution)
	}
	if settled, err := manager.settleCommittedPublication(); err != nil || settled {
		t.Fatalf("interrupted commit gained an owner from matching metadata: %v, %v", settled, err)
	}
	if err := manager.CheckExecutionRecovery(context.Background()); !errors.Is(err, ErrExecutionJournal) {
		t.Fatalf("unowned publication lost its recovery fence: %v", err)
	}
}

func TestManagerCanceledDomainRecoveryReadLeavesRetainedJournal(t *testing.T) {
	const file = "latest-execution.json"
	r, retained, _ := standbyRetirementPublicationModel(t)
	manager := retained.scope.manager
	path := filepath.Join(manager.StateRoot, file)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := manager.CheckExecutionRecovery(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired observation lost its deadline: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		manager.retainedXrayOwner() != retained || retained.standby != r.owner {
		t.Fatalf("timed-out observation changed ownership or journal: %v", err)
	}
}
