package app

import (
	"context"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
)

func maintenanceFixture(t *testing.T) (*App, autonomy.Policy, time.Time) {
	a := autonomyAPIFixture(t)
	p := saveAutonomyFixturePolicy(t, a)
	p.Application = autonomy.Window{Mode: "check", Start: "00:00", End: "23:59", Days: []int{0, 1, 2, 3, 4, 5, 6}}
	p.Components.Mode = "off"
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy = p
	if a.persistAutonomyLocked(context.Background()) != nil {
		t.Fatal("persist")
	}
	a.autonomy.mu.Unlock()
	return a, p, time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
}
func TestRepair2MaintenanceRetryDoesNotConsumeWindowOnFailure(t *testing.T) {
	a, p, now := maintenanceFixture(t)
	calls := 0
	a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
		calls++
		return calls >= 2, false, "test"
	}
	a.autonomyMaintenance(context.Background(), p, now)
	if a.autonomy.doc.Maintenance["application"] != "" {
		t.Fatal("failed task closed window")
	}
	a.autonomyMaintenance(context.Background(), p, now.Add(30*time.Second))
	if calls != 1 {
		t.Fatal("no backoff")
	}
	a.autonomyMaintenance(context.Background(), p, now.Add(time.Minute))
	if calls != 2 || a.autonomy.doc.Maintenance["application"] == "" {
		t.Fatal("not retried/completed")
	}
	a.autonomyMaintenance(context.Background(), p, now.Add(10*time.Minute))
	if calls != 2 {
		t.Fatal("duplicate success")
	}
	fresh := &App{Store: a.Store, Catalog: a.Catalog}
	if fresh.loadAutonomy(context.Background()) != nil || fresh.autonomy.doc.Maintenance["application"] == "" {
		t.Fatal("completion lost")
	}
}
func TestRepair2MaintenanceAttemptsBoundedAndPendingDoesNotRestart(t *testing.T) {
	for _, pending := range []bool{false, true} {
		a, p, now := maintenanceFixture(t)
		calls, launches := 0, 0
		a.autonomy.maintenanceTestRun = func(_ context.Context, _ string, _ autonomy.Window, wasPending bool) (bool, bool, string) {
			calls++
			if !wasPending {
				launches++
			}
			return pending && calls == 5, pending && calls < 5, "test"
		}
		for i := 0; i < 6; i++ {
			a.autonomyMaintenance(context.Background(), p, now.Add(time.Duration(i)*5*time.Minute))
		}
		if pending {
			if calls != 5 || launches != 1 {
				t.Fatal("pending consumed attempts or restarted", calls, launches)
			}
		} else if calls != 3 || launches != 3 {
			t.Fatal("unbounded retries", calls)
		}
	}
}
func TestRepair2MaintenanceRunsBeforeContinuouslyDueService(t *testing.T) {
	a, _, _ := autonomousIntegrationFixture(t)
	p := a.autonomyPolicy()
	p.Application = autonomy.Window{Mode: "check", Start: "00:00", End: "23:59", Days: []int{0, 1, 2, 3, 4, 5, 6}}
	p.Components.Mode = "off"
	a.autonomy.mu.Lock()
	a.autonomy.doc.Policy = p
	if a.persistAutonomyLocked(context.Background()) != nil {
		t.Fatal("persist")
	}
	a.autonomy.mu.Unlock()
	calls := 0
	a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
		calls++
		return true, false, "test"
	}
	autonomyTestDue(a, false)
	a.autonomyRound(context.Background(), time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC))
	if calls != 1 {
		t.Fatal("due service starved maintenance", calls)
	}
}
func TestRepair2CancelledMaintenanceCannotPersistSuccess(t *testing.T) {
	a, p, now := maintenanceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	a.autonomy.maintenanceTestRun = func(context.Context, string, autonomy.Window, bool) (bool, bool, string) {
		cancel()
		return true, false, "test"
	}
	a.autonomyMaintenance(ctx, p, now)
	if a.autonomy.doc.Maintenance["application"] != "" {
		t.Fatal("cancel wrote completion")
	}
}
