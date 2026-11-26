package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func TestAppliedNodeRecoverySameNetworkRepairsMissingOwnedRuntime(t *testing.T) {
	a, id, adapter, checker, previous := nodeRecoveryFixture(t)
	a.FreshProfile = func(context.Context) (string, error) { return previous.NetworkProfileID, nil }
	a.Dataplane.FreshProfile = a.FreshProfile
	missing := true
	adapter.observe = func(context.Context) error {
		if missing {
			return errors.New("owned process absent")
		}
		return nil
	}
	adapter.after = func(phase string) error {
		if phase == "commit" {
			missing = false
		}
		return nil
	}
	before := a.Store.Get()
	a.nodeRecoveryRound(context.Background(), time.Now())
	current, _, err := a.Dataplane.Committed()
	if err != nil || a.nodeRecoverySnapshot().State != "recovered" || missing || current.State != "committed" {
		t.Fatalf("same WAN hid missing runtime: %+v err=%v", a.nodeRecoverySnapshot(), err)
	}
	if len(checker.requests) != 1 || checker.requests[0].NodeID != id || checker.requests[0].NetworkProfile != previous.NetworkProfileID || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(previous.Routes, current.Routes) {
		t.Fatal("repair changed endpoint/scope/settings or skipped fresh check")
	}
	if strings.Join(adapter.calls, ",") != "snapshot,stage,validate,canary,activate,health,commit" {
		t.Fatal(adapter.calls)
	}
	a.nodeRecoveryRound(context.Background(), time.Now().Add(2*time.Minute))
	if len(checker.requests) != 1 {
		t.Fatal("healthy owned runtime was reapplied")
	}
}

func TestAppliedNodeRecoveryObservationTimeoutIsNotAbsence(t *testing.T) {
	for _, observation := range []error{context.DeadlineExceeded, context.Canceled} {
		t.Run(observation.Error(), func(t *testing.T) {
			a, _, adapter, checker, previous := nodeRecoveryFixture(t)
			a.FreshProfile = func(context.Context) (string, error) { return previous.NetworkProfileID, nil }
			a.Dataplane.FreshProfile = a.FreshProfile
			adapter.observe = func(context.Context) error { return observation }
			before := a.Store.Get()
			a.nodeRecoveryRound(context.Background(), time.Now())
			current, _, _ := a.Dataplane.Committed()
			if len(checker.requests) != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(current, previous) || !reflect.DeepEqual(before, a.Store.Get()) {
				t.Fatal("unknown observation restarted runtime")
			}
		})
	}
}

func TestAppliedNodeRecoveryMissingRuntimeFailurePreservesNodeAndRetryBudget(t *testing.T) {
	a, _, adapter, checker, previous := nodeRecoveryFixture(t)
	a.FreshProfile = func(context.Context) (string, error) { return previous.NetworkProfileID, nil }
	a.Dataplane.FreshProfile = a.FreshProfile
	adapter.observe = func(context.Context) error { return errors.New("missing runtime") }
	checker.fail = true
	before := a.Store.Get()
	now := time.Now()
	for _, after := range []time.Duration{0, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 6 * time.Minute} {
		a.nodeRecoveryRound(context.Background(), now.Add(after))
	}
	status := a.nodeRecoverySnapshot()
	if status.State != "requires-review" || status.Reason != "service-unconfirmed" || status.FailedStage != "checks" || len(checker.requests) != 3 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) {
		t.Fatalf("unbounded or hidden failed repair: %+v calls=%v", status, adapter.calls)
	}
	current, _, _ := a.Dataplane.Committed()
	if !reflect.DeepEqual(previous, current) {
		t.Fatal("failed check rewrote applied authority")
	}
}

func TestNodeRecoveryReasonsNeverExposeRawFailure(t *testing.T) {
	secret := errors.New("private-profile://credential@host")
	for _, test := range []struct {
		err         error
		state, want string
	}{
		{secret, "", "operation-unconfirmed"},
		{errors.Join(secret, context.DeadlineExceeded), "", "deadline"},
		{errors.Join(secret, dataplane.ErrExactNodeNetworkChanged), "", "network-unconfirmed"},
		{secret, "rollback-failed", "cleanup-unconfirmed"},
		{errors.Join(secret, dataplane.ErrExactNodeBusy), "", "checker-busy"},
	} {
		if got := nodeRecoveryReason(test.err, dataplane.Execution{State: test.state}); got != test.want {
			t.Fatalf("unsafe reason %q", got)
		}
	}
}
