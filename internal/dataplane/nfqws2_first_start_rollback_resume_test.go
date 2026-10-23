package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func firstStartInterruptedRollbackFixture(t *testing.T) (*firstStartFixture, *nfqws2Lease) {
	t.Helper()
	f := newFirstStartFixture(t)
	f.plan.PlanID = "dp-1111111111111111"
	f.apply(t)
	prior, err := f.a.readLease()
	if err != nil || prior == nil {
		t.Fatal("prior running lease missing", err)
	}
	f.plan.PlanID, f.plan.Digest = "dp-2222222222222222", strings.Repeat("b", 64)
	f.plan.Routes[0].Domains = []string{"failed.example"}
	f.a.HealthProbe = func(context.Context, string) error { return errors.New("modeled candidate health failure") }
	observe := f.a.firstStartObservation
	interrupted := false
	f.a.firstStartObservation = func(ctx context.Context, full bool) error {
		lease, err := f.a.readLease()
		if err != nil {
			return err
		}
		if !interrupted && lease != nil && lease.Transaction == prior.Transaction && lease.FirstStart.Phase == nfqws2FirstStopped {
			interrupted = true
			return errors.New("modeled absence refusal after prior lease restoration")
		}
		return observe(ctx, full)
	}
	failed, err := f.m.Apply(firstStartContext(t), f.plan, nil)
	if err == nil || failed.State != "rollback-failed" || !interrupted {
		t.Fatal("real rollback did not reach its interrupted prior restart", failed.State, err, interrupted)
	}
	stopped, err := f.a.readLease()
	expected := *prior
	first := *prior.FirstStart
	first.Phase = nfqws2FirstStopped
	expected.FirstStart = &first
	if err != nil || !reflect.DeepEqual(stopped, &expected) || f.running || f.ownedRules {
		t.Fatal("interrupted rollback did not retain the exact prior stopped lease", err)
	}
	if f.a.firstStartReview != nil {
		t.Fatal("retry must acquire its own native review after Apply releases it")
	}
	f.a.firstStartObservation = observe
	return f, prior
}

// Exercise the actual first-start Apply/rollback/retry sequence. Only native
// command/process/kernel leaves use the established isolated consumer model.
func TestNFQWS2FirstStartRollbackRetryResumesStoppedPriorLease(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f, prior := firstStartInterruptedRollbackFixture(t)
	result, err := f.m.RetryFailedRollback(firstStartContext(t), f.plan.PlanID, f.plan.Digest, func(Plan) error { return nil })
	if err != nil || result.State != "rolled-back" || !result.RollbackVerified {
		t.Fatal("retry did not finish the interrupted prior restart", result.State, err)
	}
	lease, err := f.a.readLease()
	if err != nil || lease == nil || !nfqws2RollbackLeaseEqual(lease, prior) || lease.FirstStart.Process == nil || *lease.FirstStart.Process == *prior.FirstStart.Process || !f.running || !f.ownedRules {
		t.Fatal("restored prior runtime lacks a fresh original process receipt", err)
	}
	if f.a.firstStartReview != nil {
		t.Fatal("retry leaked the finite native review")
	}
	f.assertWriterReleased(t)
}

func TestNFQWS2FirstStartRollbackResumeMatchesOnlyExactPriorStoppedLease(t *testing.T) {
	for _, which := range []string{"exact", "not-first-start", "snapshot-stopped", "snapshot-not-running", "process", "owner", "transaction", "config", "list", "starting", "retiring"} {
		t.Run(which, func(t *testing.T) {
			f := firstStartStoppedInactiveFixture(t)
			lease, err := f.a.readLease()
			if err != nil || lease == nil {
				t.Fatal(err)
			}
			before, first := *lease, *lease.FirstStart
			first.Phase = nfqws2FirstRunning
			before.FirstStart = &first
			snapshot := nfqws2Snapshot{FirstStart: true, WasRunning: true, Lease: &before}
			switch which {
			case "not-first-start":
				snapshot.FirstStart = false
			case "snapshot-stopped":
				before.FirstStart.Phase = nfqws2FirstStopped
			case "snapshot-not-running":
				snapshot.WasRunning = false
			case "process":
				process := *lease.FirstStart.Process
				process.Start = "changed"
				lease.FirstStart.Process = &process
			case "owner":
				lease.Owner = strings.Repeat("f", 24)
			case "transaction":
				lease.Transaction += "-other"
			case "config":
				lease.ConfigHash = strings.Repeat("f", 64)
			case "list":
				lease.Lists[0].BlockHash = strings.Repeat("f", 64)
			case "starting", "retiring":
				lease.FirstStart.Phase = which
			}
			if got := nfqws2FirstStartRollbackResumeMatches(lease, snapshot); got != (which == "exact") {
				t.Fatal("recovery admission accepted drift or rejected the exact stopped prior lease", which, got)
			}
			if which == "exact" && nfqws2RollbackLeaseEqual(lease, snapshot.Lease) {
				t.Fatal("stopped admission weakened the strict running rollback comparison")
			}
		})
	}
}

func TestNFQWS2FirstStartRollbackRetryRefusesChangedOrUnknownPriorRuntime(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"lease-process", "lease-phase", "config", "list", "run", "pid", "foreign-process", "missing-source", "missing-native-owner", "native-failure", "native-file-drift", "late-foreign-process"} {
		t.Run(which, func(t *testing.T) {
			f, _ := firstStartInterruptedRollbackFixture(t)
			switch which {
			case "lease-process", "lease-phase":
				lease, err := f.a.readLease()
				if err != nil {
					t.Fatal(err)
				}
				if which == "lease-process" {
					lease.FirstStart.Process.Start = "999"
				} else {
					lease.FirstStart.Phase = nfqws2FirstRetiring
				}
				if err := f.a.writeLease(lease); err != nil {
					t.Fatal(err)
				}
			case "config":
				writeStockText(t, f.a.ConfigPath, readText(t, f.a.ConfigPath)+"# foreign edit\n")
			case "list":
				path := f.a.ownedListPaths()[0]
				writeStockText(t, path, readText(t, path)+"foreign.example\n")
			case "run":
				writeStockText(t, f.a.ConfigPath+".run", "foreign overlay\n")
			case "pid":
				if err := os.MkdirAll(filepath.Dir(f.a.firstStartPIDPath()), 0700); err != nil {
					t.Fatal(err)
				}
				writeStockText(t, f.a.firstStartPIDPath(), "999\n")
			case "foreign-process":
				f.foreign = true
			case "missing-source":
				f.a.firstStartObservation = nil
			case "missing-native-owner":
				f.a.stockNativeOwner = nil
			case "native-failure":
				f.runner.nativeErr = errors.New("modeled fresh native failure")
			case "native-file-drift":
				f.runner.onNative = func() { writeStockText(t, f.a.ConfigPath, readText(t, f.a.ConfigPath)+"# slow-boundary drift\n") }
			case "late-foreign-process":
				f.runner.onNative = func() { f.foreign = true }
			}
			before, err := f.a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			calls := len(f.calls)
			result, err := f.m.RetryFailedRollback(firstStartContext(t), f.plan.PlanID, f.plan.Digest, func(Plan) error { return nil })
			if err == nil || result.State != "rollback-failed" || result.RollbackVerified {
				t.Fatal("changed or unknown prior state lost its fence", which, result.State, err)
			}
			for _, call := range f.calls[calls:] {
				if firstStartRuntimeAction(call) {
					t.Fatal("refused prior runtime reached an init lifecycle action", which, call)
				}
			}
			after, readErr := f.a.readLease()
			if readErr != nil || !reflect.DeepEqual(before, after) || f.running || f.ownedRules || f.a.firstStartReview != nil {
				t.Fatal("refusal changed or revived the prior process metadata", which, readErr)
			}
			f.assertWriterReleased(t)
		})
	}
}
