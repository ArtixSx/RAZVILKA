package dataplane

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func restoredNFQWS2HookRetryFixture(t *testing.T) (*nfqws2HookFixture, Plan, Plan, string) {
	t.Helper()
	h := newNFQWS2HookFixture(t, false)
	previous := h.committed(t)
	failed := previous
	failed.PlanID, failed.Digest, failed.State = "dp-2222222222222222", strings.Repeat("2", 64), "rollback-failed"
	root := filepath.Join(h.m.StateRoot, "transactions", failed.PlanID)
	if err := h.m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "nfqws2"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := h.a.Snapshot(firstStartContext(t), failed, filepath.Join(root, "nfqws2")); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Record(failed); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	execution := Execution{PlanID: failed.PlanID, Digest: failed.Digest, State: "rollback-failed", StartedAt: now, FinishedAt: now}
	for _, step := range [][2]string{{"snapshot", "passed"}, {"stage", "passed"}, {"activate", "failed"}, {"rollback", "failed"}, {"verify-rollback", "failed"}} {
		execution.Steps = append(execution.Steps, ExecutionStep{Adapter: "nfqws2", Phase: step[0], State: step[1], StartedAt: now, FinishedAt: now})
	}
	if err := h.m.writeExecution(root, execution); err != nil {
		t.Fatal(err)
	}
	return h, previous, failed, root
}

func TestNFQWS2RollbackRetryRestoresAlreadyRunningHooks(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, mode := range []string{"complete-loss", "mangle-loss", "full"} {
		t.Run(mode, func(t *testing.T) {
			h, previous, failed, _ := restoredNFQWS2HookRetryFixture(t)
			if mode == "complete-loss" {
				h.kernel = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)
			}
			if mode == "mangle-loss" {
				h.lose(t, 4)
			}
			before, calls := h.files(t), len(h.calls)
			lease, err := h.a.readLease()
			if err != nil {
				t.Fatal(err)
			}
			result, err := h.m.RetryFailedRollback(firstStartContext(t), failed.PlanID, failed.Digest, func(p Plan) error {
				if !reflect.DeepEqual(p, previous) {
					return ErrReviewChanged
				}
				return nil
			})
			if err != nil || result.State != "rolled-back" || !result.RollbackVerified || h.m.checkExecutionRecovery() != nil {
				t.Fatal("canonical retry did not restore missing hooks", result, err)
			}
			if !nfqws2HookSameRows(h.kernel.rows(), h.fullKernel(t).rows()) {
				t.Fatal("canonical retry changed the foreign graph or did not restore the exact owned graph")
			}
			after, err := h.a.readLease()
			if err != nil || !reflect.DeepEqual(lease, after) {
				t.Fatal("hook repair changed the live lease or process receipt", err)
			}
			h.assertFiles(t, before)
			for _, call := range h.calls[calls:] {
				if firstStartRuntimeAction(call) {
					t.Fatal("already-running rollback restarted the process", call)
				}
			}
			want := map[string]int{"complete-loss": 14, "mangle-loss": 12, "full": 0}[mode]
			if len(h.writes) != want {
				t.Fatal("unexpected hook writes", len(h.writes), want)
			}
		})
	}
}

func TestNFQWS2RollbackHookRepairRequiresOriginalDurableIntent(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	h, _, failed, root := restoredNFQWS2HookRetryFixture(t)
	h.kernel = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)
	if err := h.a.Rollback(firstStartContext(t), failed, filepath.Join(root, "nfqws2")); err != nil {
		t.Fatal(err)
	}
	if len(h.writes) != 0 {
		t.Fatal("ordinary adapter call obtained journal writer authority")
	}
	if confirmed, err := h.a.VerifyRollback(firstStartContext(t), failed, filepath.Join(root, "nfqws2")); err == nil || confirmed {
		t.Fatal("unchanged verifier accepted absent hooks")
	}
}

func TestNFQWS2RollbackHookRepairRetainsFenceOnForeignOrDrift(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, mode := range []string{"foreign-partial", "guard", "journal-drift", "unacknowledged-write"} {
		t.Run(mode, func(t *testing.T) {
			h, _, failed, _ := restoredNFQWS2HookRetryFixture(t)
			h.kernel = newNFQWS2HookKernel(t, nfqws2HookWithoutOwned(nfqws2HookFullV4()), nfqws2RouterIPv6Fixture)
			guard := func(Plan) error { return nil }
			switch mode {
			case "foreign-partial":
				if err := h.kernel.apply(4, []string{"-t", "nat", "-N", "nfqws_nat"}); err != nil {
					t.Fatal(err)
				}
			case "guard":
				guard = func(Plan) error { return ErrReviewChanged }
			case "journal-drift":
				h.beforeRead = func(n int) {
					if n != 1 {
						return
					}
					path := filepath.Join(h.m.StateRoot, "latest-execution.json")
					raw, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					var execution Execution
					if err := json.Unmarshal(raw, &execution); err != nil {
						t.Fatal(err)
					}
					execution.Error += " foreign observation change"
					raw, _ = json.Marshal(execution)
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "unacknowledged-write":
				h.beforeWrite = func(n, family int, args []string) error {
					if n == 1 {
						if err := h.kernel.apply(family, args); err != nil {
							t.Fatal(err)
						}
						return errors.New("modeled lost response")
					}
					return nil
				}
			}
			before := h.kernel.rows()
			result, err := h.m.RetryFailedRollback(firstStartContext(t), failed.PlanID, failed.Digest, guard)
			if err == nil || result.State == "rolled-back" || h.m.checkExecutionRecovery() == nil {
				t.Fatal("uncertain repair closed the journal fence", result, err)
			}
			if mode != "unacknowledged-write" && (len(h.writes) != 0 || !nfqws2HookSameRows(before, h.kernel.rows())) {
				t.Fatal("foreign graph or revoked intent reached a hook effect")
			}
			if mode == "unacknowledged-write" && len(h.writes) != 1 {
				t.Fatal("unknown effect was adopted or cleaned", h.writes)
			}
		})
	}
}
