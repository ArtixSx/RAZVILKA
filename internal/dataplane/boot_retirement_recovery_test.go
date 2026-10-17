package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func retiredBootRecoveryFixture(t *testing.T) (*bootRetirementFixture, *fakeAdapter, string) {
	f := newMixedStopRetirementFixture(t)
	result, err := runMixedStopFixture(f, func(context.Context) error { return nil }, nil)
	if err != nil || result.State != "rolled-back" {
		t.Fatal("prepare original retirement", err)
	}
	nfq := &fakeAdapter{id: "nfqws2"}
	f.m.Adapters["nfqws2"] = nfq
	archive := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest)
	return f, nfq, archive
}

func TestBootRetirementRecoverRequiresFreshPlanWithoutHistoricalReconcile(t *testing.T) {
	f, nfq, _ := retiredBootRecoveryFixture(t)
	profiles := 0
	f.m.FreshProfile = func(context.Context) (string, error) { profiles++; return "wan-ffffffffffff", nil }
	before := proxyRollbackRetryFiles(t, f.m.StateRoot)
	for i := 0; i < 2; i++ {
		recovery, err := f.m.Recover(context.Background())
		if err != nil || recovery.State != "fresh-plan-required" || recovery.Guarded || recovery.PlanID != f.plan.PlanID {
			t.Fatal("retired plan not settled for fresh review", recovery, err)
		}
	}
	changed, err := f.m.RefreshCommitted(context.Background())
	if err != nil || len(changed) != 0 || profiles != 0 || len(nfq.calls) != 0 || f.processes.calls != 0 {
		t.Fatal("historical runtime replayed", profiles, nfq.calls, err)
	}
	after := proxyRollbackRetryFiles(t, f.m.StateRoot)
	delete(after, "0/latest-recovery.json")
	delete(before, "0/latest-recovery.json")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("startup rewrote original retired history")
	}
}

func TestBootRetirementRecoverKeepsHistoricalPlanRetiredAcrossPreviewAndFailedFreshApply(t *testing.T) {
	for _, mode := range []string{"preview", "failed-fresh-apply"} {
		t.Run(mode, func(t *testing.T) {
			f, nfq, _ := retiredBootRecoveryFixture(t)
			fresh := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-3333333333333333", Digest: strings.Repeat("3", 64), Adapters: []string{"nfqws2"}, State: "planned"}
			if mode == "failed-fresh-apply" {
				fresh.State = "rolled-back"
			}
			if err := f.m.Record(fresh); err != nil {
				t.Fatal(err)
			}
			if mode == "failed-fresh-apply" {
				root := filepath.Join(f.m.StateRoot, "transactions", fresh.PlanID)
				if err := f.m.prepareExecutionRoot(root); err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC().Format(time.RFC3339Nano)
				e := Execution{PlanID: fresh.PlanID, Digest: fresh.Digest, State: "rolled-back", StartedAt: now, FinishedAt: now, Steps: []ExecutionStep{{Adapter: "nfqws2", Phase: "activate", State: "failed", StartedAt: now, FinishedAt: now}}}
				if err := f.m.writeExecution(root, e); err != nil {
					t.Fatal(err)
				}
			}
			recovery, err := f.m.Recover(context.Background())
			if err != nil || recovery.State != "fresh-plan-required" || recovery.Guarded || len(nfq.calls) != 0 {
				t.Fatal("preview/failed fresh Apply revived history", recovery, nfq.calls, err)
			}
			latest, _, _ := f.m.Latest()
			if latest.PlanID != fresh.PlanID {
				t.Fatal("fresh user plan overwritten")
			}
		})
	}
}

func TestBootRetirementRecoverRefusesMissingOrTamperedProofWithoutRuntimeEffects(t *testing.T) {
	for _, mode := range []string{"missing-manifest", "missing-publication", "manifest-checksum", "publication-checksum", "missing-witness", "witness-binding", "archive-bytes", "restored-source", "terminal-not-passed"} {
		t.Run(mode, func(t *testing.T) {
			f, nfq, archive := retiredBootRecoveryFixture(t)
			switch mode {
			case "missing-manifest", "missing-publication":
				name := "manifest.json"
				if mode == "missing-publication" {
					name = "publication.json"
				}
				if err := os.Remove(filepath.Join(archive, name)); err != nil {
					t.Fatal(err)
				}
			case "manifest-checksum":
				inactiveWrite(t, filepath.Join(archive, "manifest.json"), []byte("{}"))
			case "publication-checksum":
				inactiveWrite(t, filepath.Join(archive, "publication.json"), []byte("{}"))
			case "missing-witness", "witness-binding":
				name := filepath.Join(archive, "observations", retirementNewBoot+".json")
				if mode == "missing-witness" {
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				} else {
					inactiveWrite(t, name, []byte("{}"))
				}
			case "archive-bytes":
				inactiveWrite(t, filepath.Join(archive, "files", "sing-box", "policy.json"), []byte("changed"))
			case "restored-source":
				raw, err := os.ReadFile(filepath.Join(archive, "files", "sing-box", "policy.json"))
				if err != nil {
					t.Fatal(err)
				}
				inactiveWrite(t, f.a.policyPath(), raw)
			case "terminal-not-passed":
				var p bootRetirementPublication
				raw, _ := os.ReadFile(filepath.Join(archive, "publication.json"))
				_ = json.Unmarshal(raw, &p)
				var e Execution
				_ = json.Unmarshal(p.After["latest-execution.json"], &e)
				e.Steps[len(e.Steps)-1].State = "failed"
				raw, _ = json.Marshal(e)
				p.After["latest-execution.json"], p.After[filepath.Join("transactions", f.plan.PlanID, "execution.json")] = raw, raw
				p.Checksum = bootPublicationChecksum(p)
				encoded, _ := json.Marshal(p)
				inactiveWrite(t, filepath.Join(archive, "publication.json"), encoded)
				inactiveWrite(t, filepath.Join(f.root, "execution.json"), raw)
				inactiveWrite(t, filepath.Join(f.m.StateRoot, "latest-execution.json"), raw)
			}
			recovery, err := f.m.Recover(context.Background())
			if !errors.Is(err, ErrExecutionJournal) || recovery.State != "journal-recovery-required" || !recovery.Guarded || len(nfq.calls) != 0 || f.processes.calls != 0 {
				t.Fatal("uncertain retirement replayed old runtime", recovery, nfq.calls, err)
			}
			if _, err := f.m.RefreshCommitted(context.Background()); !errors.Is(err, ErrExecutionJournal) {
				t.Fatal("refresh ignored damaged retirement proof", err)
			}
		})
	}
}

func TestBootRetirementRecoverAllowsGenuineFreshCommittedPlan(t *testing.T) {
	f, nfq, _ := retiredBootRecoveryFixture(t)
	fresh := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-3333333333333333", Digest: strings.Repeat("3", 64), Adapters: []string{"nfqws2"}, State: "committed"}
	if err := f.m.Record(fresh); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(f.m.StateRoot, "transactions", fresh.PlanID)
	if err := f.m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := f.m.writeExecution(root, Execution{PlanID: fresh.PlanID, Digest: fresh.Digest, State: "committed", StartedAt: now, FinishedAt: now}); err != nil {
		t.Fatal(err)
	}
	recovery, err := f.m.Recover(context.Background())
	if err != nil || recovery.State != "recovered" || !nfq.recovered || recovery.PlanID != fresh.PlanID {
		t.Fatal("old archive fenced genuine fresh commit", recovery, nfq.calls, err)
	}
}

func TestBootRetirementRecoverNeverTrustsProseAsProof(t *testing.T) {
	f, nfq, archive := retiredBootRecoveryFixture(t)
	raw, err := os.ReadFile(filepath.Join(archive, "publication.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p bootRetirementPublication
	_ = json.Unmarshal(raw, &p)
	var e Execution
	_ = json.Unmarshal(p.After["latest-execution.json"], &e)
	e.Steps = e.Steps[:len(e.Steps)-1]
	e.Error = "retired-after-boot" // Text remains, but the attested terminal record changed.
	raw, _ = json.Marshal(e)
	inactiveWrite(t, filepath.Join(f.root, "execution.json"), raw)
	inactiveWrite(t, filepath.Join(f.m.StateRoot, "latest-execution.json"), raw)
	recovery, err := f.m.Recover(context.Background())
	if err == nil || !recovery.Guarded || len(nfq.calls) != 0 {
		t.Fatal("prose bypassed missing attested terminal step", recovery, err)
	}
	if bytes.Equal(raw, p.After["latest-execution.json"]) {
		t.Fatal("fixture did not change attested record")
	}
}
