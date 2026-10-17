package dataplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newMixedStopRetirementFixture(t *testing.T) *bootRetirementFixture {
	f := newBootRetirementFixture(t)
	nfq := NewNFQWS2Adapter()
	if err := f.m.Register(nfq); err != nil {
		t.Fatal(err)
	}
	previous, found, err := f.m.committedLocked()
	if err != nil || !found {
		t.Fatal(err)
	}
	previous.Adapters = []string{"nfqws2", "sing-box"}
	if err := f.m.Record(previous); err != nil {
		t.Fatal(err)
	}
	f.plan.Adapters = previous.Adapters
	if err := f.m.Record(f.plan); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	execution := Execution{PlanID: f.plan.PlanID, Digest: f.plan.Digest, State: "rollback-failed", StartedAt: now, FinishedAt: now}
	for _, s := range []struct{ a, p, state string }{{"nfqws2", "snapshot", "passed"}, {"sing-box", "snapshot", "passed"}, {"nfqws2", "deactivate", "passed"}, {"sing-box", "deactivate", "failed"}, {"sing-box", "rollback", "failed"}, {"nfqws2", "rollback", "passed"}, {"nfqws2", "verify-rollback", "failed"}, {"sing-box", "verify-rollback", "passed"}} {
		execution.Steps = append(execution.Steps, ExecutionStep{Adapter: s.a, Phase: s.p, State: s.state, StartedAt: now, FinishedAt: now})
	}
	if err := f.m.writeExecution(f.root, execution); err != nil {
		t.Fatal(err)
	}
	priorRoot := filepath.Join(f.m.StateRoot, "transactions", previous.PlanID)
	if err := f.m.prepareExecutionRoot(priorRoot); err != nil {
		t.Fatal(err)
	}
	prior := Execution{PlanID: previous.PlanID, Digest: previous.Digest, State: "committed", StartedAt: now, FinishedAt: now}
	raw, _ := json.Marshal(prior)
	inactiveWrite(t, filepath.Join(priorRoot, "execution.json"), raw)
	var snapshot proxySnapshot
	raw, err = os.ReadFile(filepath.Join(f.root, "sing-box", "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &snapshot)
	// The failed Stop happened on the NEW boot. Its committed generation is
	// still from the old boot; no snapshot boot or receipt is rewritten.
	snapshot.BootID = retirementNewBoot
	raw, _ = json.Marshal(snapshot)
	inactiveWrite(t, filepath.Join(f.root, "sing-box", "snapshot.json"), raw)
	raw, _ = json.Marshal(nfqws2Snapshot{WasRunning: true, ConfigExisted: true})
	inactiveWrite(t, filepath.Join(f.root, "nfqws2", "snapshot.json"), raw)
	if err := os.MkdirAll(filepath.Join(priorRoot, "sing-box"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeProxyPolicyReceipt(filepath.Join(priorRoot, "sing-box"), proxyPolicyReceipt{Schema: 1, Engine: "sing-box", Boot: retirementOldBoot, Digest: proxyPolicyDigest(snapshot.Policy), Phase: "complete", Generation: snapshot.PolicyBinding.Generation}); err != nil {
		t.Fatal(err)
	}
	return f
}

func runMixedStopFixture(f *bootRetirementFixture, absent func(context.Context) error, fault func(string) error) (Execution, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return f.m.retireFailedRollbackAfterBoot(ctx, f.plan.PlanID, f.plan.Digest, f.settings, func(Plan) error { return nil }, bootRetirementOptions{proof: &f.proof, nfqAbsent: absent, fault: fault})
}

func TestMixedStopBootRetirementPreservesUnknownHistoryAndRequiresFreshSources(t *testing.T) {
	f := newMixedStopRetirementFixture(t)
	if _, ok := f.m.reviewFailedRollback(f.plan.PlanID, f.plan.Digest); ok {
		t.Fatal("ordinary retry/close acquired failed-Deactivate lane")
	}
	nfq := newNFQWS2InactiveFixture(t)
	calls := 0
	absent := func(ctx context.Context) error { calls++; return nfq.verify(ctx) }
	original, err := os.ReadFile(filepath.Join(f.root, "execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	execution, err := runMixedStopFixture(f, absent, nil)
	if err != nil || execution.State != "rolled-back" || execution.RollbackVerified {
		t.Fatal(execution.State, execution.RollbackVerified, err)
	}
	if calls < 4 || nfq.reads < 4 {
		t.Fatal("NFQ absence was cached", calls, nfq.reads)
	}
	archive := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest)
	var manifest bootRetirementManifest
	raw, err := os.ReadFile(filepath.Join(archive, "manifest.json"))
	if err != nil || json.Unmarshal(raw, &manifest) != nil {
		t.Fatal(err)
	}
	if manifest.Schema != 2 || manifest.OldBoot != retirementOldBoot || !bytes.Equal(original, manifest.Evidence[filepath.Join("transactions", f.plan.PlanID, "execution.json")]) {
		t.Fatal("original history or old generation boot lost")
	}
	if f.processes.calls != 0 {
		t.Fatal("metadata retirement invoked runtime process controller")
	}
}

func TestMixedStopBootRetirementRefusesWithoutNFQAbsence(t *testing.T) {
	for _, mode := range []string{"missing-source", "live-process", "later-source-failure", "same-boot", "bad-committed-receipt", "resource-row", "wrong-forward-phase"} {
		t.Run(mode, func(t *testing.T) {
			f := newMixedStopRetirementFixture(t)
			calls := 0
			absent := func(context.Context) error { calls++; return nil }
			switch mode {
			case "missing-source":
				absent = nil
			case "live-process":
				absent = func(context.Context) error { return ErrNFQWSManagedProcessUnknown }
			case "later-source-failure":
				absent = func(context.Context) error {
					calls++
					if calls > 1 {
						return ErrNFQWSManagedProcessUnknown
					}
					return nil
				}
			case "same-boot":
				f.a.bootIdentity = func() (string, error) { return retirementOldBoot, nil }
			case "bad-committed-receipt":
				previous, _, _ := f.m.committedLocked()
				inactiveWrite(t, filepath.Join(f.m.StateRoot, "transactions", previous.PlanID, "sing-box", "policy-additions.json"), []byte("{}"))
			case "resource-row":
				// An unknown resource is never silently discarded by this lane.
				raw, _ := os.ReadFile(filepath.Join(f.root, "execution.json"))
				var e map[string]any
				_ = json.Unmarshal(raw, &e)
				e["resource_plan_id"] = "dp-3333333333333333"
				raw, _ = json.Marshal(e)
				inactiveWrite(t, filepath.Join(f.root, "execution.json"), raw)
				inactiveWrite(t, filepath.Join(f.m.StateRoot, "latest-execution.json"), raw)
			case "wrong-forward-phase":
				raw, _ := os.ReadFile(filepath.Join(f.root, "execution.json"))
				var e Execution
				_ = json.Unmarshal(raw, &e)
				e.Steps[3].Phase = "activate"
				_ = f.m.writeExecution(f.root, e)
			}
			result, err := runMixedStopFixture(f, absent, nil)
			if err == nil || result.State == "rolled-back" {
				t.Fatal("invalid history/source retired", result.State, err)
			}
			if f.processes.calls != 0 {
				t.Fatal("refusal invoked runtime mutation")
			}
		})
	}
}

func TestMixedStopBootRetirementPublicationCanResumeWithoutNewAuthority(t *testing.T) {
	f := newMixedStopRetirementFixture(t)
	crash := errors.New("fixture interruption")
	_, err := runMixedStopFixture(f, func(context.Context) error { return nil }, func(point string) error {
		if point == "publication-write:latest-execution.json" {
			return crash
		}
		return nil
	})
	if err == nil {
		t.Fatal("fault not injected")
	}
	result, err := runMixedStopFixture(f, func(context.Context) error { return nil }, nil)
	if err != nil || result.State != "rolled-back" || result.RollbackVerified {
		t.Fatal(result.State, err)
	}
}

func TestMixedStopBootRetirementArchivesCopiedOrphanAsEvidenceOnly(t *testing.T) {
	f := newMixedStopRetirementFixture(t)
	var doc policyAdditionDocument
	bound := filepath.Join(f.a.StateRoot, "policy-generations", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", policyAdditionFile)
	raw, err := os.ReadFile(bound)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &doc)
	orphan := filepath.Join(f.a.StateRoot, "policy-generations", "dddddddddddddddddddddddddddddddd")
	// Keep original root hash/id; copied metadata never becomes a new grant.
	inactiveWrite(t, filepath.Join(orphan, policyAdditionFile), raw)
	inactiveWrite(t, filepath.Join(orphan, policyAdditionLock), []byte(policyAdditionMarker))
	result, err := runMixedStopFixture(f, func(context.Context) error { return nil }, nil)
	if err != nil || result.State != "rolled-back" {
		t.Fatal(result.State, err)
	}
	archive := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest, "files", "sing-box", "policy-generations", filepath.Base(orphan), policyAdditionFile)
	got, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(raw, got) {
		t.Fatal("copied orphan evidence changed", err)
	}
}

func TestMixedStopBootRetirementRefusesTamperedBindingAndUnknownOrphanBoot(t *testing.T) {
	for _, mode := range []string{"bound-root", "orphan-boot", "orphan-checksum", "orphan-foreign-interface"} {
		t.Run(mode, func(t *testing.T) {
			f := newMixedStopRetirementFixture(t)
			path := filepath.Join(f.a.StateRoot, "policy-generations", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", policyAdditionFile)
			raw, _ := os.ReadFile(path)
			var doc policyAdditionDocument
			_ = json.Unmarshal(raw, &doc)
			if mode == "bound-root" {
				doc.RootHash = doc.PolicyHash
			} else {
				path = filepath.Join(f.a.StateRoot, "policy-generations", "dddddddddddddddddddddddddddddddd", policyAdditionFile)
				inactiveWrite(t, filepath.Join(filepath.Dir(path), policyAdditionLock), []byte(policyAdditionMarker))
				if mode == "orphan-boot" {
					doc.Boot = retirementNewBoot
				} else if mode == "orphan-foreign-interface" {
					doc.Steps[0].Add[4] = "nwg0"
					doc.Steps[0].Delete[4] = "nwg0"
				} else {
					doc.ID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
				}
			}
			if mode != "orphan-checksum" {
				doc.Checksum = policyAdditionChecksum(doc)
			}
			raw, _ = json.Marshal(doc)
			inactiveWrite(t, path, raw)
			if result, err := runMixedStopFixture(f, func(context.Context) error { return nil }, nil); err == nil || result.State == "rolled-back" {
				t.Fatal("tampered authority became archive permission", err)
			}
		})
	}
}

// Optional read-only replay of an operator-provided private evidence archive.
// It validates history/metadata only. It never extracts files, observes the
// local kernel, invokes runtime controllers or grants a router operation.
func TestMixedStopBootRetirementRetainedArchive(t *testing.T) {
	path := os.Getenv("RAZVILKA_TEST_STOP_RETIREMENT_ARCHIVE")
	if path == "" || runtime.GOOS != "linux" {
		t.Skip("explicit Linux private archive replay only")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open private archive", err)
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal("open archive gzip", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	images := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("read archive", err)
		}
		const prefix = "razvilka/state/dataplane/"
		if header.Typeflag != tar.TypeReg || !strings.HasPrefix(header.Name, prefix) {
			continue
		}
		name := strings.TrimPrefix(header.Name, prefix)
		if !filepath.IsLocal(name) || header.Size > bootRetirementLimit {
			t.Fatal("unsafe archived metadata")
		}
		raw, err := io.ReadAll(io.LimitReader(reader, bootRetirementLimit+1))
		if err != nil {
			t.Fatal("read metadata", err)
		}
		images[name] = raw
	}
	var execution Execution
	var plan, previous Plan
	if json.Unmarshal(images["latest-execution.json"], &execution) != nil || json.Unmarshal(images["latest-plan.json"], &plan) != nil || json.Unmarshal(images["latest-committed-plan.json"], &previous) != nil {
		t.Fatal("archived histories missing")
	}
	m := New("/opt/razvilka/state/dataplane")
	proxy, err := NewProxyTunnelAdapter("sing-box", nil, m.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(proxy); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(NewNFQWS2Adapter()); err != nil {
		t.Fatal(err)
	}
	var transaction Execution
	if json.Unmarshal(images[filepath.Join("transactions", plan.PlanID, "execution.json")], &transaction) != nil {
		t.Fatal("archived transaction missing")
	}
	reviewed, ok := m.reviewFailedRollbackImagesMode(plan.PlanID, plan.Digest, &execution, &transaction, plan, previous, true)
	if !ok || !mixedStopRetirementHistory(reviewed) {
		t.Fatal("archive not eligible intact failed Stop")
	}
	manifest := bootRetirementManifest{Schema: 2, PlanID: plan.PlanID, Digest: plan.Digest, CurrentBoot: retirementNewBoot, Evidence: map[string][]byte{}, Files: map[string][]byte{}}
	for _, name := range mixedStopRetirementEvidence(reviewed) {
		manifest.Evidence[name] = images[name]
	}
	for _, path := range bootRetirementRuntimePaths(proxy) {
		name, _ := filepath.Rel(m.StateRoot, path)
		if raw, ok := images[name]; ok {
			manifest.Files[name] = raw
		}
	}
	for name, raw := range images {
		if strings.HasPrefix(name, "sing-box/policy-generations/") {
			manifest.Files[name] = raw
		}
	}
	var binding proxyPolicyBinding
	var doc policyAdditionDocument
	if json.Unmarshal(manifest.Files["sing-box/policy-generation.json"], &binding) != nil || json.Unmarshal(manifest.Files[filepath.Join("sing-box", "policy-generations", binding.Generation, policyAdditionFile)], &doc) != nil {
		t.Fatal("archive binding missing")
	}
	manifest.OldBoot = doc.Boot
	if err := validateMixedStopRetirement(proxy, reviewed, manifest); err != nil {
		t.Fatal("archived metadata eligibility refused", err)
	}
	t.Logf("private archive metadata eligible: evidence=%d files=%d; no runtime absence or live action proved", len(manifest.Evidence), len(manifest.Files))
}

func TestMixedStopBootRetirementNFQInventoryMutationKeepsFence(t *testing.T) {
	f := newMixedStopRetirementFixture(t)
	nfq := newNFQWS2InactiveFixture(t)
	calls := 0
	result, err := runMixedStopFixture(f, func(ctx context.Context) error {
		calls++
		if calls > 1 {
			nfq.image.Rows = append(nfq.image.Rows, nfqwsDirectStockTestRow(4, "mangle", "-N", "RZQ_orphan"))
		}
		return nfq.verify(ctx)
	}, nil)
	if err == nil || result.State == "rolled-back" || calls < 2 {
		t.Fatal("fresh inventory ownership mutation cleared fence", result.State, calls, err)
	}
	if check := f.m.CheckExecutionRecovery(context.Background()); check == nil {
		t.Fatal("failed publication cleared durable fence")
	}
}

func TestMixedStopBootRetirementManifestDurableBeforePublicationAndWriteFailureKeepsFence(t *testing.T) {
	f := newMixedStopRetirementFixture(t)
	interrupted := false
	result, err := runMixedStopFixture(f, func(context.Context) error { return nil }, func(point string) error {
		if point != "publication-intent" {
			return nil
		}
		archive := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest)
		raw, err := os.ReadFile(filepath.Join(archive, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		var manifest bootRetirementManifest
		if json.Unmarshal(raw, &manifest) != nil || manifest.Checksum != bootRetirementChecksum(manifest) || len(manifest.Evidence) != 8 || len(manifest.Files) == 0 {
			t.Fatal("original bytes not archived before publication")
		}
		interrupted = true
		return errors.New("fixture journal write failed")
	})
	if !interrupted || err == nil || result.State == "rolled-back" {
		t.Fatal("write failure reported retirement", result.State, err)
	}
	if check := f.m.CheckExecutionRecovery(context.Background()); check == nil {
		t.Fatal("write failure cleared fence")
	}
}

func TestMixedStopBootRetirementPublicationRefusesTargetMutationDuringAbsence(t *testing.T) {
	for _, mode := range []string{"different-bytes", "same-bytes-new-inode"} {
		t.Run(mode, func(t *testing.T) {
			f := newMixedStopRetirementFixture(t)
			target := filepath.Join(f.root, "execution.json")
			original, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			foreign := []byte("foreign publication image")
			if mode == "same-bytes-new-inode" {
				foreign = original
			}
			calls := 0
			result, err := runMixedStopFixture(f, func(context.Context) error {
				calls++
				if calls == 2 {
					if mode == "different-bytes" {
						inactiveWrite(t, target, foreign)
					} else {
						replacement := target + ".replacement"
						inactiveWrite(t, replacement, foreign)
						root, err := os.OpenRoot(f.root)
						if err != nil {
							t.Fatal(err)
						}
						err = root.Rename(filepath.Base(replacement), filepath.Base(target))
						_ = root.Close()
						if err != nil {
							t.Fatal("replace held target", err)
						}
					}
				}
				return nil
			}, nil)
			if err == nil || result.State == "rolled-back" || calls < 2 {
				t.Fatal("mutation across absence accepted", result.State, calls, err)
			}
			got, readErr := os.ReadFile(target)
			if readErr != nil || !bytes.Equal(got, foreign) {
				t.Fatal("foreign target overwritten", readErr)
			}
			if f.m.CheckExecutionRecovery(context.Background()) == nil {
				t.Fatal("mutation cleared recovery fence")
			}
		})
	}
}

func TestMixedStopBootRetirementCommittedExecutionMutationDuringAbsenceRefusesBeforeArchive(t *testing.T) {
	f := newMixedStopRetirementFixture(t)
	previous, _, _ := f.m.committedLocked()
	target := filepath.Join(f.m.StateRoot, "transactions", previous.PlanID, "execution.json")
	foreign := []byte("changed committed provenance")
	result, err := runMixedStopFixture(f, func(context.Context) error { inactiveWrite(t, target, foreign); return nil }, nil)
	if err == nil || result.State == "rolled-back" {
		t.Fatal("immutable committed execution drift accepted", result.State, err)
	}
	archive := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest, "manifest.json")
	if _, err := os.Stat(archive); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale provenance published manifest", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, foreign) {
		t.Fatal("committed provenance overwritten", err)
	}
	if f.m.CheckExecutionRecovery(context.Background()) == nil {
		t.Fatal("provenance drift cleared recovery fence")
	}
}
