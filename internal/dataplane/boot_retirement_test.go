package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const retirementOldBoot = "11111111-1111-1111-1111-111111111111"
const retirementNewBoot = "22222222-2222-2222-2222-222222222222"

type bootRetirementFixture struct {
	*inactiveFixture
	m        *Manager
	plan     Plan
	settings string
	root     string
	original map[string][]byte
}

func newBootRetirementFixture(t *testing.T) *bootRetirementFixture {
	t.Helper()
	f := newInactiveFixture(t, "sing-box")
	m := New(filepath.Dir(f.a.StateRoot))
	if err := m.Register(f.a); err != nil {
		t.Fatal(err)
	}
	previous := networkExecutionPlan()
	previous.PlanID = "dp-1111111111111111"
	previous.State = "committed"
	if err := m.Record(previous); err != nil {
		t.Fatal(err)
	}
	plan := previous
	plan.PlanID = "dp-2222222222222222"
	plan.Digest = strings.Repeat("2", 64)
	plan.State = "rollback-failed"
	plan.Ready = false
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(m.StateRoot, "transactions", plan.PlanID)
	if err := m.prepareExecutionRoot(root); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	execution := Execution{PlanID: plan.PlanID, Digest: plan.Digest, State: "rollback-failed", StartedAt: now, FinishedAt: now}
	for _, phase := range []string{"snapshot", "stage", "validate", "activate", "rollback", "verify-rollback"} {
		state := "passed"
		if phase == "activate" || phase == "rollback" || phase == "verify-rollback" {
			state = "failed"
		}
		execution.Steps = append(execution.Steps, ExecutionStep{Adapter: "sing-box", Phase: phase, State: state, StartedAt: now, FinishedAt: now})
	}
	if err := m.writeExecution(root, execution); err != nil {
		t.Fatal(err)
	}
	policy := testEarlyPolicy()
	generation := strings.Repeat("a", 32)
	path, _ := f.a.policyGenerationRoot(generation)
	writeDoc := func(path, id string) {
		steps, err := policyAdditionExpected(policy)
		if err != nil {
			t.Fatal(err)
		}
		steps[0].State = "intent"
		doc := policyAdditionDocument{Schema: 1, ID: id, Boot: retirementOldBoot, RootHash: policyAdditionRootHash(path), PolicyHash: policyAdditionHash(policy), Phase: "active", Steps: steps}
		f.writeReceipt(t, path, doc)
		inactiveWrite(t, filepath.Join(path, policyAdditionLock), []byte(policyAdditionMarker))
	}
	writeDoc(path, generation)
	if err := f.a.savePolicyJournal(policy, true); err != nil {
		t.Fatal(err)
	}
	binding := proxyPolicyBinding{Schema: 1, Engine: "sing-box", Digest: proxyPolicyDigest(policy), Generation: generation, ReceiptID: generation, Phase: "active"}
	if err := f.a.writePolicyBinding(binding); err != nil {
		t.Fatal(err)
	}
	adapterRoot := filepath.Join(root, "sing-box")
	raw, _ := json.Marshal(policy)
	inactiveWrite(t, filepath.Join(adapterRoot, "policy.staged.json"), raw)
	if err := f.a.prepareCandidatePolicy(adapterRoot, policy); err != nil {
		t.Fatal(err)
	}
	f.a.bootIdentity = func() (string, error) { return retirementOldBoot, nil }
	if err := f.a.beginCandidatePolicy(adapterRoot, policy); err != nil {
		t.Fatal(err)
	}
	writeDoc(adapterRoot, strings.Repeat("b", 32))
	snapshot := proxySnapshot{EngineID: "sing-box", SidecarKind: f.a.effectiveSidecar(), BootID: retirementOldBoot, Policy: policy, PolicyExists: true, PolicyTracked: true, PolicyBinding: &binding, PolicyWasActive: true, EngineWasRunning: true, SidecarWasRunning: true, RuntimeEngineExists: true, RuntimeEngine: []byte("{}"), RuntimeSideExists: true, RuntimeSidecar: []byte("{}")}
	raw, _ = json.Marshal(snapshot)
	inactiveWrite(t, filepath.Join(adapterRoot, "snapshot.json"), raw)
	inactiveWrite(t, f.a.engineConfigPath(), []byte("{}"))
	inactiveWrite(t, f.a.sidecarConfigPath(), []byte("{}"))
	f.a.bootIdentity = func() (string, error) { return retirementNewBoot, nil }
	result := &bootRetirementFixture{inactiveFixture: f, m: m, plan: plan, settings: strings.Repeat("c", 64), root: root, original: map[string][]byte{}}
	_ = filepath.WalkDir(m.StateRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			name, _ := filepath.Rel(m.StateRoot, path)
			result.original[name] = raw
		}
		return nil
	})
	return result
}

func (f *bootRetirementFixture) run(guard func(Plan) error, fault func(string) error) (Execution, error) {
	return f.m.retireFailedRollbackAfterBoot(context.Background(), f.plan.PlanID, f.plan.Digest, f.settings, guard, bootRetirementOptions{proof: &f.proof, fault: fault})
}

func bootRetirementTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[path] = data
		return nil
	})
	if err != nil {
		t.Fatal("read retired file tree", err)
	}
	return files
}

func TestBootRetirementExpiresFilesWithoutKernelOrReceiptAuthority(t *testing.T) {
	f := newBootRetirementFixture(t)
	// Firmware rules in other tables do not prevent a negative inventory.
	f.runner.rules[4] += "100: from all fwmark 0xffffaaa lookup 4096\n101: from all fwmark 0xffffaaa blackhole\n"
	f.runner.rules[6] += "1172: from all oif nwg0 lookup 16395\n"
	execution, err := f.run(func(Plan) error { return nil }, nil)
	if err != nil || execution.State != "rolled-back" || execution.RollbackVerified {
		t.Fatal(execution.State, execution.RollbackVerified, err)
	}
	if f.processes.calls != 0 {
		t.Fatal("retirement invoked a process controller", f.processes.calls)
	}
	if err := f.m.CheckExecutionRecovery(context.Background()); err != nil {
		t.Fatal("journal remains fenced", err)
	}
	archive := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest)
	var manifest bootRetirementManifest
	raw, err := os.ReadFile(filepath.Join(archive, "manifest.json"))
	if err != nil || json.Unmarshal(raw, &manifest) != nil {
		t.Fatal(err)
	}
	for name, original := range manifest.Files {
		archived, err := os.ReadFile(filepath.Join(archive, "files", name))
		if err != nil || !bytes.Equal(archived, original) || !bytes.Equal(archived, f.original[name]) {
			t.Fatal("original artifact changed", name, err)
		}
		if _, err := os.Lstat(filepath.Join(f.m.StateRoot, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("live artifact remains", name, err)
		}
	}
	for name, original := range manifest.Evidence {
		if !bytes.Equal(original, f.original[name]) {
			t.Fatal("original journal not preserved", name)
		}
	}
	// The original candidate's old-boot intent is still unknown to normal APIs.
	if err := f.a.removeCandidatePolicy(context.Background(), filepath.Join(f.root, "sing-box")); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("file retirement minted cleanup authority", err)
	}
	// Both observers use the same closed foreign-firmware grammar. File-only
	// retirement does not grant authority over our table or unknown RPDB rows.
	before := bootRetirementTree(t, f.m.StateRoot)
	if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); err != nil {
		t.Fatal("known foreign firmware prevented ordinary inactivity proof", err)
	}
	foreignRules := f.runner.rules[4]
	for _, row := range []string{
		fmt.Sprintf("1400: from all lookup %d\n", f.a.Table),
		fmt.Sprintf("%d: from all fwmark 0x1 lookup 4096\n", f.a.Priority),
		"1400: from all lookup 4096 proto unknown\n",
	} {
		f.runner.rules[4] = foreignRules + row
		if err := f.a.verifyRuntimeInactive(context.Background(), f.proof); !errors.Is(err, ErrProxyRuntimeInactive) {
			t.Fatal("retirement admitted an owned or unrecognized RPDB row", row, err)
		}
	}
	if f.processes.calls != 0 || !reflect.DeepEqual(before, bootRetirementTree(t, f.m.StateRoot)) {
		t.Fatal("ordinary inactivity observation changed processes or retired files")
	}
}

func TestBootRetirementRefusesUncertainScopeBeforeChangingFiles(t *testing.T) {
	for _, mode := range []string{"same-boot", "guard", "digest", "dns", "retained", "receipt-missing", "receipt-corrupt", "snapshot-boot", "binding", "process", "interface", "selector", "default", "firewall", "read-error", "later-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := newBootRetirementFixture(t)
			guard := func(Plan) error { return nil }
			switch mode {
			case "same-boot":
				f.a.bootIdentity = func() (string, error) { return retirementOldBoot, nil }
			case "guard":
				guard = func(Plan) error { return errors.New("settings changed") }
			case "digest":
				f.plan.Digest = strings.Repeat("f", 64)
			case "dns":
				p, _, _ := f.m.Latest()
				p.DNS = &ScopedDNSPlan{}
				if err := f.m.Record(p); err != nil {
					t.Fatal(err)
				}
			case "retained":
				var e *Execution
				_, _ = readOptionalJournal(filepath.Join(f.m.StateRoot, "latest-execution.json"), &e)
				e.ResourcePlanID = "different"
				raw, _ := json.Marshal(e)
				inactiveWrite(t, filepath.Join(f.m.StateRoot, "latest-execution.json"), raw)
				inactiveWrite(t, filepath.Join(f.root, "execution.json"), raw)
			case "receipt-missing":
				if err := os.Remove(filepath.Join(f.root, "sing-box", policyAdditionFile)); err != nil {
					t.Fatal(err)
				}
			case "receipt-corrupt":
				inactiveWrite(t, filepath.Join(f.root, "sing-box", policyAdditionFile), []byte("{}"))
			case "snapshot-boot":
				var snapshot proxySnapshot
				raw, _ := os.ReadFile(filepath.Join(f.root, "sing-box", "snapshot.json"))
				_ = json.Unmarshal(raw, &snapshot)
				snapshot.BootID = ""
				raw, _ = json.Marshal(snapshot)
				inactiveWrite(t, filepath.Join(f.root, "sing-box", "snapshot.json"), raw)
			case "binding":
				inactiveWrite(t, f.a.policyBindingPath(), []byte("{}"))
			case "process":
				f.writeProcess(t, 456, "S", "0", "sing-box\x00run\x00")
			case "interface":
				f.proof.interfaces = func() ([]net.Interface, error) {
					return []net.Interface{{Index: 1, Name: "lo"}, {Index: 2, Name: f.a.Interface}}, nil
				}
			case "selector":
				f.runner.rules[4] += "64: from all lookup 203\n"
			case "default":
				f.runner.routes[6] = "default dev rz-sing proto boot metric 1024\n"
			case "firewall":
				f.runner.fw["iptables/filter"] = "-P FORWARD ACCEPT\n-N " + f.a.forwardingChain() + "\n"
			case "read-error":
				f.runner.err = errors.New("read failed")
			case "later-drift":
				calls := 0
				f.proof.interfaces = func() ([]net.Interface, error) {
					calls++
					if calls == 2 {
						return []net.Interface{{Index: 1, Name: "lo"}, {Index: 2, Name: f.a.Interface}}, nil
					}
					return []net.Interface{{Index: 1, Name: "lo"}}, nil
				}
			}
			before := proxyRollbackRetryFiles(t, f.m.StateRoot)
			if _, err := f.run(guard, nil); err == nil {
				t.Fatal("uncertain retirement accepted")
			}
			after := proxyRollbackRetryFiles(t, f.m.StateRoot)
			if !reflect.DeepEqual(before, after) || f.processes.calls != 0 {
				t.Fatal("refused retirement changed files or processes", f.processes.calls)
			}
		})
	}
}

func TestBootRetirementInterruptedMovesResumeWithOriginalEvidence(t *testing.T) {
	for _, cut := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13} {
		t.Run(string(rune('0'+cut)), func(t *testing.T) {
			f := newBootRetirementFixture(t)
			calls := 0
			result, err := f.run(func(Plan) error { return nil }, func(point string) error {
				if strings.HasPrefix(point, "publication-") {
					return nil
				}
				calls++
				if calls == cut {
					return errors.New("simulated process cut")
				}
				return nil
			})
			if err == nil || result.State != "rollback-failed" {
				t.Fatal("interrupted retirement cleared fence", result.State, err, calls)
			}
			result, err = f.run(func(Plan) error { return nil }, nil)
			if err != nil || result.State != "rolled-back" || result.RollbackVerified {
				t.Fatal("could not resume explicit file retirement", result.State, err)
			}
		})
	}
}

func TestBootRetirementInterruptedRecoverySurvivesAnotherBoot(t *testing.T) {
	for _, cut := range []int{1, 4, 13} {
		t.Run(string(rune('a'+cut)), func(t *testing.T) {
			f := newBootRetirementFixture(t)
			calls := 0
			if _, err := f.run(func(Plan) error { return nil }, func(point string) error {
				if strings.HasPrefix(point, "publication-") {
					return nil
				}
				calls++
				if calls == cut {
					return errors.New("power cut")
				}
				return nil
			}); err == nil {
				t.Fatal("cut did not interrupt retirement")
			}
			archive := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest)
			before, err := os.ReadFile(filepath.Join(archive, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			thirdBoot := "33333333-3333-3333-3333-333333333333"
			f.a.bootIdentity = func() (string, error) { return thirdBoot, nil }
			result, err := f.run(func(Plan) error { return nil }, nil)
			if err != nil || result.State != "rolled-back" || result.RollbackVerified {
				t.Fatal("another reboot created a permanent fence", result.State, err)
			}
			after, err := os.ReadFile(filepath.Join(archive, "manifest.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("resume rewrote original boot provenance", err)
			}
			for _, boot := range []string{retirementNewBoot, thirdBoot} {
				if _, err := os.Stat(filepath.Join(archive, "observations", boot+".json")); err != nil {
					t.Fatal("missing independent boot witness", boot, err)
				}
			}
		})
	}
}

type bootRetirementProcessCut struct{}

func bootRetirementCut(call func()) (cut bool) {
	defer func() {
		if value := recover(); value != nil {
			if _, ok := value.(bootRetirementProcessCut); !ok {
				panic(value)
			}
			cut = true
		}
	}()
	call()
	return false
}

func TestBootRetirementTornJournalPublicationResumesExplicitly(t *testing.T) {
	for cut := 1; cut <= 11; cut++ {
		t.Run(string(rune('a'+cut)), func(t *testing.T) {
			f := newBootRetirementFixture(t)
			calls := 0
			// Panic skips the recovery runner's error-correction publication, just
			// as process exit does. Only locks/handles unwind before a fresh Manager.
			crashed := bootRetirementCut(func() {
				_, _ = f.run(func(Plan) error { return nil }, func(point string) error {
					if strings.HasPrefix(point, "publication-") {
						calls++
						if calls == cut {
							panic(bootRetirementProcessCut{})
						}
					}
					return nil
				})
			})
			if !crashed {
				t.Fatal("publication boundary was not exercised", cut, calls)
			}
			f.m = New(f.m.StateRoot)
			if err := f.m.Register(f.a); err != nil {
				t.Fatal(err)
			}
			if cut%2 == 0 {
				f.a.bootIdentity = func() (string, error) { return "33333333-3333-3333-3333-333333333333", nil }
			}
			result, err := f.run(func(Plan) error { return nil }, nil)
			if err != nil || result.State != "rolled-back" || result.RollbackVerified {
				t.Fatal("torn metadata publication created permanent fence", cut, result.State, err)
			}
			if err := f.m.CheckExecutionRecovery(context.Background()); err != nil {
				t.Fatal("publication remains torn", err)
			}
		})
	}
}

func TestBootRetirementReplayRefusesChangedEvidenceBeforeWriting(t *testing.T) {
	for _, target := range []string{"committed", "snapshot", "settings"} {
		t.Run(target, func(t *testing.T) {
			f := newBootRetirementFixture(t)
			calls := 0
			if !bootRetirementCut(func() {
				_, _ = f.run(func(Plan) error { return nil }, func(point string) error {
					if strings.HasPrefix(point, "publication-") {
						calls++
						if calls == 8 {
							panic(bootRetirementProcessCut{})
						}
					}
					return nil
				})
			}) {
				t.Fatal("publication cut not exercised")
			}
			name := filepath.Join(f.m.StateRoot, "latest-committed-plan.json")
			if target == "snapshot" {
				name = filepath.Join(f.root, "sing-box", "snapshot.json")
			}
			if target == "settings" {
				f.settings = strings.Repeat("d", 64)
			} else {
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				inactiveWrite(t, name, append(raw, '\n'))
			}
			before := proxyRollbackRetryFiles(t, f.m.StateRoot)
			if _, err := f.run(func(Plan) error { return nil }, nil); err == nil {
				t.Fatal("replay accepted changed evidence", target)
			}
			if after := proxyRollbackRetryFiles(t, f.m.StateRoot); !reflect.DeepEqual(before, after) {
				t.Fatal("replay wrote journals before validating current evidence")
			}
		})
	}
}

func TestBootRetirementProvenanceChangeCannotCloseFence(t *testing.T) {
	for _, target := range []string{"manifest", "witness"} {
		t.Run(target, func(t *testing.T) {
			f := newBootRetirementFixture(t)
			result, err := f.run(func(Plan) error { return nil }, func(point string) error {
				if point == "manifest-published" {
					name := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest, "manifest.json")
					if target == "witness" {
						name = filepath.Join(filepath.Dir(name), "observations", retirementNewBoot+".json")
					}
					if err := os.Remove(name); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			})
			if err == nil || result.State != "rollback-failed" {
				t.Fatal("missing provenance cleared the fence", result.State, err)
			}
			for name, original := range f.original {
				actual, err := os.ReadFile(filepath.Join(f.m.StateRoot, name))
				if err != nil || !bytes.Equal(actual, original) {
					t.Fatal("provenance refusal changed originals", name, err)
				}
			}
		})
	}
}

func copyBootRetirementTree(t *testing.T, source, destination string) {
	t.Helper()
	err := filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBootRetirementDirectoryReplacementAfterMovePreservesReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows prevents renaming these held directory/file handles; Linux exercises replacement detection")
	}
	for _, target := range []string{"state", "proxy", "transaction"} {
		t.Run(target, func(t *testing.T) {
			f := newBootRetirementFixture(t)
			replaced := false
			var replacementPath string
			var before map[string]string
			result, err := f.run(func(Plan) error { return nil }, func(point string) error {
				if replaced || !strings.HasPrefix(point, "after-rename:") {
					return nil
				}
				replaced = true
				replacementPath = f.m.StateRoot
				if target == "proxy" {
					replacementPath = f.a.StateRoot
				} else if target == "transaction" {
					replacementPath = f.root
				}
				held := replacementPath + "-original"
				if err := os.Rename(replacementPath, held); err != nil {
					t.Fatal(err)
				}
				copyBootRetirementTree(t, held, replacementPath)
				before = proxyRollbackRetryFiles(t, replacementPath)
				return nil
			})
			if !replaced || err == nil || result.State != "rollback-failed" {
				t.Fatal("replacement acquired retirement authority", replaced, result.State, err)
			}
			if after := proxyRollbackRetryFiles(t, replacementPath); !reflect.DeepEqual(before, after) {
				t.Fatal("retirement wrote into replacement directory")
			}
		})
	}
}

func TestBootRetirementPrepublicationTemporaryDoesNotPreventRetry(t *testing.T) {
	f := newBootRetirementFixture(t)
	archive := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest)
	orphan := filepath.Join(archive, ".manifest-new")
	inactiveWrite(t, orphan, []byte("unconfirmed previous temporary bytes"))
	result, err := f.run(func(Plan) error { return nil }, nil)
	if err != nil || result.State != "rolled-back" {
		t.Fatal("old temporary permanently blocked retirement", result.State, err)
	}
	if raw, err := os.ReadFile(orphan); err != nil || string(raw) != "unconfirmed previous temporary bytes" {
		t.Fatal("unknown temporary was removed", err)
	}
}

func TestBootRetirementRejectsForeignPublicationBeforeImage(t *testing.T) {
	f := newBootRetirementFixture(t)
	if !bootRetirementCut(func() {
		_, _ = f.run(func(Plan) error { return nil }, func(point string) error {
			if point == "publication-intent" {
				panic(bootRetirementProcessCut{})
			}
			return nil
		})
	}) {
		t.Fatal("intent cut missing")
	}
	path := filepath.Join(f.m.StateRoot, "boot-retirements", f.plan.PlanID+"-"+f.plan.Digest, "publication.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var publication bootRetirementPublication
	if json.Unmarshal(raw, &publication) != nil {
		t.Fatal("bad publication fixture")
	}
	var foreign Execution
	if json.Unmarshal(publication.Before["latest-execution.json"], &foreign) != nil {
		t.Fatal("bad execution fixture")
	}
	foreign.State = "committed"
	raw, _ = json.Marshal(foreign)
	publication.Before["latest-execution.json"] = raw
	inactiveWrite(t, filepath.Join(f.m.StateRoot, "latest-execution.json"), raw)
	publication.Checksum = bootPublicationChecksum(publication)
	raw, _ = json.Marshal(publication)
	inactiveWrite(t, path, raw)
	before := proxyRollbackRetryFiles(t, f.m.StateRoot)
	if _, err := f.run(func(Plan) error { return nil }, nil); err == nil {
		t.Fatal("foreign committed before-image was overwritten")
	}
	if after := proxyRollbackRetryFiles(t, f.m.StateRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("refused foreign publication changed files")
	}
}

func TestBootRetirementMixedNFQPlanRefusesWithoutCleanup(t *testing.T) {
	f := newBootRetirementFixture(t)
	if err := f.m.Register(NewNFQWS2Adapter()); err != nil {
		t.Fatal(err)
	}
	previous, _, _ := f.m.Committed()
	previous.Adapters = []string{"nfqws2", "sing-box"}
	if err := f.m.Record(previous); err != nil {
		t.Fatal(err)
	}
	plan, _, _ := f.m.Latest()
	plan = f.plan
	plan.Adapters = previous.Adapters
	if err := f.m.Record(plan); err != nil {
		t.Fatal(err)
	}
	var execution *Execution
	if _, err := readOptionalJournal(filepath.Join(f.root, "execution.json"), &execution); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	execution.Steps = append([]ExecutionStep{{Adapter: "nfqws2", Phase: "snapshot", State: "passed", StartedAt: now, FinishedAt: now}}, execution.Steps...)
	if err := f.m.writeExecution(f.root, *execution); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.m.reviewFailedRollback(plan.PlanID, plan.Digest); !ok {
		t.Fatal("mixed fixture did not pass ordinary journal review")
	}
	before := proxyRollbackRetryFiles(t, f.m.StateRoot)
	if _, err := f.run(func(Plan) error { return nil }, nil); err == nil {
		t.Fatal("mixed NFQ ownership was implicitly closed")
	}
	if after := proxyRollbackRetryFiles(t, f.m.StateRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("unsupported mixed scope changed files")
	}
}

func TestBootRetirementCleanupIntentDoesNotBecomeAnACK(t *testing.T) {
	f := newBootRetirementFixture(t)
	for _, path := range []string{filepath.Join(f.root, "sing-box", policyAdditionFile), filepath.Join(f.a.StateRoot, "policy-generations", strings.Repeat("a", 32), policyAdditionFile)} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc policyAdditionDocument
		if json.Unmarshal(raw, &doc) != nil {
			t.Fatal("bad fixture")
		}
		doc.Steps[0].State = "cleanup-intent"
		doc.Checksum = policyAdditionChecksum(doc)
		raw, _ = json.Marshal(doc)
		inactiveWrite(t, path, raw)
	}
	result, err := f.run(func(Plan) error { return nil }, nil)
	if err != nil || result.State != "rolled-back" || result.RollbackVerified || f.processes.calls != 0 {
		t.Fatal("cleanup-intent expiry ran effects or claimed rollback", result.State, err)
	}
	var doc policyAdditionDocument
	raw, err := os.ReadFile(filepath.Join(f.root, "sing-box", policyAdditionFile))
	if err != nil || json.Unmarshal(raw, &doc) != nil || doc.Steps[0].State != "cleanup-intent" || doc.Boot != retirementOldBoot {
		t.Fatal("old cleanup intent was rewritten", err)
	}
}

func TestBootRetirementBusyOriginalReceiptRefuses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("production receipt flock is Linux-only")
	}
	f := newBootRetirementFixture(t)
	file, err := os.OpenFile(filepath.Join(f.root, "sing-box", policyAdditionLock), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := lockCloudflareScanFile(file); err != nil {
		t.Fatal(err)
	}
	defer unlockCloudflareScanFile(file)
	before := proxyRollbackRetryFiles(t, f.m.StateRoot)
	if _, err := f.run(func(Plan) error { return nil }, nil); err == nil {
		t.Fatal("another original receipt writer did not retain the fence")
	}
	if after := proxyRollbackRetryFiles(t, f.m.StateRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("busy receipt refusal changed files")
	}
}

func TestBootRetirementSymlinkSourceAndArchiveRefuse(t *testing.T) {
	for _, target := range []string{"source", "archive"} {
		t.Run(target, func(t *testing.T) {
			f := newBootRetirementFixture(t)
			outside := t.TempDir()
			var link string
			if target == "source" {
				link = f.a.StateRoot
				if err := os.Remove(outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(link, outside); err != nil {
					t.Fatal(err)
				}
			} else {
				link = filepath.Join(f.m.StateRoot, "boot-retirements")
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			before := proxyRollbackRetryFiles(t, outside)
			if _, err := f.run(func(Plan) error { return nil }, nil); err == nil {
				t.Fatal("symlink retirement accepted")
			}
			if after := proxyRollbackRetryFiles(t, outside); !reflect.DeepEqual(before, after) {
				t.Fatal("retirement wrote through symlink")
			}
		})
	}
}
