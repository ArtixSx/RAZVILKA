package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

func TestProxySnapshotBoundedReaderRoundTripsValidSnapshotLargerThanXrayConfigLimit(t *testing.T) {
	root := t.TempDir()
	// Both expert file images are valid, bounded engine JSON. Legal whitespace
	// formatting survives a snapshot verbatim; base64 and two independent images
	// make the snapshot larger than a single 4 MiB engine admission document.
	exit := []byte(`{"outbounds":[{"protocol":"socks","tag":"exit","settings":{"servers":[{"address":"1.1.1.1","port":1080}]}}]}`)
	config := append(bytes.Repeat([]byte(" "), 3<<20), exit...)
	if len(config) > 4<<20 || !json.Valid(config) {
		t.Fatal("fixture is not a valid bounded expert configuration")
	}
	if _, err := routeidentity.ConfigOutbound("xray", config); err != nil {
		t.Fatal("fixture does not retain the original static exit", err)
	}
	engine, _, err := buildProxyCandidate("xray", exit, 18082)
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := buildSOCKSTunnelConfig("rz-xray", "172.31.22.1/30", 18082)
	if err != nil {
		t.Fatal(err)
	}
	want := proxySnapshot{
		EngineID: "xray", CandidateXrayMode: "generic", PreviousXrayMode: "generic", SidecarKind: "sing-box",
		ConfigPath: filepath.Join(root, "expert.json"), Config: config, ConfigExisted: true,
		ConfigDraft: true, StagedConfig: append([]byte(nil), config...),
		RuntimeEngine: engine, RuntimeEngineExists: true, RuntimeSidecar: sidecar, RuntimeSideExists: true,
		BootID: "snapshot-fixture-boot", EngineWasRunning: true, SidecarWasRunning: true,
	}
	raw, err := json.MarshalIndent(want, "", "  ")
	if err != nil || len(raw) <= 4<<20 || len(raw) > 64<<20 {
		t.Fatal("fixture did not cross the snapshot/config limit boundary", len(raw), err)
	}
	path := filepath.Join(root, "snapshot.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readProxySnapshot(root)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("valid multi-image snapshot was rejected or changed", err)
	}
	got.Config[0] = '\n'
	if want.Config[0] != ' ' {
		t.Fatal("decoded snapshot aliases caller's original file image")
	}
	retained, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(retained, raw) {
		t.Fatal("snapshot reader mutated the persisted original", err)
	}
}

func TestProxySnapshotBoundedReaderRejectsAmbiguousJSONAndUnsafeFileShape(t *testing.T) {
	for _, mode := range []string{"duplicate", "alias-duplicate", "nested-duplicate", "unknown", "trailing", "null", "empty", "missing-config-path", "directory", "over-64MiB"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "snapshot.json")
			raw := map[string]string{
				"duplicate":        `{"config_path":"first","config_path":"second"}`,
				"alias-duplicate":  `{"config_path":"first","CONFIG_PATH":"second"}`,
				"nested-duplicate": `{"config_path":"expert.json","policy":{"engine":"xray","engine":"sing-box"}}`,
				"unknown":          `{"config_path":"expert.json","unknown_mode":"generic"}`,
				"trailing":         `{"config_path":"expert.json"}{}`,
				"null":             `null`, "empty": ``, "missing-config-path": `{}`,
			}
			if mode == "directory" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if mode == "over-64MiB" {
				// Size refusal is based on the anchored regular file before JSON
				// decoding; a sparse fixture avoids an unnecessary large allocation.
				file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate((64 << 20) + 1)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			} else if err := os.WriteFile(path, []byte(raw[mode]), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readProxySnapshot(root); err == nil {
				t.Fatal("ambiguous or unsafe snapshot accepted")
			}
		})
	}
	if _, err := readProxySnapshot("relative-root"); !errors.Is(err, ErrProxyPolicyUnknown) {
		t.Fatal("relative snapshot root admitted", err)
	}
}

func TestProxySnapshotLargerDocumentLimitDoesNotWidenScopedXrayJSONAdmission(t *testing.T) {
	data := append(bytes.Repeat([]byte(" "), 4<<20), []byte(`{}`)...)
	if !json.Valid(data) || scopedNodeUniqueJSON(data) {
		t.Fatal("larger snapshot allowance leaked into the 4 MiB scoped engine scanner")
	}
}

func TestProxySnapshotTransactionRootReplacementCannotStageIntoSameSnapshotCopy(t *testing.T) {
	f := newXrayDispatchFixture(t)
	if err := os.MkdirAll(f.a.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	root := privateScopedXrayFixtureDir(t)
	if err := f.a.Snapshot(f.ctx, f.nodePlan, root); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	held := filepath.Join(t.TempDir(), "original-transaction")
	original := nodeRouterTransitReadbackTree(t, root)
	stateBefore := nodeRouterTransitReadbackTree(t, f.a.StateRoot)
	starts, stops := f.processes.starts, f.processes.stops
	var replacementBefore map[string]string
	cut := false
	materialize := f.a.NodeRoutes
	f.a.NodeRoutes = func(ctx context.Context, requests []NodeRouteRequest, profile string, now time.Time) (NodeRouteMaterial, error) {
		material, err := materialize(ctx, requests, profile, now)
		if err == nil && !cut {
			cut = true
			if err := os.Rename(root, held); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "snapshot.json"), snapshot, 0600); err != nil {
				t.Fatal(err)
			}
			replacementBefore = nodeRouterTransitReadbackTree(t, root)
		}
		return material, err
	}
	err = f.a.Stage(f.ctx, f.nodePlan, root)
	if !cut || !errors.Is(err, ErrProxyPolicyUnknown) || f.processes.starts != starts || f.processes.stops != stops || len(f.processes.active) != 0 ||
		!reflect.DeepEqual(replacementBefore, nodeRouterTransitReadbackTree(t, root)) || !reflect.DeepEqual(original, nodeRouterTransitReadbackTree(t, held)) ||
		!reflect.DeepEqual(stateBefore, nodeRouterTransitReadbackTree(t, f.a.StateRoot)) {
		t.Fatal("same snapshot hash adopted replacement transaction root or changed owned state", err, cut)
	}
	f.constantOwner()
}

type proxySnapshotBoundsProcesses struct {
	ProcessController
	running int
	last    ProcessSpec
	cut     func(ProcessSpec, bool)
}

func (p *proxySnapshotBoundsProcesses) Running(spec ProcessSpec) bool {
	running := p.ProcessController.Running(spec)
	p.running++
	p.last = spec
	if p.cut != nil {
		p.cut(spec, running)
	}
	return running
}

func TestProxySnapshotTransactionRootReplacementOrMarkerDriftDuringFinalRollbackRunningCannotVerify(t *testing.T) {
	for _, mode := range []string{"same-byte-root-replacement", "candidate-marker-drift"} {
		t.Run(mode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit("generic")
			root := f.stage("node")
			if err := f.a.Activate(f.ctx, f.nodePlan, root); err != nil {
				t.Fatal(err)
			}
			if err := f.a.Rollback(f.ctx, f.nodePlan, root); err != nil {
				t.Fatal(err)
			}
			processes := &proxySnapshotBoundsProcesses{ProcessController: f.processes}
			f.a.Processes = processes
			commandStart := len(f.commands)
			if ok, err := f.a.VerifyRollback(f.ctx, f.nodePlan, root); err != nil || !ok {
				t.Fatal("baseline exact rollback verification failed", ok, err)
			}
			baselineCommands := append([]string(nil), f.commands[commandStart:]...)
			finalRunning := processes.running
			oldView, err := f.a.xrayModeView(proxyXrayModeGeneric)
			if err != nil || finalRunning < 4 || len(baselineCommands) == 0 || !reflect.DeepEqual(processes.last, oldView.sidecarProcess()) {
				t.Fatal("fixture did not reach final exact old-sidecar check after kernel readbacks", finalRunning, err)
			}
			snapshot, err := os.ReadFile(filepath.Join(root, "snapshot.json"))
			if err != nil {
				t.Fatal(err)
			}
			held := filepath.Join(t.TempDir(), "verified-original-transaction")
			original := nodeRouterTransitReadbackTree(t, root)
			stateBefore := nodeRouterTransitReadbackTree(t, f.a.StateRoot)
			activeBefore := make(map[string]ProcessSpec, len(f.processes.active))
			for id, spec := range f.processes.active {
				spec.Args = append([]string(nil), spec.Args...)
				activeBefore[id] = spec
			}
			starts, stops := f.processes.starts, f.processes.stops
			processes.running = 0
			commandStart = len(f.commands)
			cut := false
			var cutTree map[string]string
			processes.cut = func(spec ProcessSpec, running bool) {
				if processes.running != finalRunning {
					return
				}
				if !running || !reflect.DeepEqual(spec, oldView.sidecarProcess()) || !reflect.DeepEqual(baselineCommands, f.commands[commandStart:]) {
					t.Fatal("cut did not follow every baseline kernel readback and final old-sidecar observation")
				}
				cut = true
				if mode == "same-byte-root-replacement" {
					if err := os.Rename(root, held); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(root, 0700); err != nil {
						t.Fatal(err)
					}
				} else {
					var changed proxySnapshot
					if err := json.Unmarshal(snapshot, &changed); err != nil {
						t.Fatal(err)
					}
					changed.CandidateXrayMode = string(proxyXrayModeGeneric)
					snapshot, err = json.Marshal(changed)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(root, "snapshot.json"), snapshot, 0600); err != nil {
					t.Fatal(err)
				}
				cutTree = nodeRouterTransitReadbackTree(t, root)
			}
			ok, err := f.a.VerifyRollback(f.ctx, f.nodePlan, root)
			if !cut || ok || !errors.Is(err, ErrProxyPolicyUnknown) || processes.running != finalRunning ||
				!reflect.DeepEqual(baselineCommands, f.commands[commandStart:]) || f.processes.starts != starts || f.processes.stops != stops ||
				!reflect.DeepEqual(activeBefore, f.processes.active) || !reflect.DeepEqual(stateBefore, nodeRouterTransitReadbackTree(t, f.a.StateRoot)) ||
				!reflect.DeepEqual(cutTree, nodeRouterTransitReadbackTree(t, root)) {
				t.Fatal("final successful process callback admitted changed transaction or caused effects", ok, err, cut)
			}
			if mode == "same-byte-root-replacement" && !reflect.DeepEqual(original, nodeRouterTransitReadbackTree(t, held)) {
				t.Fatal("verification changed the retained original transaction")
			}
			f.constantOwner()
		})
	}
}
