package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

func TestUSQUECommittedRecordRejectsAnotherBootSessionOrPID(t *testing.T) {
	dir := t.TempDir()
	spec := ProcessSpec{ID: "usque-engine", Binary: filepath.Join(dir, "usque"), Dir: dir, PIDPath: filepath.Join(dir, "engine.pid"), MatchArg: filepath.Join(dir, "engine.json"), RouteProof: true}
	spec.Args = []string{"-c", spec.MatchArg}
	args := routeidentity.Hash([]byte(strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00"))
	session := committedUSQUESession{sha: routeidentity.Hash([]byte("current session")), argsSHA: args}
	base := routeidentity.Receipt{Version: 1, PID: 2345, BootID: "current-boot", StartTicks: "34", Executable: spec.Binary, ArgsHash: args, ConfigHash: session.sha}
	root, err := ownedfs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, scenario := range []string{"same", "old-boot", "replaced-session", "changed-pid", "changed-argv", "changed-binary", "zero-birth"} {
		t.Run(scenario, func(t *testing.T) {
			record := base
			switch scenario {
			case "old-boot":
				record.BootID = "old-boot"
			case "replaced-session":
				record.ConfigHash = routeidentity.Hash([]byte("obsolete session"))
			case "changed-pid":
				record.PID++
			case "changed-argv":
				record.ArgsHash = routeidentity.Hash([]byte("different transport"))
			case "changed-binary":
				record.Executable += "-changed"
			case "zero-birth":
				record.StartTicks = "0"
			}
			if err := os.WriteFile(spec.PIDPath, []byte("2345\n"), 0600); err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(record)
			if err := os.WriteFile(spec.PIDPath+routeidentity.ReceiptSuffix, data, 0600); err != nil {
				t.Fatal(err)
			}
			read, err := committedUSQUEProcessRecord(root, spec, session, base.BootID)
			if scenario == "same" && (err != nil || read.pid != base.PID) || scenario != "same" && !errors.Is(err, ErrUSQUELocalProcessUnconfirmed) {
				t.Fatal("invalid original process record classification", err)
			}
		})
	}
}

func TestUSQUELiveProviderFailureNeverRestartsHealthyLocalProcess(t *testing.T) {
	f := newUSQUELifecycleFixture(t)
	f.activate()
	if err := f.a.Commit(f.ctx, f.plan, f.root); err != nil {
		t.Fatal(err)
	}
	plan, err := Build(Input{Revision: 2, NetworkProfileID: f.plan.NetworkProfileID, Routes: f.plan.Routes, EngineConfigDrafts: f.plan.EngineDrafts,
		Engines: []Engine{{ID: "usque", Installed: true, Configured: true, Activatable: true, Canary: true}}, Host: HostState{IPCommand: true, TUN: true, SingBox: true}})
	if err != nil || !plan.Ready {
		t.Fatal("invalid fixture plan", err, plan.Blockers)
	}
	plan.State = "committed"
	m := New(filepath.Join(f.base, "manager"))
	if err := m.Register(f.a); err != nil {
		t.Fatal(err)
	}
	if err := m.Record(plan); err != nil {
		t.Fatal(err)
	}
	old := f.evidence(f.a.evidencePath())
	starts, stops := f.processes.starts, f.processes.stops
	mutations := len(receiptMutationCalls(f.runner.seen))
	called := 0
	providerFailure := errors.New("fixture remote service unavailable")
	f.a.ownedUSQUELiveIO.produce = func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		called++
		return usquediag.OwnedRuntimeEvidence{}, providerFailure
	}
	result, err := m.MonitorCommittedUSQUEHealth(f.ctx, plan, f.a.Configs, nil, "", true)
	if !errors.Is(err, providerFailure) || called != 1 || result.RestartAttempted || result.Restarted {
		t.Fatal("live local process entered restart after failed network operation", result, err)
	}
	delete(f.processes.active, "usque-engine")
	f.processes.base.running["usque-engine"] = false
	controlRoot := filepath.Join(f.base, "control")
	if _, err := operationgate.InitializeSelfUpdateControl(f.ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	ctx, release, err := gate.ExclusiveContext(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	control, err := gate.ReviewControlEpoch(ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	result, err = m.MonitorCommittedUSQUEHealth(ctx, plan, f.a.Configs, control, controlRoot, true)
	if !errors.Is(err, ErrUSQUELocalProcessUnconfirmed) || called != 1 || result.RestartAttempted || result.Restarted {
		t.Fatal("mutable Running(false) granted startup", result, err)
	}
	if f.processes.starts != starts || f.processes.stops != stops || len(receiptMutationCalls(f.runner.seen)) != mutations || !bytes.Equal(old, f.evidence(f.a.evidencePath())) {
		t.Fatal("unconfirmed monitor changed runtime, rules or service evidence")
	}
}
