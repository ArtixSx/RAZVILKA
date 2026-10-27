package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func unstagedColdXrayFixture(t *testing.T) (*inactiveFixture, string, Plan) {
	t.Helper()
	f := newInactiveFixture(t, "xray")
	f.a.Configs.LiveRoot = filepath.Join(privateScopedXrayFixtureDir(t), "live")
	if err := os.MkdirAll(f.a.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	f.a.scopedXray = true
	f.a.NodeRoutes = func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
		t.Fatal("preflight invoked materializer")
		return NodeRouteMaterial{}, nil
	}
	f.a.NodeTUNProbe = func(context.Context, NodeTUNRequest) (NodeTUNObservation, error) {
		t.Fatal("preflight probed tunnel")
		return NodeTUNObservation{}, nil
	}
	f.a.xrayOperation = true
	f.a.xrayCandidateMode = proxyXrayModeNode
	f.a.xrayPreviousMode = proxyXrayModeCold
	f.a.FreshProfile = func(context.Context) (string, error) { return executionNetwork, nil }
	root := privateScopedXrayFixtureDir(t)
	plan := Plan{NetworkProfileID: executionNetwork, Routes: []Route{{ServiceID: "telegram", Resolved: "xray:node-" + strings.Repeat("a", 64), ProbeURL: "https://service.example/"}}}
	if err := f.a.Snapshot(context.Background(), plan, root); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Stage(context.Background(), plan, root); err == nil || !strings.Contains(err.Error(), "client sources") {
		t.Fatal("did not reproduce original pre-effect refusal", err)
	}
	return f, root, plan
}

func TestUnstagedColdXrayRollbackLeavesExactAbsenceUntouched(t *testing.T) {
	f, root, plan := unstagedColdXrayFixture(t)
	processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
	f.a.Processes = processes
	before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
	if err := f.a.rollbackWithUnstagedInactiveProof(context.Background(), plan, root, &f.proof); err != nil {
		t.Fatal("no-effect refusal attempted cleanup", err)
	}
	if len(processes.start) != 0 || len(processes.stop) != 0 {
		t.Fatal("no-op touched processes", processes.start, processes.stop)
	}
	if after := proxyRollbackRetryFiles(t, f.a.StateRoot, root); !reflect.DeepEqual(before, after) {
		t.Fatal("no-op modified transaction/runtime files")
	}
	reads := len(f.runner.seen)
	if ok, err := f.a.verifyRollbackWithInactiveProof(context.Background(), plan, root, &f.proof); !ok || err != nil {
		t.Fatal("fresh exact absence not verified", ok, err)
	}
	if len(f.runner.seen) <= reads {
		t.Fatal("verification reused cached absence")
	}
}

func TestUnstagedColdXrayRollbackRefusesEffectsAndUnknownWithoutCleanup(t *testing.T) {
	for _, mode := range []string{"candidate-file", "foreign-file", "foreign-process", "kernel-error", "kernel-rule", "config-drift", "boot", "cancel", "closing-artifact", "closing-root", "closing-interface"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "closing-root" && runtime.GOOS == "windows" {
				t.Skip("Windows held directory handle prevents rename; exercised on Linux")
			}
			f, root, plan := unstagedColdXrayFixture(t)
			processes := &proxyRollbackRetryProcesses{base: f.a.Processes}
			f.a.Processes = processes
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "candidate-file":
				inactiveWrite(t, filepath.Join(root, "engine.staged.json"), []byte(`{}`))
			case "foreign-file":
				inactiveWrite(t, f.a.engineConfigPath(), []byte(`{}`))
			case "foreign-process":
				f.writeProcess(t, 456, "S", "0", "xray\x00run\x00")
			case "kernel-error":
				f.runner.err = errors.New("read failed")
			case "kernel-rule":
				f.runner.rules[4] += fmt.Sprintf("%d: from all lookup %d\n", f.a.Priority, f.a.Table)
			case "config-drift":
				s, _ := readProxySnapshot(root)
				inactiveWrite(t, s.ConfigPath, []byte(`{}`))
			case "boot":
				f.a.bootIdentity = func() (string, error) { return "other", nil }
			case "cancel":
				cancel()
			case "closing-interface":
				processes.base = &unstagedClosingProcesses{ProcessController: processes.base, closing: func() { inactiveWrite(t, f.a.nodeInterfacePath(), []byte(`{}`)) }}
			case "closing-artifact":
				f.runner.hook = func() { inactiveWrite(t, filepath.Join(root, "canary"), []byte("foreign")) }
			case "closing-root":
				f.runner.hook = func() {
					if err := os.Rename(root, root+"-old"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(root, 0700); err != nil {
						t.Fatal(err)
					}
					raw, err := os.ReadFile(filepath.Join(root+"-old", "snapshot.json"))
					if err != nil {
						t.Fatal(err)
					}
					inactiveWrite(t, filepath.Join(root, "snapshot.json"), raw)
				}
			}
			before := proxyRollbackRetryFiles(t, f.a.StateRoot, root)
			if err := f.a.rollbackWithUnstagedInactiveProof(ctx, plan, root, &f.proof); err == nil {
				t.Fatal("unknown/effect accepted", mode)
			}
			if len(processes.start) != 0 || len(processes.stop) != 0 {
				t.Fatal("refusal touched processes")
			}
			if mode != "closing-artifact" && mode != "closing-root" && mode != "closing-interface" {
				if after := proxyRollbackRetryFiles(t, f.a.StateRoot, root); !reflect.DeepEqual(before, after) {
					t.Fatal("refusal changed foreign bytes")
				}
			}
		})
	}
}

// A real cleanup failure after candidate effects is never converted to a no-op.
func TestUnstagedColdXrayNeverSwallowsIssuedRollbackFailure(t *testing.T) {
	f := newXrayDispatchFixture(t)
	root := f.stage("node")
	if err := f.a.Activate(f.ctx, f.nodePlan, root); err != nil {
		t.Fatal(err)
	}
	processes := &unstagedFailingStop{ProcessController: f.a.Processes, err: errors.New("exit status 255")}
	f.a.Processes = processes
	err := f.a.Rollback(f.ctx, f.nodePlan, root)
	if err == nil || !strings.Contains(err.Error(), "exit status 255") || processes.stops == 0 {
		t.Fatal("issued failure hidden", err, processes.stops)
	}
}

type unstagedFailingStop struct {
	ProcessController
	err   error
	stops int
}

func (p *unstagedFailingStop) Stop(context.Context, ProcessSpec) error { p.stops++; return p.err }

type unstagedClosingProcesses struct {
	ProcessController
	calls   int
	closing func()
}

func (p *unstagedClosingProcesses) Running(spec ProcessSpec) bool {
	p.calls++
	if p.calls == 4 {
		p.closing()
	}
	return p.ProcessController.Running(spec)
}
