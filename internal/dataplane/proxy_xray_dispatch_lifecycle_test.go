package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// These public lifecycle fixtures use local files, a real NodeStore compiler,
// in-memory exact process/kernel state and a paired selected/control witness.
// They launch no executable and perform no DNS/network/native observation.
type xrayDispatchProcesses struct {
	base   *proxyFakeProcesses
	active map[string]ProcessSpec
	starts int
	stops  int
}

func (p *xrayDispatchProcesses) Start(ctx context.Context, spec ProcessSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.starts++
	spec.Args = append([]string(nil), spec.Args...)
	p.active[spec.ID] = spec
	return p.base.Start(ctx, spec)
}

func (p *xrayDispatchProcesses) Stop(ctx context.Context, spec ProcessSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if current, exists := p.active[spec.ID]; exists && !reflect.DeepEqual(current, spec) {
		return fmt.Errorf("fixture refused wrong process mode or exact argv: %s", spec.ID)
	}
	p.stops++
	delete(p.active, spec.ID)
	return p.base.Stop(ctx, spec)
}

func (p *xrayDispatchProcesses) Running(spec ProcessSpec) bool {
	current, exists := p.active[spec.ID]
	return exists && p.base.Running(spec) && reflect.DeepEqual(current, spec)
}

type xrayDispatchFixture struct {
	t             *testing.T
	a             *ProxyTunnelAdapter
	registered    *ProxyTunnelAdapter
	scoped        *scopedXrayFixture
	processes     *xrayDispatchProcesses
	ctx           context.Context
	genericPlan   Plan
	nodePlan      Plan
	commands      []string
	materialized  int
	nodeProofs    int
	canaryProofs  int
	genericProbes int
	failNode      bool
	failGeneric   bool
}

func newXrayDispatchFixture(t *testing.T) *xrayDispatchFixture {
	t.Helper()
	scoped := scopedXrayTestFixture(t)
	scoped.a.Configs.LiveRoot = filepath.Join(privateScopedXrayFixtureDir(t), "live-configs")
	materializer := scoped.a.NodeRoutes
	a, err := NewXrayRuntimeAdapter(scoped.a.Configs, filepath.Dir(scoped.a.StateRoot), materializer)
	if err != nil {
		t.Fatal(err)
	}
	f := &xrayDispatchFixture{t: t, a: a, registered: a, scoped: scoped, nodePlan: scoped.plan}
	// The explicit paired-client verifier is the approved portable test path.
	// This one-time startup choice remains constant throughout every operation.
	a.nodeRouterVerifier = false
	f.processes = &xrayDispatchProcesses{base: scoped.processes, active: map[string]ProcessSpec{}}
	a.Processes = f.processes
	a.EngineBin, a.SidecarBin, a.IP, a.IPTables, a.IP6Tables = scoped.a.EngineBin, scoped.a.SidecarBin, scoped.a.IP, scoped.a.IPTables, scoped.a.IP6Tables
	a.FreshProfile, a.bootIdentity, a.Resolver = scoped.a.FreshProfile, scoped.a.bootIdentity, scoped.a.Resolver
	a.nodeEndpointDial = scoped.a.nodeEndpointDial
	a.SOCKSProbe, a.ServiceIPProbe = scoped.a.SOCKSProbe, scoped.a.ServiceIPProbe
	baseRunner := scoped.a.Runner
	a.Runner = networkCleanupRunner(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		f.commands = append(f.commands, name+" "+strings.Join(args, " "))
		return baseRunner.Run(ctx, name, args...)
	})
	a.NodeRoutes = func(ctx context.Context, requests []NodeRouteRequest, profile string, now time.Time) (NodeRouteMaterial, error) {
		f.materialized++
		return materializer(ctx, requests, profile, now)
	}
	a.nodeRuntimeIdentity = func(spec ProcessSpec, address string) (string, error) {
		if !f.processes.Running(spec) {
			return "", errors.New("fixture exact process/mode absent")
		}
		data, err := os.ReadFile(spec.MatchArg)
		if err != nil {
			return "", err
		}
		return spec.ID + ":" + strconv.Itoa(scoped.identity) + ":" + routeidentity.Hash(data), nil
	}
	// One coherent private pair sample; no action/controller/identity/boot
	// callback is invoked by this fixture's final local observer.
	a.xrayRetirementPairObserver = func(ctx context.Context, specs [2]ProcessSpec) (xrayRetirementPair, error) {
		var pair xrayRetirementPair
		for i, spec := range specs {
			current, exists := f.processes.active[spec.ID]
			if !exists || !reflect.DeepEqual(current, spec) || ctx.Err() != nil {
				return pair, ErrProxyPolicyUnknown
			}
			data, err := readBoundedProxyConfig(spec.MatchArg)
			if err != nil {
				return pair, err
			}
			pair[i] = xrayRetirementProcessIdentity{Receipt: routeidentity.Receipt{Version: 1, PID: 100 + i,
				BootID: "boot-test", StartTicks: strconv.Itoa(scoped.identity), Executable: spec.Binary,
				ArgsHash:   routeidentity.Hash([]byte(strings.Join(append([]string{spec.Binary}, spec.Args...), "\x00") + "\x00")),
				ConfigHash: routeidentity.Hash(data)}, Namespace: "fixture-owned-netns"}
			clear(data)
		}
		return pair, nil
	}
	paired := scoped.a.NodeTUNProbe
	a.NodeTUNProbe = func(ctx context.Context, request NodeTUNRequest) (NodeTUNObservation, error) {
		f.nodeProofs++
		if f.failNode {
			return NodeTUNObservation{}, errors.New("fixture candidate node service failed")
		}
		return paired(ctx, request)
	}
	a.CanaryProbe = func(ctx context.Context, rawURL, address string) error {
		f.canaryProofs++
		return scoped.a.CanaryProbe(ctx, rawURL, address)
	}
	a.Probe = func(context.Context, string) error {
		f.genericProbes++
		if f.failGeneric {
			return errors.New("fixture candidate generic service failed")
		}
		return nil
	}
	f.genericPlan = Plan{NetworkProfileID: executionNetwork, EngineDrafts: []string{"xray/main"}, Routes: []Route{{
		ServiceID: "telegram", ServiceName: "Telegram", Selected: "xray", Resolved: "xray", CIDRs: []string{"8.8.8.8/32"}, Sources: []string{"192.168.1.25/32"}, ProbeURL: "https://telegram.org/",
	}}}
	f.ctx = WithReviewGuard(context.Background(), func(context.Context) error { return nil })
	f.constantOwner()
	return f
}

func (f *xrayDispatchFixture) constantOwner() {
	f.t.Helper()
	if f.a != f.registered || f.a.ID() != "xray" || f.a.StateRoot != f.scoped.a.StateRoot || f.a.scopedXray || !f.a.xrayPlanDispatch || f.a.nodeRouterVerifier {
		f.t.Fatal("public operation mutated/replaced the registered startup owner")
	}
}

func (f *xrayDispatchFixture) freshOwner() *ProxyTunnelAdapter {
	f.t.Helper()
	// Reconstruct the same startup coordinates after a simulated app restart;
	// current private metadata, rather than a caller plan, chooses Deactivate.
	a, err := NewXrayRuntimeAdapter(f.a.Configs, filepath.Dir(f.a.StateRoot), f.a.NodeRoutes)
	if err != nil {
		f.t.Fatal(err)
	}
	a.nodeRouterVerifier = false
	a.EngineBin, a.SidecarBin, a.IP, a.IPTables, a.IP6Tables = f.a.EngineBin, f.a.SidecarBin, f.a.IP, f.a.IPTables, f.a.IP6Tables
	a.Processes, a.Runner, a.FreshProfile, a.bootIdentity = f.a.Processes, f.a.Runner, f.a.FreshProfile, f.a.bootIdentity
	a.Resolver, a.SOCKSProbe, a.ServiceIPProbe = f.a.Resolver, f.a.SOCKSProbe, f.a.ServiceIPProbe
	a.nodeEndpointDial = f.a.nodeEndpointDial
	a.CanaryProbe, a.Probe = f.a.CanaryProbe, f.a.Probe
	a.NodeTUNProbe, a.nodeRuntimeIdentity = f.a.NodeTUNProbe, f.a.nodeRuntimeIdentity
	a.xrayRetirementPairObserver = f.a.xrayRetirementPairObserver
	if a.scopedXray || !a.xrayPlanDispatch || a.nodeRouterVerifier {
		f.t.Fatal("fresh constructor changed registered startup flags")
	}
	return a
}

func (f *xrayDispatchFixture) plan(mode string) Plan {
	if mode == "node" {
		return f.nodePlan
	}
	return f.genericPlan
}

func (f *xrayDispatchFixture) stageGeneric(config string) {
	f.t.Helper()
	if config == "" {
		config = `{"outbounds":[` + strings.Replace(xrayRemoteExit, "edge.example", "1.1.1.1", 1) + `]}`
	}
	if _, err := f.a.Configs.Stage("xray", "main", config); err != nil {
		f.t.Fatal(err)
	}
}

func (f *xrayDispatchFixture) stage(mode string) string {
	f.t.Helper()
	plan := f.plan(mode)
	if mode == "generic" {
		f.stageGeneric("")
	}
	root := privateScopedXrayFixtureDir(f.t)
	for _, step := range []struct {
		name string
		run  func(context.Context, Plan, string) error
	}{{"Snapshot", f.a.Snapshot}, {"Stage", f.a.Stage}, {"Validate", f.a.Validate}} {
		if err := step.run(f.ctx, plan, root); err != nil {
			f.t.Fatal(mode, step.name, err)
		}
		f.constantOwner()
	}
	if err := f.a.Canary(f.ctx, plan.RoutePlanFor("xray"), root); err != nil {
		f.t.Fatal(mode, "Canary", err)
	}
	f.constantOwner()
	return root
}

func (f *xrayDispatchFixture) commit(mode string) string {
	f.t.Helper()
	root := f.stage(mode)
	for _, step := range []struct {
		name string
		run  func(context.Context, Plan, string) error
	}{{"Activate", f.a.Activate}, {"Health", f.a.Health}, {"Commit", f.a.Commit}} {
		if err := step.run(f.ctx, f.plan(mode), root); err != nil {
			f.t.Fatal(mode, step.name, err)
		}
		f.constantOwner()
	}
	f.current(mode)
	return root
}

func (f *xrayDispatchFixture) current(mode string) {
	f.t.Helper()
	view := *f.a
	view.scopedXray = mode == "node"
	if !f.processes.Running(view.engineProcess()) || !f.processes.Running(view.sidecarProcess()) {
		f.t.Fatal("current exact engine/sidecar process mode differs", mode)
	}
	if _, err := os.Lstat(f.a.nodeManifestPath()); mode == "node" && err != nil || mode == "generic" && !errors.Is(err, os.ErrNotExist) {
		f.t.Fatal("private node manifest presence differs from current mode", mode, err)
	}
	if _, err := os.Lstat(f.a.nodeInterfacePath()); mode == "node" && err != nil || mode == "generic" && !errors.Is(err, os.ErrNotExist) {
		f.t.Fatal("private scoped interface lease presence differs from current mode", mode, err)
	}
	f.constantOwner()
}

func TestXrayDispatchPublicLifecycleGenericAndNode(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		t.Run(mode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(mode)
			if mode == "generic" && f.materialized != 0 || mode == "node" && (f.materialized == 0 || f.nodeProofs == 0) {
				t.Fatal("public owner used the wrong config/verifier path")
			}
			starts, stops := f.processes.starts, f.processes.stops
			if err := f.a.Reconcile(f.ctx, f.plan(mode)); err != nil {
				t.Fatal("healthy public Reconcile", err)
			}
			if f.processes.starts != starts || f.processes.stops != stops {
				t.Fatal("healthy dispatch Reconcile restarted the owner")
			}
			if _, err := f.a.RefreshPolicy(f.ctx, f.plan(mode)); err != nil {
				t.Fatal("public RefreshPolicy", err)
			}
			f.current(mode)
		})
	}
}

func TestXrayDispatchPublicLifecycleCrossModeRollbackRestoresExactOldOwner(t *testing.T) {
	for _, oldMode := range []string{"generic", "node"} {
		t.Run(oldMode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(oldMode)
			oldEngine, _ := os.ReadFile(f.a.engineConfigPath())
			oldSidecar, _ := os.ReadFile(f.a.sidecarConfigPath())
			oldPolicy, exists, err := f.a.loadPolicy()
			if err != nil || !exists {
				t.Fatal(err)
			}
			newMode := "node"
			if oldMode == "node" {
				newMode = "generic"
			}
			root := f.stage(newMode)
			if err := f.a.Activate(f.ctx, f.plan(newMode), root); err != nil {
				t.Fatal("cross-mode Activate", err)
			}
			f.current(newMode)
			f.failNode, f.failGeneric = newMode == "node", newMode == "generic"
			// Generic legacy health skips source-only service probes; replace the
			// exact SOCKS readiness callback to fail that actual public path.
			probe := f.a.SOCKSProbe
			if newMode == "generic" {
				f.a.SOCKSProbe = func(context.Context, string) error { return errors.New("fixture candidate SOCKS failed") }
			}
			nodeProofs := f.nodeProofs
			if err := f.a.Health(f.ctx, f.plan(newMode), root); err == nil {
				t.Fatal("candidate failure was not observed")
			}
			if newMode == "node" && f.nodeProofs != nodeProofs+1 {
				t.Fatal("node candidate failure did not exercise its independent paired witness")
			}
			f.a.SOCKSProbe = probe
			f.failNode, f.failGeneric = false, false
			if err := f.a.Rollback(f.ctx, f.plan(newMode), root); err != nil {
				t.Fatal("cross-mode Rollback", err)
			}
			ok, err := f.a.VerifyRollback(f.ctx, f.plan(newMode), root)
			if err != nil || !ok {
				t.Fatal("cross-mode restoration was not verified", ok, err)
			}
			engine, _ := os.ReadFile(f.a.engineConfigPath())
			sidecar, _ := os.ReadFile(f.a.sidecarConfigPath())
			policy, exists, err := f.a.loadPolicy()
			if err != nil || !exists || string(engine) != string(oldEngine) || string(sidecar) != string(oldSidecar) || !reflect.DeepEqual(policy, oldPolicy) {
				t.Fatal("rollback did not restore exact old config and policy", err)
			}
			f.current(oldMode)
			if err := f.a.Reconcile(f.ctx, f.plan(oldMode)); err != nil {
				t.Fatal("restored old owner is not healthy", err)
			}
		})
	}
}

func TestXrayDispatchPublicLifecycleStageFailureKeepsOldModeUntouched(t *testing.T) {
	for _, oldMode := range []string{"generic", "node"} {
		t.Run(oldMode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(oldMode)
			newMode := "node"
			if oldMode == "node" {
				newMode = "generic"
				f.stageGeneric(`{"outbounds":[{"protocol":"freedom"}]}`)
			}
			root := privateScopedXrayFixtureDir(t)
			if err := f.a.Snapshot(f.ctx, f.plan(newMode), root); err != nil {
				t.Fatal(err)
			}
			if newMode == "node" {
				f.a.NodeRoutes = func(context.Context, []NodeRouteRequest, string, time.Time) (NodeRouteMaterial, error) {
					return NodeRouteMaterial{}, errors.New("fixture materialization refused")
				}
			}
			before := nodeRouterTransitReadbackTree(t, f.a.StateRoot)
			active := make(map[string]ProcessSpec, len(f.processes.active))
			for id, spec := range f.processes.active {
				active[id] = spec
			}
			starts, stops, mutations := f.processes.starts, f.processes.stops, len(receiptMutationCalls(f.commands))
			if err := f.a.Stage(f.ctx, f.plan(newMode), root); err == nil {
				t.Fatal("invalid candidate Stage passed")
			}
			if f.processes.starts != starts || f.processes.stops != stops || len(receiptMutationCalls(f.commands)) != mutations ||
				!reflect.DeepEqual(active, f.processes.active) || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, f.a.StateRoot)) {
				t.Fatal("failed Stage changed current old runtime/kernel/private state")
			}
			f.current(oldMode)
		})
	}
}

func TestXrayDispatchPublicLifecycleRetirementSnapshotCapturesExactRunningOldMode(t *testing.T) {
	for _, oldMode := range []string{"generic", "node"} {
		t.Run(oldMode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(oldMode)
			root := privateScopedXrayFixtureDir(t)
			plan := Plan{NetworkProfileID: executionNetwork, RetiringAdapters: []string{"xray"}, Routes: []Route{{ServiceID: "other", Selected: "sing-box", Resolved: "sing-box"}}}
			before := nodeRouterTransitReadbackTree(t, f.a.StateRoot)
			starts, stops, mutations := f.processes.starts, f.processes.stops, len(receiptMutationCalls(f.commands))
			if err := f.a.Snapshot(f.ctx, plan, root); err != nil {
				t.Fatal("retirement Snapshot", err)
			}
			snapshot, err := readProxySnapshot(root)
			if err != nil || snapshot.CandidateXrayMode != "cold" || snapshot.PreviousXrayMode != oldMode ||
				!snapshot.EngineWasRunning || !snapshot.SidecarWasRunning || !snapshot.PolicyWasActive || !snapshot.PolicyTracked ||
				snapshot.NodeManifestExists != (oldMode == "node") || snapshot.NodeInterfaceExists != (oldMode == "node") {
				t.Fatal("retirement Snapshot did not bind complete exact live old mode", snapshot.CandidateXrayMode, snapshot.PreviousXrayMode, err)
			}
			if f.processes.starts != starts || f.processes.stops != stops || len(receiptMutationCalls(f.commands)) != mutations ||
				!reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, f.a.StateRoot)) {
				t.Fatal("retirement Snapshot changed live old owner")
			}
			f.current(oldMode)
		})
	}
}

func TestXrayDispatchPublicLifecycleSnapshotModeBindingRefusesChangedCandidateBeforeEffects(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		for _, change := range []string{"passed-plan", "snapshot-marker"} {
			for _, operation := range []string{"Stage", "Canary", "Activate", "Rollback", "VerifyRollback"} {
				t.Run(mode+"/"+change+"/"+operation, func(t *testing.T) {
					f := newXrayDispatchFixture(t)
					root := f.stage(mode)
					otherMode := "node"
					if mode == "node" {
						otherMode = "generic"
					}
					plan := f.plan(mode)
					if change == "passed-plan" {
						plan = f.plan(otherMode)
					} else {
						snapshot, err := readProxySnapshot(root)
						if err != nil {
							t.Fatal(err)
						}
						snapshot.CandidateXrayMode = otherMode
						data, err := json.Marshal(snapshot)
						if err != nil || os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0600) != nil {
							t.Fatal("could not replace fixture marker", err)
						}
					}
					before := nodeRouterTransitReadbackTree(t, root)
					beforeState := nodeRouterTransitReadbackTree(t, filepath.Dir(f.a.StateRoot))
					starts, stops, commands, materialized := f.processes.starts, f.processes.stops, len(f.commands), f.materialized
					var err error
					switch operation {
					case "Stage":
						err = f.a.Stage(f.ctx, plan, root)
					case "Canary":
						err = f.a.Canary(f.ctx, plan.RoutePlanFor("xray"), root)
					case "Activate":
						err = f.a.Activate(f.ctx, plan, root)
					case "Rollback":
						err = f.a.Rollback(f.ctx, plan, root)
					case "VerifyRollback":
						_, err = f.a.VerifyRollback(f.ctx, plan, root)
					}
					if !errors.Is(err, ErrProxyPolicyUnknown) || f.processes.starts != starts || f.processes.stops != stops || len(f.commands) != commands || f.materialized != materialized ||
						!reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, root)) || !reflect.DeepEqual(beforeState, nodeRouterTransitReadbackTree(t, filepath.Dir(f.a.StateRoot))) {
						t.Fatal("changed candidate binding reached an operation effect", err)
					}
					f.constantOwner()
				})
			}
		}
	}
}

func TestXrayDispatchPublicLifecycleSnapshotMarkerDriftDuringAdmissionRefusesBeforeEffects(t *testing.T) {
	for _, operation := range []string{"Stage", "Activate"} {
		for _, marker := range []string{"generic", ""} {
			t.Run(operation+"/marker="+marker, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				root := f.stage("node")
				before := nodeRouterTransitReadbackTree(t, root)
				delete(before, "snapshot.json") // The callback alone changes this fixture file.
				beforeState := nodeRouterTransitReadbackTree(t, filepath.Dir(f.a.StateRoot))
				starts, stops, commands, materialized := f.processes.starts, f.processes.stops, len(f.commands), f.materialized
				cut := false
				f.a.FreshProfile = func(ctx context.Context) (string, error) {
					if !cut {
						cut = true
						snapshot, err := readProxySnapshot(root)
						if err != nil || snapshot.CandidateXrayMode != "node" {
							t.Fatal("cut was not after first bound snapshot read", err)
						}
						snapshot.CandidateXrayMode = marker
						data, err := json.Marshal(snapshot)
						if err != nil || os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0600) != nil {
							t.Fatal("could not replace fixture marker", err)
						}
					}
					return executionNetwork, ctx.Err()
				}
				var err error
				if operation == "Stage" {
					err = f.a.Stage(f.ctx, f.nodePlan, root)
				} else {
					err = f.a.Activate(f.ctx, f.nodePlan, root)
				}
				after := nodeRouterTransitReadbackTree(t, root)
				delete(after, "snapshot.json")
				if !cut || !errors.Is(err, ErrProxyPolicyUnknown) || f.processes.starts != starts || f.processes.stops != stops || len(f.commands) != commands || f.materialized != materialized ||
					!reflect.DeepEqual(before, after) || !reflect.DeepEqual(beforeState, nodeRouterTransitReadbackTree(t, filepath.Dir(f.a.StateRoot))) {
					t.Fatal("admission callback marker drift reached an operation effect", cut, err)
				}
				f.constantOwner()
			})
		}
	}
}

func TestXrayDispatchPublicLifecycleFreshRollbackRetryRestoresBothOldModes(t *testing.T) {
	for _, oldMode := range []string{"generic", "node"} {
		t.Run(oldMode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(oldMode)
			oldEngine, _ := os.ReadFile(f.a.engineConfigPath())
			oldSidecar, _ := os.ReadFile(f.a.sidecarConfigPath())
			oldSpecs := map[string]ProcessSpec{}
			for id, spec := range f.processes.active {
				oldSpecs[id] = spec
			}
			newMode := "node"
			if oldMode == "node" {
				newMode = "generic"
			}
			root := f.stage(newMode)
			if err := f.a.Activate(f.ctx, f.plan(newMode), root); err != nil {
				t.Fatal("cross-mode Activate", err)
			}
			f.a.Processes = &proxyRollbackRetryProcesses{base: f.processes, failStopID: "xray-engine", failStopOnce: true}
			if err := f.a.Rollback(f.ctx, f.plan(newMode), root); err == nil {
				t.Fatal("transient Stop cut was not reached")
			}
			candidate, err := f.a.readStagedPolicy(root)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := f.a.readCandidatePolicyReceipt(root, candidate)
			if err != nil || receipt.Phase != "restoring" {
				t.Fatal("retry did not retain durable restoring phase", receipt, err)
			}
			status, err := f.a.additionStatus(f.ctx, candidate, root)
			if err != nil || !status.Removed || status.Unknown {
				t.Fatal("candidate cleanup was not settled before retry", status, err)
			}
			fresh := f.freshOwner()
			if err := fresh.Rollback(f.ctx, f.plan(newMode), root); err != nil {
				t.Fatal("fresh public cross-mode Rollback", err)
			}
			if ok, err := fresh.VerifyRollback(f.ctx, f.plan(newMode), root); err != nil || !ok {
				t.Fatal("fresh public restored old mode was not verified", ok, err)
			}
			engine, _ := os.ReadFile(f.a.engineConfigPath())
			sidecar, _ := os.ReadFile(f.a.sidecarConfigPath())
			if string(engine) != string(oldEngine) || string(sidecar) != string(oldSidecar) || !reflect.DeepEqual(oldSpecs, f.processes.active) {
				t.Fatal("fresh retry did not restore old config and exact ProcessSpecs/RouteProof")
			}
			f.current(oldMode)
			if fresh.scopedXray || !fresh.xrayPlanDispatch || fresh.nodeRouterVerifier {
				t.Fatal("fresh retry mutated startup owner flags")
			}
		})
	}
}

func TestXrayDispatchPublicLifecycleLegacyGenericSnapshotHeaderAllowsNodeCandidateAndRollback(t *testing.T) {
	f := newXrayDispatchFixture(t)
	f.commit("generic")
	oldEngine, _ := os.ReadFile(f.a.engineConfigPath())
	oldSidecar, _ := os.ReadFile(f.a.sidecarConfigPath())
	oldSpecs := map[string]ProcessSpec{}
	for id, spec := range f.processes.active {
		oldSpecs[id] = spec
	}
	root := privateScopedXrayFixtureDir(t)
	if err := f.a.Snapshot(f.ctx, f.nodePlan, root); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readProxySnapshot(root)
	if err != nil || snapshot.PreviousXrayMode != "generic" || !snapshot.EngineWasRunning || !snapshot.SidecarWasRunning {
		t.Fatal("fixture did not capture live old generic mode", err)
	}
	// Legacy generic snapshots omit both engine/sidecar header identities. The
	// complete captured generic files and receipts still constrain restoration.
	snapshot.EngineID, snapshot.SidecarKind = "", ""
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "snapshot.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		name string
		run  func(context.Context, Plan, string) error
	}{{"Stage", f.a.Stage}, {"Validate", f.a.Validate}} {
		if err := step.run(f.ctx, f.nodePlan, root); err != nil {
			t.Fatal("legacy generic header", step.name, err)
		}
	}
	if err := f.a.Canary(f.ctx, f.nodePlan.RoutePlanFor("xray"), root); err != nil {
		t.Fatal("legacy generic header Canary", err)
	}
	if err := f.a.Activate(f.ctx, f.nodePlan, root); err != nil {
		t.Fatal("legacy generic header Activate", err)
	}
	f.current("node")
	if err := f.a.Rollback(f.ctx, f.nodePlan, root); err != nil {
		t.Fatal("legacy generic header Rollback", err)
	}
	if ok, err := f.a.VerifyRollback(f.ctx, f.nodePlan, root); err != nil || !ok {
		t.Fatal("legacy generic old owner not verified", ok, err)
	}
	engine, _ := os.ReadFile(f.a.engineConfigPath())
	sidecar, _ := os.ReadFile(f.a.sidecarConfigPath())
	if string(engine) != string(oldEngine) || string(sidecar) != string(oldSidecar) || !reflect.DeepEqual(oldSpecs, f.processes.active) {
		t.Fatal("legacy header rollback changed exact old generic config/process mode")
	}
	f.current("generic")
}

func TestXrayDispatchPublicLifecycleInvalidPlanRefusesEveryEntryBeforeEffects(t *testing.T) {
	for _, invalid := range []string{"mixed", "malformed-node"} {
		for _, operation := range []string{"Snapshot", "Stage", "Validate", "Canary", "Activate", "Health", "Commit", "Reconcile", "RefreshPolicy", "Rollback", "VerifyRollback"} {
			t.Run(invalid+"/"+operation, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				plan := f.nodePlan
				plan.Routes = append([]Route(nil), plan.Routes...)
				if invalid == "mixed" {
					plan.Routes = append(plan.Routes, f.genericPlan.Routes...)
				} else {
					plan.Routes[0].Selected, plan.Routes[0].Resolved = "xray:node-", "xray:node-"
				}
				root := privateScopedXrayFixtureDir(t)
				before := nodeRouterTransitReadbackTree(t, root)
				beforeState := nodeRouterTransitReadbackTree(t, filepath.Dir(f.a.StateRoot))
				starts, stops, commands := f.processes.starts, f.processes.stops, len(f.commands)
				var err error
				switch operation {
				case "Snapshot":
					err = f.a.Snapshot(f.ctx, plan, root)
				case "Stage":
					err = f.a.Stage(f.ctx, plan, root)
				case "Validate":
					err = f.a.Validate(f.ctx, plan, root)
				case "Canary":
					err = f.a.Canary(f.ctx, plan.RoutePlanFor("xray"), root)
				case "Activate":
					err = f.a.Activate(f.ctx, plan, root)
				case "Health":
					err = f.a.Health(f.ctx, plan, root)
				case "Commit":
					err = f.a.Commit(f.ctx, plan, root)
				case "Reconcile":
					err = f.a.Reconcile(f.ctx, plan)
				case "RefreshPolicy":
					_, err = f.a.RefreshPolicy(f.ctx, plan)
				case "Rollback":
					err = f.a.Rollback(f.ctx, plan, root)
				case "VerifyRollback":
					_, err = f.a.VerifyRollback(f.ctx, plan, root)
				}
				if err == nil || f.processes.starts != starts || f.processes.stops != stops || len(f.commands) != commands || f.materialized != 0 || f.nodeProofs != 0 ||
					!reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, root)) || !reflect.DeepEqual(beforeState, nodeRouterTransitReadbackTree(t, filepath.Dir(f.a.StateRoot))) {
					t.Fatal("invalid plan reached effects, materialization or a public fallback", err)
				}
				f.constantOwner()
			})
		}
	}
}

func TestXrayDispatchPublicLifecycleCanaryRejectsWrongAdapterAndForeignRouteBeforeEffects(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		for _, invalid := range []string{"wrong-adapter", "foreign-route"} {
			t.Run(mode+"/"+invalid, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				// Keep a fully usable staged candidate and valid snapshot present:
				// rejection must come from this call's original canary scope.
				root := f.stage(mode)
				plan := f.plan(mode).RoutePlanFor("xray")
				if invalid == "wrong-adapter" {
					plan.Adapter = "sing-box"
				} else {
					plan.Routes = append(plan.Routes, Route{ServiceID: "foreign", Selected: "sing-box", Resolved: "sing-box", CIDRs: []string{"9.9.9.9/32"}})
				}
				before := nodeRouterTransitReadbackTree(t, root)
				beforeState := nodeRouterTransitReadbackTree(t, filepath.Dir(f.a.StateRoot))
				starts, stops, commands := f.processes.starts, f.processes.stops, len(f.commands)
				materialized, nodeProofs, canaryProofs, genericProbes := f.materialized, f.nodeProofs, f.canaryProofs, f.genericProbes
				if err := f.a.Canary(f.ctx, plan, root); !errors.Is(err, ErrProxyPolicyUnknown) {
					t.Fatal("invalid original RoutePlan was not refused", err)
				}
				if f.processes.starts != starts || f.processes.stops != stops || len(f.commands) != commands ||
					f.materialized != materialized || f.nodeProofs != nodeProofs || f.canaryProofs != canaryProofs || f.genericProbes != genericProbes ||
					!reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, root)) || !reflect.DeepEqual(beforeState, nodeRouterTransitReadbackTree(t, filepath.Dir(f.a.StateRoot))) {
					t.Fatal("invalid Canary scope reached a callback, process, kernel or file effect")
				}
				f.constantOwner()
			})
		}
	}
}

func TestXrayDispatchPublicLifecycleNoPlanDeactivateUsesCurrentModeAndRefusesNodeMetadataLoss(t *testing.T) {
	for _, mode := range []string{"generic", "node"} {
		t.Run(mode, func(t *testing.T) {
			f := newXrayDispatchFixture(t)
			f.commit(mode)
			fresh := f.freshOwner()
			if err := fresh.Deactivate(f.ctx); err != nil {
				t.Fatal("current-mode no-plan Deactivate", err)
			}
			if len(f.processes.active) != 0 {
				t.Fatal("no-plan Deactivate did not stop the exact current mode")
			}
			if fresh.scopedXray || !fresh.xrayPlanDispatch || fresh.nodeRouterVerifier {
				t.Fatal("no-plan Deactivate mutated fresh startup owner flags")
			}
			f.constantOwner()
		})
	}
	for _, artifact := range []string{"manifest", "interface"} {
		for _, damage := range []string{"missing", "corrupt"} {
			t.Run(artifact+"/"+damage, func(t *testing.T) {
				f := newXrayDispatchFixture(t)
				f.commit("node")
				path := f.a.nodeManifestPath()
				if artifact == "interface" {
					path = f.a.nodeInterfacePath()
				}
				var err error
				if damage == "missing" {
					err = os.Remove(path)
				} else {
					err = os.WriteFile(path, []byte(`{"schema":999}`), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				before := nodeRouterTransitReadbackTree(t, f.a.StateRoot)
				starts, stops, commands := f.processes.starts, f.processes.stops, len(f.commands)
				fresh := f.freshOwner()
				if err := fresh.Deactivate(f.ctx); err == nil {
					t.Fatal("lost scoped metadata silently became generic cleanup")
				}
				if f.processes.starts != starts || f.processes.stops != stops || len(f.commands) != commands || !reflect.DeepEqual(before, nodeRouterTransitReadbackTree(t, f.a.StateRoot)) {
					t.Fatal("ambiguous no-plan Deactivate consumed cleanup authority or mutated state")
				}
				f.constantOwner()
			})
		}
	}
}
