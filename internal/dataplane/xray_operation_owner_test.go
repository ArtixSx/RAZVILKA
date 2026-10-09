package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

type xrayOperationProcessModel struct{ starts, stops int }

func (p *xrayOperationProcessModel) Start(context.Context, ProcessSpec) error { p.starts++; return nil }
func (p *xrayOperationProcessModel) Stop(context.Context, ProcessSpec) error  { p.stops++; return nil }
func (*xrayOperationProcessModel) Running(ProcessSpec) bool                   { return false }

type xrayOperationFixture struct {
	f        *nodeDefaultSourceFixture
	manager  *Manager
	adapter  *ProxyTunnelAdapter
	model    *xrayOperationProcessModel
	control  *operationgate.ControlEpochReview
	ctx      context.Context
	cancel   context.CancelFunc
	release  func()
	spec     XraySelectedTCPRedirectSpec
	material *XrayOperationMaterial
	scope    *executionResourceScope
}

func newXrayOperationFixture(t *testing.T) *xrayOperationFixture {
	t.Helper()
	f, proof, a, spec := xraySelectedTCPMaterialFixture(t)
	x := &xrayOperationFixture{f: f, adapter: a, spec: spec, model: &xrayOperationProcessModel{}, manager: New(privateScopedXrayFixtureDir(t))}
	a.Processes = x.model
	if err := x.manager.Register(a); err != nil {
		t.Fatal(err)
	}
	gate := &operationgate.Gate{}
	x.ctx, x.cancel = context.WithCancel(f.ctx)
	t.Cleanup(x.cancel)
	var err error
	x.ctx, x.release, err = gate.ExclusiveContext(x.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.release)
	controlRoot := filepath.Join(privateScopedXrayFixtureDir(t), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(x.ctx, controlRoot); err != nil {
		t.Fatal(err)
	}
	x.control, err = gate.ReviewControlEpoch(x.ctx, controlRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.control.Close() })
	x.material, err = ReviewXrayOperationMaterial(x.ctx, x.manager, x.control, a, proof, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.material.Close() })
	return x
}

func (x *xrayOperationFixture) originalScope(t *testing.T) context.Context {
	t.Helper()
	service := x.material.material.proof.service
	p := Plan{SchemaVersion: SchemaVersion, PlanID: "dp-0123456789abcdef", Digest: strings.Repeat("b", 64), NetworkProfileID: x.material.material.ref.WANProfile, Adapters: []string{"xray"}, LAN: CloneLANPolicyRuntime(x.spec.LAN),
		Routes: []Route{{ServiceID: service.ID, LogicalServiceID: service.ID, ProbeService: &service, ProbeURL: service.ProbeURL, Selected: "xray:" + x.spec.NodeID, Resolved: "xray:" + x.spec.NodeID,
			CIDRs: append([]string(nil), service.CIDRs...), NetworkPolicyGeneration: x.spec.Generation}}}
	execution := &Execution{PlanID: p.PlanID, Digest: p.Digest}
	root := filepath.Join(x.manager.StateRoot, "transactions", execution.PlanID)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, err := x.material.Context(WithReviewGuard(x.ctx, func(c context.Context) error { return c.Err() }))
	if err != nil {
		t.Fatal(err)
	}
	x.scope, err = x.manager.newExecutionResourceScope(ctx, p, "xray", execution, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.scope.close() })
	return ctx
}

func TestXrayOperationCarrierBindsOnlyOriginalPrivateScopeAndNeverLaunches(t *testing.T) {
	x := newXrayOperationFixture(t)
	ctx := x.originalScope(t)
	o, err := newXrayOperationOwner(ctx, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := o.context(ctx)
	if err != nil || bound.Value(xrayOperationOwnerKey{}) != o || bound.Value(xrayOperationMaterialKey{}) != x.material || x.material.IsCleanupContext(bound) {
		t.Fatal("original forward scope binding failed", err)
	}
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	clean, err := o.cleanupContext(cleanup)
	if err != nil || !x.material.IsCleanupContext(clean) || x.material.IsCleanupContext(context.WithValue(clean, xrayOperationMaterialKey{}, &XrayOperationMaterial{})) {
		t.Fatal("cleanup did not retain same original identity", err)
	}
	if len(x.scope.execution.Resources) != 0 || x.model.starts != 0 || x.model.stops != 0 {
		t.Fatal("carrier published a resource or launched a process")
	}
	if _, err := o.context(nil); !errors.Is(err, ErrXrayOperationOwner) {
		t.Fatal("nil owner context accepted")
	}
	copy := xrayOperationOwner{self: o.self, material: o.material, scope: o.scope}
	if _, err := copy.context(ctx); !errors.Is(err, ErrXrayOperationOwner) {
		t.Fatal("copied private owner accepted")
	}
	copyMaterial := XrayOperationMaterial{self: x.material.self, manager: x.material.manager, adapter: x.material.adapter, material: x.material.material}
	if _, err := copyMaterial.Context(ctx); !errors.Is(err, ErrXrayOperationOwner) {
		t.Fatal("copied operation material accepted")
	}
	if err := x.material.Close(); err != nil || len(x.material.material.config) != 0 || x.material.material.proof.Current(x.f.ctx) != nil || x.control.Current(x.ctx) != nil {
		t.Fatal("Close erased shared owners or retained private bytes", err)
	}
	if _, err := o.cleanupContext(cleanup); !errors.Is(err, ErrXrayOperationOwner) {
		t.Fatal("closed carrier still bound cleanup")
	}
}

func TestXrayOperationOwnerRejectsForeignScopeAndChangedIntent(t *testing.T) {
	for _, bad := range []string{"foreign-manager", "foreign-adapter", "LAN", "WAN", "CIDRs", "extra-node-route", "malformed-xray-route", "automatic-route", "predicate", "missing-generation", "unissued"} {
		t.Run(bad, func(t *testing.T) {
			x := newXrayOperationFixture(t)
			ctx := x.originalScope(t)
			s := x.scope
			switch bad {
			case "foreign-manager":
				s.manager = New(s.manager.StateRoot)
			case "foreign-adapter":
				clone := *x.adapter
				s.adapterOwner = &clone
			case "LAN":
				s.plan.LAN.Ingress[0].ExcludedMACs = nil
			case "WAN":
				s.plan.NetworkProfileID = "wan-fedcba987654"
			case "CIDRs":
				s.plan.Routes[0].CIDRs = []string{"1.1.1.0/25"}
			case "extra-node-route":
				s.plan.Routes = append(s.plan.Routes, s.plan.Routes[0])
			case "malformed-xray-route":
				s.plan.Routes = append(s.plan.Routes, Route{Selected: "xray:bad", Resolved: "unknown"})
			case "automatic-route":
				s.plan.Routes[0].Selected = "auto"
			case "predicate":
				s.plan.Routes[0].ProbeService.ProbeURL = "https://8.8.8.8/"
			case "missing-generation":
				s.plan.Routes[0].NetworkPolicyGeneration = ""
			case "unissued":
				ctx = WithReviewGuard(x.ctx, func(c context.Context) error { return c.Err() })
			}
			if o, err := newXrayOperationOwner(ctx, s); o != nil || !errors.Is(err, ErrXrayOperationOwner) {
				t.Fatal("foreign or broadened scope admitted", err)
			}
			if x.model.starts != 0 {
				t.Fatal("bad scope reached process")
			}
		})
	}
}

func TestXrayOperationCancellationKeepsOnlyOriginalFiniteCleanup(t *testing.T) {
	x := newXrayOperationFixture(t)
	ctx := x.originalScope(t)
	o, err := newXrayOperationOwner(ctx, x.scope)
	if err != nil {
		t.Fatal(err)
	}
	x.cancel()
	fresh, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := o.context(fresh); err == nil {
		t.Fatal("fresh context revived canceled forward")
	}
	cleanup, err := o.cleanupContext(fresh)
	if err != nil || !x.material.IsCleanupContext(cleanup) {
		t.Fatal("same held operation lost bounded compensation", err)
	}
	if _, err := o.cleanupContext(context.Background()); err == nil {
		t.Fatal("unbounded cleanup accepted")
	}
	x.release()
	if _, err := o.cleanupContext(fresh); err == nil {
		t.Fatal("released original operation revived cleanup")
	}
	if x.model.starts != 0 || x.model.stops != 0 {
		t.Fatal("cleanup marker issued actual launch or stop")
	}
}

func TestXrayOperationOwnerRevokesRegistryProcessShapeAndGuardChanges(t *testing.T) {
	for _, change := range []string{"registry", "binary", "process-controller", "scope-close", "guard"} {
		t.Run(change, func(t *testing.T) {
			x := newXrayOperationFixture(t)
			ctx := x.originalScope(t)
			o, err := newXrayOperationOwner(ctx, x.scope)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "registry":
				if err := x.manager.Register(&fakeAdapter{id: "other"}); err != nil {
					t.Fatal(err)
				}
			case "binary":
				x.adapter.EngineBin += ".replacement"
			case "process-controller":
				x.adapter.Processes = &xrayOperationProcessModel{}
			case "scope-close":
				if err := x.scope.close(); err != nil {
					t.Fatal(err)
				}
			case "guard":
				x.scope.guard = func(context.Context) error { return errors.New("actual App physics changed") }
			}
			if _, err := o.context(ctx); err == nil {
				t.Fatal("changed original owner remained usable")
			}
			if change == "guard" {
				x.scope.guard = func(c context.Context) error { return c.Err() }
				if _, err := o.context(ctx); err == nil {
					t.Fatal("sticky forward guard refusal revived")
				}
			}
			if x.model.starts != 0 || x.model.stops != 0 {
				t.Fatal("revocation launched a process")
			}
		})
	}
}

func TestXrayOperationCloseCancelsBeforeJoiningOriginalRead(t *testing.T) {
	x := newXrayOperationFixture(t)
	entered, finished := make(chan struct{}), make(chan error, 1)
	var armed atomic.Bool
	x.adapter.Resolver = func(c context.Context, _ string) ([]netip.Addr, error) {
		if armed.CompareAndSwap(true, false) {
			close(entered)
			<-c.Done()
			return nil, c.Err()
		}
		return []netip.Addr{netip.MustParseAddr("9.9.9.9")}, nil
	}
	armed.Store(true)
	go func() { _, err := x.material.Context(x.ctx); finished <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original read did not enter")
	}
	closed := make(chan error, 1)
	go func() { closed <- x.material.Close() }()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled read returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked without canceling original reader")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join reader")
	}
	if len(x.material.material.config) != 0 || x.material.material.proof.Current(x.f.ctx) != nil || x.model.starts != 0 {
		t.Fatal("Close leaked bytes or closed shared proof/process")
	}
}
