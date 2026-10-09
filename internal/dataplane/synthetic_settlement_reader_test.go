package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// Actual Manager scope, protected roots, operation Gate and durable Stop;
// physical observations are an explicit socket-free model. No CT socket opens.
func syntheticSettlementOwnerModel(t *testing.T) (*SyntheticDNSExecutionBinding, *operationgate.ControlEpochReview, *operationgate.ExclusiveCleanupReview, context.CancelFunc, func(), string) {
	t.Helper()
	m, a, plan, s, ctx := syntheticExecutionModel(t)
	g := new(operationgate.Gate)
	root := filepath.Join(t.TempDir(), "control")
	if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	original, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	held, release, err := g.ExclusiveContext(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	control, err := g.ReviewControlEpoch(held, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	b, err := m.BindSyntheticDNSExecution(s.contextWith(held), a, plan)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := control.ReviewExclusiveCleanup(held)
	if err != nil {
		t.Fatal(err)
	}
	return b, control, cleanup, cancel, release, root
}

func TestSyntheticSettlementOriginalCleanupAfterCancelStopAndRelease(t *testing.T) {
	b, control, cleanup, cancel, release, root := syntheticSettlementOwnerModel(t)
	if _, err := operationgate.RequestSelfUpdateStop(context.Background(), root, "11111111111111111111111111111111", 1); err != nil {
		t.Fatal(err)
	}
	cancel()
	b.scope.cancel()
	ctx, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	calls := 0
	if err := b.withSettlementCurrent(ctx, control, cleanup, func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatal(calls, err)
	}
	if b.Current(ctx) == nil {
		t.Fatal("cleanup revived forward binding")
	}
	release()
	if err := b.withSettlementCurrent(ctx, control, cleanup, func() error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatal("release revived observation", calls, err)
	}
}

func TestSyntheticSettlementOriginalScopeBookendsRefuseDrift(t *testing.T) {
	for _, kind := range []string{"copy", "unbounded", "cancelled", "scope-close", "registry", "registry-after", "root", "root-fd", "dns", "network", "profile-intent", "physical-before", "physical-after", "control-close"} {
		t.Run(kind, func(t *testing.T) {
			b, control, cleanup, _, _, _ := syntheticSettlementOwnerModel(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			calls := 0
			change := func() {
				switch kind {
				case "registry", "registry-after":
					b.scope.manager.registryMu.Lock()
					b.scope.manager.registryGeneration++
					b.scope.manager.registryMu.Unlock()
				case "root":
					// Windows pins the original open directory against rename.
					// Moving its lookup coordinate to an actual distinct inode
					// must still fail the SAME original anchor bookend.
					b.scope.root += "-replacement"
					if err := os.Mkdir(b.scope.root, 0700); err != nil {
						t.Fatal(err)
					}
				case "dns":
					b.adapter.DNS = new(dnscontrol.Manager)
				case "root-fd":
					_ = b.scope.owned.Close()
				case "network":
					b.adapter.InactivityIdentity = nil
				case "profile-intent":
					b.scope.plan.NetworkProfileID = "changed"
				case "control-close":
					_ = control.Close()
				}
			}
			switch kind {
			case "copy":
				copy := *b
				b = &copy
			case "unbounded":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "scope-close":
				_ = b.scope.close()
			case "registry-after":
			case "physical-before", "physical-after":
				identity := b.scope.networkIdentity
				original := identity.withCurrent
				reads := 0
				identity.withCurrent = func(c context.Context, use func(context.Context, netidentity.Identity) error) error {
					reads++
					if kind == "physical-before" || reads > 1 {
						return ErrNetworkPolicyIdentity
					}
					return original(c, use)
				}
			default:
				change()
			}
			err := b.withSettlementCurrent(ctx, control, cleanup, func() error {
				calls++
				if kind == "registry-after" {
					change()
				}
				return nil
			})
			if err == nil {
				t.Fatal("original owner drift admitted")
			}
			if kind == "physical-after" || kind == "registry-after" {
				if calls != 1 {
					t.Fatal("closing check not exercised", calls)
				}
			} else if calls != 0 {
				t.Fatal("refusal entered observation", calls)
			}
		})
	}
}

func TestSyntheticSettlementScopeCloseJoinsActualObservation(t *testing.T) {
	b, control, cleanup, _, _, _ := syntheticSettlementOwnerModel(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entered, finish := make(chan struct{}), make(chan struct{})
	observed, closed := make(chan error, 1), make(chan error, 1)
	go func() {
		observed <- b.withSettlementCurrent(ctx, control, cleanup, func() error { close(entered); <-finish; return nil })
	}()
	<-entered
	go func() { closed <- b.scope.close() }()
	select {
	case <-closed:
		t.Fatal("scope closed before original read joined")
	case <-time.After(10 * time.Millisecond):
	}
	close(finish)
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := b.withSettlementCurrent(ctx, control, cleanup, func() error { t.Fatal("closed scope entered"); return nil }); err == nil {
		t.Fatal("scope close revived")
	}
}

func TestSyntheticSettlementFactoryRefusesUnoriginalMappingBeforeReader(t *testing.T) {
	b, control, _, _, _, _ := syntheticSettlementOwnerModel(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, mapping := range []*dnscontrol.SyntheticDNSMapping{nil, new(dnscontrol.SyntheticDNSMapping)} {
		if _, err := b.settlementReader(ctx, mapping, control, nil); err == nil {
			t.Fatal("DTO issued reader")
		}
	}
	for _, r := range []*syntheticSettlementReader{nil, new(syntheticSettlementReader)} {
		if _, err := r.observe(ctx); err == nil {
			t.Fatal("DTO observed")
		}
	}
}

func TestSyntheticSettlementCaptureTerminalComparisonRequiresSameMappingAndAllJoins(t *testing.T) {
	// Explicit terminal-carrier state model only: no listener is constructed,
	// and this cannot pass the production factory's original mapping/FD checks.
	for _, kind := range []string{"joined", "close-only", "copy", "different-mapping", "different-prepared", "watch-not-joined", "mapping-not-joined", "tuple-drift", "endpoint-drift"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			mapping := new(dnscontrol.SyntheticDNSMapping)
			endpoint := netip.MustParseAddrPort("192.168.1.1:10443")
			c := &DomainPolicyTCPCapture{spec: DomainPolicyTCPCaptureSpec{Listen: endpoint}, closed: true, closeDone: make(chan struct{}), mappings: make(map[*dnscontrol.SyntheticDNSMapping]*DomainPolicyTCPCaptureMapping)}
			c.self = c
			close(c.closeDone)
			p := &DomainPolicyTCPCaptureMapping{capture: c, source: mapping, observation: syntheticCTModelMapping(), closed: true, closeDone: make(chan struct{}), watchDone: make(chan struct{})}
			p.self = p
			c.mappings[mapping] = p
			if kind != "mapping-not-joined" {
				close(p.closeDone)
			}
			if kind != "watch-not-joined" {
				close(p.watchDone)
			}
			terminal := &DomainPolicyTCPCaptureRetirement{capture: c, endpoint: endpoint, done: make(chan struct{})}
			terminal.self = terminal
			c.retirement = terminal
			if kind != "close-only" {
				close(terminal.done)
			}
			r := &syntheticSettlementReader{original: mapping, frozen: p.observation, capture: c, prepared: p, captureEnd: terminal, endpoint: endpoint}
			r.self = r
			switch kind {
			case "copy":
				// Copy comparison coordinates without copying sync.Once.
				r.captureEnd = &DomainPolicyTCPCaptureRetirement{self: terminal, capture: terminal.capture, endpoint: terminal.endpoint, done: terminal.done, result: terminal.result}
			case "different-mapping":
				p.source = new(dnscontrol.SyntheticDNSMapping)
			case "different-prepared":
				c.mappings[mapping] = new(DomainPolicyTCPCaptureMapping)
			case "tuple-drift":
				p.observation.RealIPv4 = p.observation.Client
			case "endpoint-drift":
				c.spec.Listen = netip.MustParseAddrPort("192.168.1.1:10444")
			}
			got, err := r.captureEndpoint(ctx)
			if kind == "joined" {
				if err != nil || got != endpoint {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("terminal DTO/drift/partial join became evidence")
			}
			if kind == "close-only" && !errors.Is(err, ErrDomainPolicyTCPCaptureRetirementPending) {
				t.Fatal(err)
			}
		})
	}
}

func TestSyntheticSettlementOriginalPublishedDNSSessionComparison(t *testing.T) {
	b, control, _, _, _, _ := syntheticSettlementOwnerModel(t)
	if _, err := b.originalSyntheticSession(control); err == nil {
		t.Fatal("missing original session admitted")
	}
	mode := &scopedDNSSyntheticMode{binding: b, control: control, source: new(dnscontrol.NetworkPolicyDNSSyntheticResolver)}
	s := &scopedDNSSession{synthetic: mode}
	scopedDNSInactivePublish(b.root, s)
	t.Cleanup(func() {
		scopedDNSInactiveLifecycle.Lock()
		delete(scopedDNSInactiveLifecycle.roots, b.root)
		scopedDNSInactiveLifecycle.Unlock()
	})
	if got, err := b.originalSyntheticSession(control); err != nil || got != s {
		t.Fatal(got, err)
	}
	// No fd/workers exist in this explicit registry comparison model.
	r := &syntheticSettlementReader{binding: b, session: s, mode: mode, source: mode.source, control: control}
	r.self = r
	if r.joinedDNS() == nil {
		t.Fatal("registry metadata became joined DNS evidence")
	}
	finish := scopedDNSInactiveMutation(b.root)
	if _, err := b.originalSyntheticSession(control); err == nil {
		t.Fatal("in-progress mutation admitted")
	}
	finish()
	other := &scopedDNSSession{synthetic: mode}
	scopedDNSInactivePublish(b.root, other)
	if _, err := b.originalSyntheticSession(control); err == nil {
		t.Fatal("duplicate original source session admitted")
	}
}
