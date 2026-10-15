package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Only structural physical reads and WAN are modeled. Store, saved consent,
// protected control, App admission and sanctioned CAS are production objects.
// No source compatibility, actual queue, process or native packet PASS claimed.
type nfqwsPacketModel struct {
	b                         *NFQWSPacketScopeBinding
	facts                     physicalscope.IPv4LANPacketFacts
	physicalErr               error
	current, retained, closed int
}

func (m *nfqwsPacketModel) Current(c context.Context) error {
	m.current++
	if _, ok := c.Deadline(); !ok {
		return errors.New("unbounded model use")
	}
	if err := m.b.app.Operations.WithExclusiveContext(c, func() error { return nil }); err != nil {
		return err
	}
	if release, err := m.b.app.Operations.Enter(context.Background()); !errors.Is(err, operationgate.ErrBusy) {
		if release != nil {
			release()
		}
		return errors.New("model escaped original exclusive operation")
	}
	i, err := m.b.intent(c)
	if err != nil || !reflect.DeepEqual(i, m.facts.Intent) {
		return errors.Join(ErrListScopeChanged, err)
	}
	return m.physicalErr
}
func (m *nfqwsPacketModel) RetainedCurrent(c context.Context) error {
	m.retained++
	return errors.Join(c.Err(), m.physicalErr)
}
func (m *nfqwsPacketModel) PacketFacts() physicalscope.IPv4LANPacketFacts {
	return defaultRoutePacketFactsClone(m.facts)
}
func (m *nfqwsPacketModel) Close() error { m.closed++; return nil }

func nfqwsPacketFixture(t *testing.T) (*App, *NFQWSPacketScopeBinding, *nfqwsPacketModel) {
	t.Helper()
	a, old, physical := listScopeFixture(t, "all", false)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	var b *NFQWSPacketScopeBinding
	model := &nfqwsPacketModel{}
	listScopeOperation(t, a, func(ctx context.Context) {
		epoch, err := a.Operations.ReviewControlEpoch(ctx, a.SelfUpdateFiles.ControlRoot)
		if err != nil {
			t.Fatal(err)
		}
		defer epoch.Close()
		manual := []config.ResourceMatch{{Kind: "cidr", Value: "203.0.113.128/25"}}
		if _, err = a.Store.UpdateResourceExclusions(ctx, a.Store.Get(), &manual, nil); err != nil {
			t.Fatal(err)
		}
		policy := config.CloneNetworkPolicy(a.Store.Get().NetworkPolicy)
		policy.Revision++
		policy.Clients.ExcludedDeviceIDs = []string{"mac-02-00-00-00-00-55"}
		policy.Clients.ExcludedCIDRs = []string{"192.168.1.64/26"}
		ref := epoch.Reference()
		if _, err = a.Store.ApproveDefaultRouteConsent(ctx, a.Store.Get(), policy, nil, ref.InstallationID, ref.Sequence); err != nil {
			t.Fatal(err)
		}
		b, err = newNFQWSPacketScopeBinding(ctx, a, func(c context.Context, binding *NFQWSPacketScopeBinding) (nfqwsPacketObserver, error) {
			i, e := binding.intent(c)
			if e != nil {
				return nil, e
			}
			model.b = binding
			model.facts = physicalscope.IPv4LANPacketFacts{ScopeID: strings.Repeat("9", 32), Identity: physical.facts.Identity, Control: binding.control.Reference(), Intent: i, Home: physical.facts.Segments[0], IPv4Prefixes: []string{"192.168.1.0/24"}, OwnedMACs: []string{"02:00:00:00:00:ff"}, OwnedAddresses: []string{"192.168.1.1", "fd00::1"}, ExcludedMACs: []string{"02:00:00:00:00:55"}}
			return model, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() { _ = b.Close() })
	return a, b, model
}

func nfqwsPacketCompilation(t *testing.T, c context.Context, a *App, b *NFQWSPacketScopeBinding) *DefaultRouteCompilation {
	t.Helper()
	s, err := b.Observe(c)
	if err != nil {
		t.Fatal(err)
	}
	_, paths, routes, _ := defaultRouteNFQWSComparisonFixture("tcp", "ipv4")
	routes[0].CIDRs = []string{"203.0.113.0/24"}
	compiled, err := CompileNFQWSIPv4LANPacketPolicy(a.Store.Get(), s, routes, map[string]DefaultRoutePath{"listed":paths.Paths["listed"]}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func TestNFQWSPacketActualScopeCASAndRetainedCleanup(t *testing.T) {
	a, b, m := nfqwsPacketFixture(t)
	listScopeOperation(t, a, func(c context.Context) {
		compiled := nfqwsPacketCompilation(t, c, a, b)
		if len(compiled.snapshot.Scope.Devices) != 0 || len(compiled.snapshot.Scope.Segments) != 0 || len(compiled.snapshot.Devices) != 0 {
			t.Fatal("packet facts fabricated membership")
		}
		if err := b.BindCompilation(c, compiled); err != nil {
			t.Fatal(err)
		}
		if err := b.BindCompilation(c, compiled); err == nil {
			t.Fatal("binding rebound")
		}
		snap, _ := b.Observe(c)
		snap.Facts.OwnedMACs[0] = "02:00:00:00:00:88"
		if err := b.ScopeCheck(c, compiled.LAN()); err != nil {
			t.Fatal("detached fact changed original", err)
		}
		before := a.Store.Get()
		approval := before.DefaultRouteConsent.ApprovalRevision
		started := time.Now()
		_, err := a.Store.CommitNetworkPolicyWithRollback(before, compiled.Policy(), before.Services)
		finished := time.Now()
		if err != nil {
			t.Fatal(err)
		}
		if err = b.AcceptCommitted(c, a.Store.Get(), started, finished); err != nil {
			t.Fatal("original packet owner did not survive sanctioned CAS", err)
		}
		if a.Store.Get().Revision <= before.Revision || b.snapshot.Facts.Intent.Revision != approval || a.Store.Get().DefaultRouteConsent.ApprovalRevision != approval {
			t.Fatal("ordinary config revision became packet intent revision")
		}
		if err = b.ScopeCheck(c, compiled.LAN()); err != nil {
			t.Fatal(err)
		}
		// A new DHCP endpoint has no authority to shrink/expand this structural
		// scope; classification of unseen membership remains the selected Home.
		f := DefaultRouteFlow{Ingress: "br0", MAC: "02:00:00:00:00:99", Source: netip.MustParseAddr("192.168.1.200"), Destination: netip.MustParseAddr("203.0.113.10"), Protocol: "tcp", DestinationPort: 443}
		if d := compiled.Classify(f); d.Kind != DefaultRouteOverride {
			t.Fatal("new Home endpoint requires fabricated DeviceBinding", d)
		}
		// Ordinary edits poison forward admission, but cannot strand original
		// receipt cleanup. The retained read never calls fresh intent/Store.
		if err = a.Store.UpdateService("listed", config.ServiceState{Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.201/32"}}); err != nil {
			t.Fatal(err)
		}
		if err = b.ScopeCheck(c, compiled.LAN()); err == nil {
			t.Fatal("ordinary edit adopted")
		}
		reads := m.current
		cleanup, err := a.Operations.ReviewExclusiveCleanup(c)
		if err != nil {
			t.Fatal(err)
		}
		if err = cleanup.WithCurrent(c, func() error { return b.cleanupScopeCheck(c, compiled.LAN()) }); err != nil {
			t.Fatal("edited intent blocked original cleanup", err)
		}
		if m.current != reads || m.retained != 1 {
			t.Fatal("cleanup consulted forward intent")
		}
		foreign := compiled.LAN()
		foreign.Generation = strings.Repeat("a", 64)
		if err = b.cleanupScopeCheck(c, foreign); err == nil {
			t.Fatal("foreign cleanup plan admitted")
		}
		m.physicalErr = errors.New("structural Home changed")
		if err = b.cleanupScopeCheck(c, compiled.LAN()); err == nil {
			t.Fatal("physical drift allowed cleanup")
		}
	})
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil || m.closed != 1 {
		t.Fatal("owner not closed once", err, m.closed)
	}
}

func TestNFQWSPacketClassifierNegativesPreserveBaseline(t *testing.T) {
	a, b, _ := nfqwsPacketFixture(t)
	listScopeOperation(t, a, func(c context.Context) {
		compiled := nfqwsPacketCompilation(t, c, a, b)
		base := DefaultRouteFlow{Ingress: "br0", MAC: "02:00:00:00:00:99", Source: netip.MustParseAddr("192.168.1.200"), Destination: netip.MustParseAddr("203.0.113.10"), Protocol: "tcp", DestinationPort: 443}
		for _, row := range []struct {
			name string
			edit func(*DefaultRouteFlow)
			want DefaultRouteDecisionKind
		}{
			{"new client", func(*DefaultRouteFlow) {}, DefaultRouteOverride},
			{"offline excluded MAC new address", func(f *DefaultRouteFlow) { f.MAC = "02:00:00:00:00:55" }, DefaultRouteExcluded},
			{"owned MAC", func(f *DefaultRouteFlow) { f.MAC = "02:00:00:00:00:ff" }, DefaultRouteExcluded},
			{"owned address", func(f *DefaultRouteFlow) { f.Source = netip.MustParseAddr("192.168.1.1") }, DefaultRouteExcluded},
			{"negative source", func(f *DefaultRouteFlow) { f.Source = netip.MustParseAddr("192.168.1.70") }, DefaultRouteExcluded},
			{"negative destination", func(f *DefaultRouteFlow) { f.Destination = netip.MustParseAddr("203.0.113.200") }, DefaultRouteExcluded},
			{"unlisted destination", func(f *DefaultRouteFlow) { f.Destination = netip.MustParseAddr("8.8.8.8") }, DefaultRouteBaseline},
			{"native owner VPN baseline mark irrelevant", func(f *DefaultRouteFlow) { f.Destination = netip.MustParseAddr("10.10.10.10") }, DefaultRouteExcluded},
			{"UDP", func(f *DefaultRouteFlow) { f.Protocol = "udp" }, DefaultRouteBaseline},
			{"wrong port", func(f *DefaultRouteFlow) { f.DestinationPort = 80 }, DefaultRouteBaseline},
			{"other LAN", func(f *DefaultRouteFlow) { f.Ingress = "br1" }, DefaultRouteOutside},
			{"outside Home source", func(f *DefaultRouteFlow) { f.Source = netip.MustParseAddr("192.168.2.20") }, DefaultRouteOutside},
		} {
			t.Run(row.name, func(t *testing.T) {
				f := base
				row.edit(&f)
				d := compiled.Classify(f)
				if d.Kind != row.want || row.want != DefaultRouteOverride && d.Route != "" {
					t.Fatal("baseline/negative precedence lost", d)
				}
			})
		}
	})
}

func TestNFQWSPacketDispatchRejectsCompositeBeforeReadsAndClosesBoth(t *testing.T) {
	a, legacy, lm := listScopeFixture(t, "all", false)
	_ = a
	_, packet, pm := nfqwsPacketFixture(t)
	e := &managedNFQWSListExecution{scope: legacy, packetScope: packet}
	e.self = e
	lreads, preads := lm.checks, pm.current
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e.originalScope() || e.scopeCurrent(ctx, nil) == nil || e.scopeCleanupCurrent(ctx, nil) == nil || e.scopeAcceptCommitted(ctx, config.Config{}, time.Now(), time.Now()) == nil {
		t.Fatal("composite dispatched")
	}
	if lm.checks != lreads || pm.current != preads {
		t.Fatal("invalid composite touched owners")
	}
	if err := e.close(); err != nil || lm.closes != 1 || pm.closed != 1 {
		t.Fatal("partial owner leaked", err, lm.closes, pm.closed)
	}
	for _, e := range []*managedNFQWSListExecution{nil, {}, {self: &managedNFQWSListExecution{}, packetScope: packet}} {
		if e.originalScope() {
			t.Fatal("nil/copied owner accepted")
		}
	}
}

func TestNFQWSPacketAcquireErrorClosesRetainedReviewAndPhysical(t *testing.T) {
	a, b, m := nfqwsPacketFixture(t)
	_ = b.Close()
	listScopeOperation(t, a, func(c context.Context) {
		var captured *NFQWSPacketScopeBinding
		_, err := newNFQWSPacketScopeBinding(c, a, func(_ context.Context, x *NFQWSPacketScopeBinding) (nfqwsPacketObserver, error) {
			captured = x
			return m, errors.New("partial physical acquire")
		})
		if err == nil || captured == nil || !captured.closed || captured.scope.Current(c) == nil || captured.control.Current(c) == nil || m.closed != 2 {
			t.Fatal("partial acquire leaked original owners", err, m.closed)
		}
	})
}
