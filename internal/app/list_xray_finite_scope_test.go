package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Actual App, Store/CAS/control/ScopeReview, node/source proof, registered
// adapter and compiler. Only the physical/WAN and recorded-health I/O are
// existing explicit models. Physical finite decoding has separate real tests.
func modeledXrayFiniteScope(t *testing.T, ctx context.Context, f *listXraySourceFixture) *xrayFiniteScopeBinding {
	t.Helper()
	b, err := newXrayFiniteScopeBinding(ctx, f.a, func(c context.Context, selection physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error) {
		verify, snapshot, close, err := f.physical.acquire(c, selection)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		observe := func() physicalscope.FiniteIPv4PacketObservation {
			s := snapshot()
			return physicalscope.FiniteIPv4PacketObservation{ReviewID: s.ReviewID, Identity: s.Identity, Selection: s.Selection, Segments: s.Segments, Devices: s.Devices,
				UnresolvedRouter: []physicalscope.FiniteIPv4UnresolvedRouter{{Interface: "br0", IfIndex: 3, Address: "fe80::99", State: 32, Flags: 128, Type: 1}}}
		}
		retained := func(c context.Context) error {
			if _, bounded := c.Deadline(); !bounded || c.Err() != nil {
				return errors.Join(physicalscope.ErrUnknown, c.Err())
			}
			return f.physical.verifyErr
		}
		return verify, observe, retained, close, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func finiteXraySource(t *testing.T, c context.Context, f *listXraySourceFixture, b *xrayFiniteScopeBinding, service string) *XrayListRuntimeSource {
	t.Helper()
	r, err := f.a.reviewXrayListRuntimeSourceOwner(c, xrayRuntimeScope{finite: b}, service, f.adapter, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestFiniteXrayAppOriginalSourceShapeAndClosedIssuerChoice(t *testing.T) {
	f, service := newSelectedTCPInlineScopeFixture(t)
	listScopeOperation(t, f.a, func(ctx context.Context) {
		b := modeledXrayFiniteScope(t, ctx, f)
		r := finiteXraySource(t, ctx, f, b, service.ID)
		p, err := r.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer p.close()
		if r.scope != nil || r.finiteScope != b || b.compilation != p.compilation || len(b.facts.UnresolvedRouter) != 1 {
			t.Fatal("finite issuer replaced by full binding")
		}
		lan := p.compilation.LAN()
		if !slices.Equal(lan.Ingress[0].Sources, []string{"192.168.1.40/32"}) || lan.Ingress[0].Membership != "mac" || len(lan.Ingress[0].IncludedMACs) != 1 {
			t.Fatal("finite source widened")
		}
		var destinations []string
		for _, rule := range p.compilation.rules {
			destinations = append(destinations, rule.Destination.String())
			if rule.Protocol != "tcp" || rule.FirstPort != 443 || rule.LastPort != 443 {
				t.Fatal("traffic scope widened")
			}
		}
		if !slices.Equal(destinations, service.CIDRs) {
			t.Fatal("finite destinations changed")
		}
		if err := p.current(ctx); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(lan.Ingress[0].ExcludedMACs, "02:00:00:00:00:FF") {
			t.Fatal("known router negative lost")
		}
		// Copy the owner references without copying its synchronization object.
		copy := &xrayFiniteScopeBinding{self: b, app: b.app, store: b.store, scope: b.scope, expected: b.expected, facts: b.facts, bound: b.bound}
		if copy.ScopeCheck(ctx, lan) == nil || copy.Close() == nil {
			t.Fatal("copied issuer adopted")
		}
		both := xrayRuntimeScope{full: f.scope, finite: b}
		if both.matches(f.a, f.a.Store) || both.ScopeCheck(ctx, lan) == nil || both.cleanupScopeCheck(ctx, lan) == nil {
			t.Fatal("both issuer variants adopted")
		}
		if _, err := f.a.ReviewXrayListRuntimeSource(ctx, nil, service.ID, f.adapter); err == nil {
			t.Fatal("unbound full source adopted finite data")
		}
		before := r.expected
		_, started, finished := xrayAssemblySourceCAS(t, r)
		if err := r.acceptCommitted(ctx, started, finished); err != nil {
			t.Fatal("original finite CAS refused", err)
		}
		if !reflect.DeepEqual(b.expected, r.store.Get()) || b.expected.Revision != before.Revision+1 || b.compilation != p.compilation {
			t.Fatal("CAS replaced original issuer/shape")
		}
		if err := p.current(ctx); err != nil {
			t.Fatal(err)
		}
		r.scope = f.scope
		if r.Current(ctx) == nil {
			t.Fatal("source adopted both issuers")
		}
		r.scope = nil
		if r.Current(ctx) == nil {
			t.Fatal("restored union revived source")
		}
	})
}

func TestFiniteXrayAppPurposeRefusesGenericBroaderModeBeforeBinding(t *testing.T) {
	f, service := newSelectedTCPInlineScopeFixture(t)
	listScopeOperation(t, f.a, func(ctx context.Context) {
		b := modeledXrayFiniteScope(t, ctx, f)
		r := finiteXraySource(t, ctx, f, b, service.ID)
		if p, err := r.prepare(ctx); err == nil || p != nil || b.boundOnce || b.compilation != nil {
			t.Fatal("general Xray mode alone adopted finite issuer")
		}
	})
}

func TestFiniteXrayAppFrozenShapeDriftRefusesForwardAndRetained(t *testing.T) {
	for _, change := range []string{"subnet", "all", "two-macs", "nfq-mode", "mark-mode", "drop-router-negative", "tcp80", "udp", "ipv6-positive", "private-destination", "drop-destination", "shared-dns"} {
		t.Run(change, func(t *testing.T) {
			f, service := newSelectedTCPInlineScopeFixture(t)
			listScopeOperation(t, f.a, func(ctx context.Context) {
				b := modeledXrayFiniteScope(t, ctx, f)
				r := finiteXraySource(t, ctx, f, b, service.ID)
				p, err := r.prepare(ctx, true)
				if err != nil {
					t.Fatal(err)
				}
				defer p.close()
				c := p.compilation
				originalPlan, originalRules, originalDNS := c.LAN(), c.Rules(), c.snapshot.DNSMode
				g := originalPlan.Ingress[0]
				mode := originalPlan.Mode
				switch change {
				case "subnet":
					g.Sources = []string{"192.168.1.0/24"}
				case "all":
					g.Membership = "all"
					g.IncludedMACs = nil
				case "two-macs":
					g.IncludedMACs = append(slices.Clone(g.IncludedMACs), "02:00:00:00:00:02")
				case "nfq-mode":
					mode = dataplane.LANPolicyNFQWSDirectMode
				case "mark-mode":
					mode = ""
				case "drop-router-negative":
					g.ExcludedMACs = nil
				case "tcp80":
					c.rules[0].FirstPort, c.rules[0].LastPort = 80, 80
				case "udp":
					c.rules[0].Protocol = "udp"
				case "ipv6-positive":
					c.rules[0].Source = netip.MustParsePrefix("fd00::40/128")
					c.rules[0].Destination = netip.MustParsePrefix("2606:4700::/32")
				case "private-destination":
					c.rules[0].Destination = netip.MustParsePrefix("192.168.2.0/24")
				case "drop-destination":
					c.rules = c.rules[:1]
				case "shared-dns":
					c.snapshot.DNSMode = "shared"
				}
				if change == "mark-mode" {
					c.lan, err = dataplane.CompileLANPolicyRuntime(c.Digest(), []dataplane.LANPolicyIngress{g})
				} else if change == "nfq-mode" {
					c.lan, err = dataplane.CompileNFQWSDirectLANPolicyRuntime(c.Digest(), []dataplane.LANPolicyIngress{g})
				} else {
					c.lan, err = dataplane.CompileXraySelectedTCPLANPolicyRuntime(c.Digest(), []dataplane.LANPolicyIngress{g})
				}
				if err != nil {
					t.Fatal("generic compiler must allow this comparison image", mode, err)
				}
				if b.ScopeCheck(ctx, originalPlan) == nil || b.cleanupScopeCheck(ctx, originalPlan) == nil {
					t.Fatal("broader/changed compilation adopted")
				}
				c.lan, c.rules, c.snapshot.DNSMode = originalPlan, originalRules, originalDNS
				if b.ScopeCheck(ctx, originalPlan) == nil || b.cleanupScopeCheck(ctx, originalPlan) == nil {
					t.Fatal("restored compilation revived issuer")
				}
			})
		})
	}
}

func TestFiniteXrayAppRetainedCleanupDoesNotReviveOrdinaryEdit(t *testing.T) {
	f, service := newSelectedTCPInlineScopeFixture(t)
	listScopeOperation(t, f.a, func(ctx context.Context) {
		b := modeledXrayFiniteScope(t, ctx, f)
		r := finiteXraySource(t, ctx, f, b, service.ID)
		p, err := r.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer p.close()
		plan := p.compilation.LAN()
		cleanup, err := f.a.Operations.ReviewExclusiveCleanup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		state := f.a.Store.Get().Services[service.ID]
		state.Enabled = false
		if err := f.a.Store.UpdateService(service.ID, state); err != nil {
			t.Fatal(err)
		}
		if b.ScopeCheck(ctx, plan) == nil {
			t.Fatal("ordinary edit retained forward")
		}
		c, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := cleanup.WithCurrent(c, func() error { return b.cleanupScopeCheck(c, plan) }); err != nil {
			t.Fatal("same original cleanup lost", err)
		}
		wrong := dataplane.CloneLANPolicyRuntime(plan)
		wrong.Generation = "foreign"
		if b.cleanupScopeCheck(c, wrong) == nil {
			t.Fatal("foreign plan adopted")
		}
		f.physical.verifyErr = physicalscope.ErrUnknown
		if err := b.cleanupScopeCheck(c, plan); !errors.Is(err, physicalscope.ErrUnknown) {
			t.Fatal("physical refusal waived", err)
		}
		if b.ScopeCheck(ctx, plan) == nil {
			t.Fatal("cleanup revived forward")
		}
	})
}

func TestFiniteXrayAppCanceledSourceKeepsExactModeReceiptOwner(t *testing.T) {
	f, service := newSelectedTCPInlineScopeFixture(t)
	mode := "manual"
	if err := f.a.Store.UpdateServiceControl(&mode, nil, f.a.Store.Get().Revision); err != nil {
		t.Fatal(err)
	}
	listScopeOperation(t, f.a, func(ctx context.Context) {
		b := modeledXrayFiniteScope(t, ctx, f)
		r := finiteXraySource(t, ctx, f, b, service.ID)
		p, err := r.prepare(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		defer p.close()
		input := (&DefaultRouteExecutor{app: f.a}).input(p.compilation, r.expected)
		plan := defaultRouteClonePlan(dataplane.Plan{Routes: input.Routes, LAN: p.compilation.LAN(), NetworkProfileID: input.NetworkProfileID})
		_, started, finished := xrayAssemblySourceCAS(t, r)
		if err := r.acceptCommitted(ctx, started, finished); err != nil {
			t.Fatal(err)
		}
		original := b.expected
		r.cancel()
		undo, receipt, err := r.store.UpdateManualToAutoReviewed(ctx, r.expected.Revision)
		if err != nil {
			t.Fatal(err)
		}
		defer undo()
		if err := r.acceptServiceModeComparison(ctx, receipt, plan, nil, false); err != nil {
			t.Fatal("same finite mode comparison lost", err)
		}
		if !reflect.DeepEqual(b.expected, original) || r.ctx.Err() == nil || r.scope != nil || r.finiteScope != b {
			t.Fatal("mode transition replaced original finite scope")
		}
		if err := receipt.Accept(ctx); err != nil {
			t.Fatal(err)
		}
		if r.acceptServiceModeComparison(ctx, receipt, plan, nil, false) == nil {
			t.Fatal("receipt reused")
		}
	})
}

func TestFiniteXrayAppRefusesWiderIntentAtAcquisition(t *testing.T) {
	a, full, m := listScopeFixture(t, "all", false)
	listScopeOperation(t, a, func(ctx context.Context) {
		acquired := false
		b, err := newXrayFiniteScopeBinding(ctx, a, func(c context.Context, s physicalscope.SelectionReader) (func(context.Context) error, func() physicalscope.FiniteIPv4PacketObservation, func(context.Context) error, func() error, error) {
			if _, err := s(c); err != nil {
				return nil, nil, nil, nil, err
			}
			acquired = true
			return nil, nil, nil, nil, nil
		})
		if err == nil || b != nil || acquired || full.closed || m.closes != 0 {
			t.Fatal("wider intent reached finite physical acquisition")
		}
	})
}
