package dataplane

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wgDomainRefusalRunner struct{ t *testing.T }

func (r wgDomainRefusalRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.t.Fatalf("refusal must precede runtime commands: %s %s", name, strings.Join(args, " "))
	return nil, nil
}

// The 2026-10-18 incident class: service domains became /32 routes and the
// tunnel captured unrelated sites on the same address. The WireGuard family
// must refuse that intake exactly like the legacy proxy TUN.
func TestWGSharedDomainAddressRefusedBeforeCapture(t *testing.T) {
	shared := netip.MustParseAddr("8.6.112.1")
	plan := Plan{Routes: []Route{{ServiceID: "telegram", Resolved: "warp-wg", Domains: []string{"telegram.org"}, Sources: []string{"192.0.2.40/32"}}}}
	prefixes, err := resolvePolicyPrefixes(context.Background(), plan, "warp-wg", func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{shared}, nil })
	if err != nil || len(prefixes) != 1 || prefixes[0] != "8.6.112.1/32" {
		t.Fatalf("shared-IP reproduction failed: %v %v", prefixes, err)
	}
	for _, c := range []struct {
		route string
		build func(string) *WARPWireGuardAdapter
	}{
		{"warp-wg", func(root string) *WARPWireGuardAdapter { return NewWARPWireGuardAdapter(nil, root) }},
		{"amneziawg", func(root string) *WARPWireGuardAdapter { return NewAmneziaWGAdapter(nil, root) }},
		{"wireguard", func(root string) *WARPWireGuardAdapter { return NewWireGuardAdapter(nil, root) }},
		{"wireguard:home", func(root string) *WARPWireGuardAdapter { return NewWireGuardAdapter(nil, root) }},
	} {
		for _, mixed := range []bool{false, true} {
			state := filepath.Join(t.TempDir(), "state-never-created")
			a := c.build(state)
			a.Runner = wgDomainRefusalRunner{t}
			a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
				t.Fatal("refusal must precede DNS work")
				return nil, nil
			}
			candidate := Plan{Routes: []Route{{ServiceID: "telegram", Resolved: c.route, Domains: []string{"telegram.org"}, Sources: []string{"192.0.2.40/32"}}}}
			if mixed {
				candidate.Routes[0].CIDRs = []string{"149.154.160.0/20"}
			}
			root := filepath.Join(t.TempDir(), "never-created")
			if err := a.Stage(context.Background(), candidate, root); !errors.Is(err, ErrWGDomainAuthority) {
				t.Fatalf("%s mixed=%v: stage %v", c.route, mixed, err)
			}
			var preflight preflightRefusalError
			if err := a.Activate(context.Background(), candidate, root); !errors.Is(err, ErrWGDomainAuthority) || !errors.As(err, &preflight) {
				t.Fatalf("%s: activation accepted domain capture: %v", c.route, err)
			}
			if err := a.Reconcile(context.Background(), candidate); !errors.Is(err, ErrWGDomainAuthority) {
				t.Fatalf("%s: reconciliation restored domain capture: %v", c.route, err)
			}
			if changed, err := a.RefreshPolicy(context.Background(), candidate); changed || !errors.Is(err, ErrWGDomainAuthority) {
				t.Fatalf("%s: refresh extended unsafe capture: %v %v", c.route, changed, err)
			}
			for _, path := range []string{root, state} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("%s: refused intake wrote %s", c.route, path)
				}
			}
		}
	}
	// Another adapter's domain route is not this adapter's authority question.
	other := NewWireGuardAdapter(nil, t.TempDir())
	if err := other.requireLegacyIPPolicyAuthority(Plan{Routes: []Route{{Resolved: "nfqws2", Domains: []string{"youtube.com"}}, {Resolved: "warp-wg", Domains: []string{"other.example"}}, {Resolved: "wireguard", CIDRs: []string{"149.154.160.0/20"}}}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ErrWGDomainAuthority.Error(), "telegram") || strings.Contains(ErrWGDomainAuthority.Error(), shared.String()) {
		t.Fatal("reason contains private flow material")
	}
}

// A committed CIDR policy must not grow into DNS-derived capture through the
// periodic refresh or recovery path, while Stop and an interrupted domain
// transaction can still settle the runtime already installed.
func TestWGRefreshCannotWidenCommittedCaptureToDomains(t *testing.T) {
	a, runner, plan, transaction := wgReceiptFixture(t)
	oldState, oldRef := commitWGReceiptFixture(t, a, plan, transaction)
	before, err := os.ReadFile(a.statePath())
	if err != nil {
		t.Fatal(err)
	}
	a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("refresh resolved service domains")
		return nil, nil
	}
	widened := plan
	widened.Routes = append([]Route(nil), plan.Routes...)
	widened.Routes[0].Domains = []string{"telegram.org"}
	runner.calls = nil
	if changed, err := a.RefreshPolicy(context.Background(), widened); changed || !errors.Is(err, ErrWGDomainAuthority) {
		t.Fatal("refresh accepted domain capture", changed, err)
	}
	if err := a.Reconcile(context.Background(), widened); !errors.Is(err, ErrWGDomainAuthority) {
		t.Fatal("recovery accepted domain capture", err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("refused refresh touched runtime", runner.calls)
	}
	after, err := os.ReadFile(a.statePath())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused refresh changed the committed policy", err)
	}
	if ref, err := a.committedWGPolicyReference(oldState); err != nil || ref.ID != oldRef.ID {
		t.Fatal("refused refresh replaced the committed generation", ref, err)
	}
	if err := verifyPolicyEvidence(context.Background(), a.Runner, a.ip(), oldState); err != nil {
		t.Fatal("committed CIDR policy lost", err)
	}
	// An interrupted domain transaction still rolls back without touching the
	// committed generation; it never reached activation.
	retry := filepath.Join(t.TempDir(), "retry")
	if err := (&wgReceiptManagerAdapter{a}).Snapshot(context.Background(), widened, retry); err != nil {
		t.Fatal(err)
	}
	if err := a.Stage(context.Background(), widened, retry); !errors.Is(err, ErrWGDomainAuthority) {
		t.Fatal("domain stage accepted", err)
	}
	if err := a.Rollback(context.Background(), widened, retry); err != nil {
		t.Fatal("rollback of a refused domain transaction failed", err)
	}
	if err := verifyPolicyEvidence(context.Background(), a.Runner, a.ip(), oldState); err != nil {
		t.Fatal("refused transaction rollback removed committed policy", err)
	}
	if err := a.Deactivate(context.Background()); err != nil {
		t.Fatal("Stop of an already installed tunnel failed", err)
	}
	if runner.active || len(runner.policy.entries) != 0 {
		t.Fatal("Stop left the tunnel or its policy", runner.active, runner.policy.entries)
	}
	if _, err := os.Stat(a.statePath()); !os.IsNotExist(err) {
		t.Fatal("Stop retained ownership state", err)
	}
}
