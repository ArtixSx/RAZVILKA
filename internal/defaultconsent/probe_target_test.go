package defaultconsent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

func probeTargetFixture(t *testing.T) (*fixture, *Review) {
	t.Helper()
	f := consentFixture(t)
	_ = f.approve(t)
	manual := []config.ResourceMatch{{Kind: "suffix", Value: "excluded.example"}, {Kind: "ip", Value: "203.0.113.9"}, {Kind: "cidr", Value: "2001:db8::/32"}}
	after, err := f.store.UpdateResourceExclusions(f.ctx, f.store.Get(), &manual, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.policy = config.CloneNetworkPolicy(after.NetworkPolicy)
	f.policy.Revision++
	return f, f.approve(t)
}

func TestProbeTargetActualOwnerChecksWholePinnedSetBeforeLeaf(t *testing.T) {
	f, r := probeTargetFixture(t)
	for _, tt := range []struct {
		host string
		pins []netip.Addr
		want error
	}{
		{"www.cloudflare.com", nil, nil},
		{"discordsays.com", nil, nil},
		{"discordsez.com", []netip.Addr{netip.MustParseAddr("203.0.113.9")}, ErrProbeTargetExcluded},
		{"", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil},
		{"", []netip.Addr{netip.MustParseAddr("203.0.113.9")}, ErrProbeTargetExcluded},
		{"", []netip.Addr{netip.MustParseAddr("2001:db8::1")}, ErrProbeTargetExcluded},
		{"", nil, ErrProbeTargetUnknown},
		{"www.cloudflare.com", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil},
		{"excluded.example", nil, ErrProbeTargetExcluded},
		{"a.excluded.example", nil, ErrProbeTargetExcluded},
		{"notexcluded.example", nil, nil},
		{"excluded.example.evil.test", nil, nil},
		{"allowed.example", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("203.0.113.9")}, ErrProbeTargetExcluded},
		{"allowed.example", []netip.Addr{netip.MustParseAddr("2001:db8::1")}, ErrProbeTargetExcluded},
		{"allowed.example", []netip.Addr{{}}, ErrProbeTargetUnknown},
		{"https://allowed.example", nil, ErrProbeTargetUnknown},
	} {
		err := r.CheckProbeTarget(f.ctx, tt.host, tt.pins)
		if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("%s pins%v want%v got%v", tt.host, tt.pins, tt.want, err)
		}
	}
}

func TestProbeTargetCannotUseCopiedForeignReleasedOrStaleConsent(t *testing.T) {
	f, r := probeTargetFixture(t)
	var nilReview *Review
	copyReview := &Review{self: r.self, owner: r.owner, ref: r.ref}
	for _, bad := range []*Review{nilReview, {}, copyReview} {
		if err := bad.CheckProbeTarget(f.ctx, "allowed.example", nil); err == nil {
			t.Fatal("constructed target owner accepted")
		}
	}
	if err := r.CheckProbeTarget(context.Background(), "allowed.example", nil); err == nil {
		t.Fatal("unowned context accepted")
	}
	if err := f.store.UpdateService("new", config.ServiceState{Enabled: true, Route: "usque"}); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckProbeTarget(f.ctx, "allowed.example", nil); err == nil {
		t.Fatal("changed full config retained target permission")
	}
	f2, r2 := probeTargetFixture(t)
	f2.release()
	if err := r2.CheckProbeTarget(f2.ctx, "allowed.example", nil); err == nil {
		t.Fatal("released original lease accepted")
	}
}
