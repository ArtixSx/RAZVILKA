package startuptools

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestWGInactivityStartupFactoryRefusesUnissuedExpiredAndChangedAbsence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, lease := range []*Lease{nil, {}, unitLease(t)} {
		if source, err := lease.ReviewWGInactivity(ctx, nil, nil, "wireguard"); source != nil || !errors.Is(err, ErrUnknown) {
			t.Fatal("unissued/foreign profile minted source", err)
		}
	}
	l := managedListDescriptorFixture(t, [2]bool{false, false})
	if source, err := l.ReviewWGInactivity(context.Background(), nil, nil, "wireguard"); source != nil || err == nil {
		t.Fatal("unbounded source minted")
	}
	if err := os.WriteFile(l.profile.wgAliases[0], []byte("unreviewed occupant"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{"wireguard", "amneziawg"} {
		source, err := l.ReviewWGInactivity(ctx, nil, nil, engine)
		var failure *failure
		if source != nil || !errors.As(err, &failure) || failure.stage != "WG_ABSENCE_CHANGED" {
			t.Fatal("actual changed absence reached source assembly", engine, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if source, err := l.ReviewWGInactivity(ctx, nil, nil, "wireguard"); source != nil || err == nil {
		t.Fatal("closed lease minted source")
	}
}

func TestWGInactivityStartupSourceRequiresSameOriginalLeaseAndEngine(t *testing.T) {
	l := unitLease(t)
	r := &wgInactivityRunner{l, "wireguard"}
	if !r.SameWGToolSource(&wgRunner{l, "wireguard"}) {
		t.Fatal("same original lease refused")
	}
	for _, other := range []*wgRunner{nil, {l, "amneziawg"}, {unitLease(t), "wireguard"}, {nil, "wireguard"}} {
		if r.SameWGToolSource(other) {
			t.Fatal("foreign source compared as original")
		}
	}
}

func TestWGInactivityStartupIndependentABIRejectsEffectsAndFallback(t *testing.T) {
	l := managedListDescriptorFixture(t, [2]bool{true, false})
	for _, test := range []struct {
		name string
		args []string
	}{
		{l.profile.wgAliases[0], []string{"show", "all", "public-key"}},
		{l.profile.aliases[0], []string{"-t", "filter", "-S"}},
		{l.profile.aliases[1], []string{"-t", "nat", "-S"}},
		{l.profile.ipAlias, []string{"-j", "link", "show"}},
		{l.profile.ipAlias, []string{"-N", "-6", "rule", "show"}},
		{l.profile.ipAlias, []string{"-N", "-details", "-j", "route", "show", "table", "206"}},
		{l.profile.ipAlias, []string{"-N", "-j", "route", "show", "table", "205", "exact", "1.1.1.1/32"}},
		{l.profile.ipAlias, []string{"route", "show", "table", "213"}},
		{l.profile.ipAlias, []string{"route", "show", "table", "213", "exact", "1.1.1.1/32"}},
	} {
		if !wgInactivitySourceArguments(l, test.name, test.args) {
			t.Fatal("fixed readonly ABI refused", test)
		}
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{l.profile.wgAliases[1], []string{"show", "all", "public-key"}},
		{"wg", []string{"show", "all", "public-key"}},
		{l.profile.wgAliases[0], []string{"show", "all", "dump"}},
		{l.profile.wgAliases[0], []string{"setconf", "rz-wg", "private.conf"}},
		{l.profile.aliases[0], []string{"-t", "filter", "-F"}},
		{l.profile.ipAlias, []string{"rule", "show"}},
		{l.profile.ipAlias, []string{"-N", "-N", "rule", "show"}},
		{l.profile.ipAlias, []string{"-N", "-4", "-6", "rule", "show"}},
		{l.profile.ipAlias, []string{"-j", "link", "show", "dev", "rz-wg"}},
		{l.profile.ipAlias, []string{"-N", "route", "show", "table", "all"}},
		{l.profile.ipAlias, []string{"-N", "route", "show", "table", "254"}},
		{l.profile.ipAlias, []string{"-N", "route", "show", "table", "0206"}},
		{l.profile.ipAlias, []string{"route", "show", "table", "206"}},
		{l.profile.ipAlias, []string{"-N", "route", "show", "table", "206", "exact", "1.1.1.1/32"}},
		{l.profile.ipAlias, []string{"-N", "-details", "route", "show", "table", "206"}},
		{l.profile.ipAlias, []string{"-N", "-j", "route", "show", "table", "205", "exact", "1.1.1.0/24"}},
		{l.profile.ipAlias, []string{"-N", "route", "get", "1.1.1.1"}},
		{l.profile.ipAlias, []string{"-N", "route", "flush", "table", "206"}},
	} {
		if wgInactivitySourceArguments(l, test.name, test.args) {
			t.Fatal("effect/broad/private/fallback ABI admitted", test)
		}
	}
	r := &wgInactivityRunner{l, "wireguard"}
	if out, err := r.RunWG(context.Background(), nil, l.profile.ipAlias, "-N", "rule", "show"); len(out) != 0 || err == nil {
		t.Fatal("source read lacked sealed admission")
	}
}
