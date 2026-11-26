package dataplane

import (
	"context"
	"errors"
	"testing"
)

func TestComponentLiveAcceptanceRequiresLiveServiceProof(t *testing.T) {
	f := newForwardingRepairFixture(t)
	// This committed source-scoped fixture has no exact node service proof.
	// Presence, a PID and candidate health must not settle a component update.
	if err := f.m.CheckComponentLive(context.Background(), f.plan, "sing-box"); err == nil {
		t.Fatal("presence-only scoped runtime accepted")
	}
	f.unchangedPrivateRuntime(t)
	requireOnlyFirewallReads(t, f.firewall)
	if err := f.m.CheckComponentLive(context.Background(), f.plan, "xray"); err == nil {
		t.Fatal("unused component accepted")
	}
	guardErr := errors.New("Stop or revision changed")
	if err := f.m.CheckComponentLive(WithReviewGuard(context.Background(), func(context.Context) error { return guardErr }), f.plan, "sing-box"); !errors.Is(err, guardErr) {
		t.Fatal("current authority ignored", err)
	}
}
