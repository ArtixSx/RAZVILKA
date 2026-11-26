package app

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// Proxy engines are proven on the committed routes in the isolated canary,
// with the installed version first; live routes are never touched.
func TestProxyUpdateCheckUsesIsolatedCanaryOnCommittedRoutes(t *testing.T) {
	a, id, adapter := nodeApplyFixture(t)
	if w := nodeRouteRequest(a, id, "apply", nodeApplyBody(reviewedNode(t, a, id)), "owner-a", context.Background()); w.Code != 200 {
		t.Fatalf("initial apply: %d %s", w.Code, w.Body.String())
	}
	adapter.calls = nil
	check, adapters, err := a.proxyUpdateCheck(context.Background(), "sing-box")
	if err != nil || !slices.Equal(adapters, []string{"sing-box"}) {
		t.Fatalf("precheck: %v %v", adapters, err)
	}
	if !slices.Equal(adapter.calls, []string{"snapshot", "stage", "validate", "canary"}) {
		t.Fatalf("precheck did not use the isolated canary only: %v", adapter.calls)
	}
	adapter.calls = nil
	if err = check(context.Background()); err != nil || slices.Contains(adapter.calls, "activate") || slices.Contains(adapter.calls, "commit") {
		t.Fatalf("check touched live routes: %v %v", adapter.calls, err)
	}
	adapter.after = func(phase string) error {
		if phase == "canary" {
			return errors.New("new binary cannot start")
		}
		return nil
	}
	if err = check(context.Background()); err == nil {
		t.Fatal("failed canary accepted")
	}
	if _, _, err = a.proxyUpdateCheck(context.Background(), "sing-box"); !errors.Is(err, errProxyPrecheck) {
		t.Fatalf("precheck failure not reported: %v", err)
	}
	// Xray and WireGuard are not used by the committed routes: nothing to prove.
	for _, id := range []string{"xray", "wireguard", "warp-wg"} {
		adapter.calls = nil
		check, adapters, err = a.proxyUpdateCheck(context.Background(), id)
		if err != nil || len(adapters) != 0 || check(context.Background()) != nil || len(adapter.calls) != 0 {
			t.Fatalf("unused engine %s: %v %v %v", id, adapters, err, adapter.calls)
		}
	}
}
