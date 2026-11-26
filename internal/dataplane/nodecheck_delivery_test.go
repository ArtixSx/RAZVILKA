package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// The delivered endpoint selection must remain inside the shared transport
// stages, so screening and slotted full checks agree about the successful IP.
func TestDeliveryCheckPinsSuccessfulEndpointWithinReservedSlot(t *testing.T) {
	checker := slottedFakeChecker(t, 2)
	first := netip.MustParseAddr("203.0.113.8")
	second := netip.MustParseAddr("203.0.113.9")
	resolved, dialed, prepared := 0, 0, 0
	checker.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "node.example" {
			resolved++
		}
		return []netip.Addr{first, second}, nil
	}
	checker.dialTransport = func(_ context.Context, endpoint exactNodeEndpoint, addresses []netip.Addr) (bool, error) {
		dialed++
		if len(addresses) != 1 || endpoint.Host != "node.example" {
			t.Fatalf("lost endpoint identity: %+v %v", endpoint, addresses)
		}
		if addresses[0] == first {
			return true, errors.New("first address unavailable")
		}
		return true, nil
	}
	checker.prepare = func(_ context.Context, session exactNodeSession, _ NodeCheckRequest, endpoint exactNodeEndpoint) (exactNodeSession, error) {
		prepared++
		if endpoint.Pinned != second || endpoint.Host != "node.example" || session.Root == "" || session.Port < checker.Port {
			t.Fatalf("runtime did not receive successful endpoint and slot: %+v %+v", endpoint, session)
		}
		session.Spec.Binary = "sing-box"
		return session, nil
	}
	result, err := checker.Check(context.Background(), checkedNodeRequest())
	if err != nil || !result.Available || resolved != 1 || dialed != 2 || prepared != 1 || len(checker.gate) != 2 {
		t.Fatalf("result=%+v err=%v dns=%d dial=%d prepare=%d free=%d", result, err, resolved, dialed, prepared, len(checker.gate))
	}
	measurements := 0
	for _, stage := range result.Stages {
		if stage.ID == "tcp_connect" && stage.Status == "passed" && stage.Duration >= 0 {
			measurements++
		}
	}
	if measurements != 1 {
		t.Fatalf("want one TCP measurement, got %d", measurements)
	}
	// Screening exposes the same timing without preparing any runtime or
	// promoting an open port to a usable service path.
	result, decided, err := checker.ScreenTransport(context.Background(), checkedNodeRequest())
	if err != nil || decided || result.Available || prepared != 1 || resolved != 2 || dialed != 4 {
		t.Fatalf("screening changed runtime or proof: %+v decided=%t err=%v", result, decided, err)
	}
}
