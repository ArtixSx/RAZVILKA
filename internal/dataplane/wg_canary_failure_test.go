package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/tunnelcheck"
)

// Port fallback must not turn a failed provider request into a claim that no
// handshake occurred. The real probe/handshake ordering and fallback loop run;
// only the kernel commands and HTTPS transport are replaced by local fixtures.
func TestWARPCanaryPreservesProviderFailureAcrossPortFallback(t *testing.T) {
	for _, outcome := range []string{"bootstrap-only", "then-handshake-failure", "then-success", "handshake-only"} {
		t.Run(outcome, func(t *testing.T) {
			a := NewWARPWireGuardAdapter(nil, t.TempDir())
			a.RuntimeConfigPath = filepath.Join(t.TempDir(), "rz-warp.conf")
			if err := os.WriteFile(a.RuntimeConfigPath, []byte(testWARPProfile()), 0600); err != nil {
				t.Fatal(err)
			}
			runner := &warpFakeRunner{active: true}
			a.Runner, a.WG, a.IP = runner, "wg", "ip"
			a.HandshakeTimeout = time.Nanosecond
			a.FallbackPorts = []int{500, 4500}
			plan := RoutePlan{Adapter: "warp-wg", Routes: []Route{{Resolved: "warp-wg", ServiceName: "selected", ProbeURL: "https://service.example/", Sources: []string{"192.168.1.4/32"}}}}
			before := append([]string(nil), plan.Routes[0].Sources...)
			providerErr := errors.New("modeled provider trace failure")
			traceCalls, serviceCalls := 0, 0
			err := a.probeCanaryServices(context.Background(), plan, t.TempDir(), func(_ context.Context, url, source string) error {
				if source != "172.16.0.2" {
					t.Fatalf("candidate source changed: %q", source)
				}
				if url == "https://www.cloudflare.com/cdn-cgi/trace" {
					traceCalls++
					runner.neverHandshake = outcome == "handshake-only" || outcome == "then-handshake-failure" && traceCalls > 1
					if outcome == "then-success" && traceCalls > 1 {
						return nil
					}
					return providerErr
				}
				if url != "https://service.example/" {
					t.Fatalf("unselected service was probed: %q", url)
				}
				serviceCalls++
				return nil
			}, "172.16.0.2")
			if !reflect.DeepEqual(plan.Routes[0].Sources, before) {
				t.Fatal("probe changed the selected LAN sources")
			}
			if outcome == "then-success" {
				if err != nil || traceCalls != 2 || serviceCalls != 1 {
					t.Fatalf("fallback stopped before a proved success: trace=%d service=%d err=%v", traceCalls, serviceCalls, err)
				}
				return
			}
			if err == nil || traceCalls != 3 || serviceCalls != 0 {
				t.Fatalf("unproved provider was accepted or fallback changed: trace=%d service=%d err=%v", traceCalls, serviceCalls, err)
			}
			var transport WARPHandshakeError
			switch outcome {
			case "bootstrap-only":
				if !errors.Is(err, tunnelcheck.ErrBootstrap) || !errors.Is(err, providerErr) || errors.Is(err, tunnelcheck.ErrHandshake) || errors.As(err, &transport) {
					t.Fatalf("confirmed handshake was mislabeled as transport exhaustion: %v", err)
				}
			case "then-handshake-failure":
				if !errors.Is(err, tunnelcheck.ErrBootstrap) || !errors.Is(err, tunnelcheck.ErrHandshake) || !errors.As(err, &transport) || len(transport.Ports) != 0 {
					t.Fatalf("mixed failures lost evidence or invented total handshake exhaustion: %v", err)
				}
			case "handshake-only":
				if errors.Is(err, tunnelcheck.ErrBootstrap) || !errors.Is(err, tunnelcheck.ErrHandshake) || !errors.As(err, &transport) || !reflect.DeepEqual(transport.Ports, []int{2408, 500, 4500}) {
					t.Fatalf("actual handshake exhaustion lost its attempted ports: %v", err)
				}
			}
		})
	}
}
