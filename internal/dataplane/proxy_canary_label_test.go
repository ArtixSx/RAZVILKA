package dataplane

import (
	"context"
	"errors"
	"github.com/ArtixSx/razvilka/internal/usquediag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyCanaryFailureUsesActualEngineLabel(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		t.Run(engine, func(t *testing.T) {
			a, processes, _ := networkCleanupProxy(t)
			if engine == "xray" {
				var err error
				a, err = NewProxyTunnelAdapter(engine, a.Configs, a.StateRoot)
				if err != nil {
					t.Fatal(err)
				}
				a.Processes = processes
			}
			a.SOCKSProbe = func(context.Context, string) error { return nil }
			a.CanaryProbe = func(context.Context, string, string) error { return errors.New("fixture service refused") }
			root := t.TempDir()
			raw := `{"outbounds":[{"type":"direct","tag":"proxy"}]}`
			if engine == "xray" {
				raw = `{"outbounds":[{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"node.example","port":443,"users":[{"id":"123e4567-e89b-12d3-a456-426614174000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"node.example"}}}]}`
			}
			if err := os.WriteFile(filepath.Join(root, "engine.staged.json"), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			err := a.Canary(context.Background(), RoutePlan{Routes: []Route{{ServiceID: "fixture", ServiceName: "Fixture", Resolved: engine, ProbeURL: "https://example.com/"}}}, root)
			if err == nil || !strings.Contains(err.Error(), engine+": candidate probe") || strings.Contains(err.Error(), "QUIC") || strings.Contains(err.Error(), "HTTP/2") {
				t.Fatal("wrong candidate label", err)
			}
		})
	}
}
func TestUSQUECanaryFailureKeepsTransportLabels(t *testing.T) {
	f := usqueOwnedBridgeNewFixture(t, usqueTransport{})
	root := t.TempDir()
	base, processes, _ := networkCleanupProxy(t)
	adapter, err := NewProxyTunnelAdapter("usque", base.Configs, base.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	adapter.Processes = processes
	adapter.SOCKSProbe = func(context.Context, string) error { return nil }
	adapter.FreshProfile = f.a.FreshProfile
	f.a = adapter
	f.a.EngineBin = "usque"
	raw := `{"private_key":"fixture-key","endpoint_pub_key":"fixture-pub","id":"fixture-device","access_token":"fixture-token","endpoint_v4":"1.1.1.1","endpoint_h2_v4":"162.159.193.10"}`
	if err := os.WriteFile(filepath.Join(root, "engine.staged.json"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	f.a.ownedUSQUEProbe = func(context.Context, usquediag.OwnedProbeOptions) (usquediag.OwnedRuntimeEvidence, error) {
		return usquediag.OwnedRuntimeEvidence{}, errors.New("fixture transport refused")
	}
	err = f.a.Canary(f.ctx, f.plan, root)
	if err == nil || !strings.Contains(err.Error(), "QUIC:") || !strings.Contains(err.Error(), "HTTP/2:") {
		t.Fatal("USQUE transport labels lost", err)
	}
}
