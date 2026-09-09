package dataplane

import (
	"context"
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
)

func awgNativeFixture() string {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	return "[Interface]\nPrivateKey = " + key + "\nAddress = 10.8.0.2/32\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nHeaderProtectionKey = " + key + "\nRandomTrailers = true\nDisableCookies = false\nH1 = 10-20\nH2 = 30-40\nH3 = 50\nH4 = 60\nI1 = <r 10>\n[Peer]\nPublicKey = " + key + "\nEndpoint = 8.8.4.4:51820\nAllowedIPs = 0.0.0.0/0\n"
}
func TestAWG31NativeTypeAndFullParameters(t *testing.T) {
	a := NewAmneziaWGAdapter(nil, t.TempDir())
	a.RuntimeConfigPath = filepath.Join(t.TempDir(), "profile.conf")
	if err := os.WriteFile(a.RuntimeConfigPath, []byte(awgNativeFixture()), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &warpFakeRunner{}
	a.Runner = runner
	a.IP = "ip"
	a.WG = "wg"
	a.WGQuick = "wg-quick"
	a.AWGCapabilities = func(context.Context) awgprofile.Capabilities {
		return awgprofile.Capabilities{Backend: "kernel", ToolPath: "wg", ToolVersion: "awg v3.1.20260812", ModuleLoaded: true, LoadedModuleVersion: "3.1.20260906"}
	}
	// Capture transient setconf before cleanup, without putting its keys in logs.
	capture := &awgSetconfCapture{inner: runner}
	a.Runner = capture
	if err := a.startInterface(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "type amneziawg") || strings.Contains(strings.Join(runner.calls, "\n"), "wg-quick up") {
		t.Fatal("wrong runtime implementation")
	}
	for _, want := range []string{"RandomTrailers = on", "DisableCookies = off", "HeaderProtectionKey =", "H1 = 10-20", "I1 = <r 10>"} {
		if !strings.Contains(capture.config, want) {
			t.Fatal("native parameter missing", want)
		}
	}
	if _, err := os.Stat(a.RuntimeConfigPath + ".setconf"); !os.IsNotExist(err) {
		t.Fatal("temporary key file remains")
	}
	ports, err := a.warpEndpointPorts()
	if err != nil || len(ports) != 1 || ports[0] != 51820 {
		t.Fatal("AWG received Cloudflare fallback ports", ports, err)
	}
}

type awgSetconfCapture struct {
	inner  *warpFakeRunner
	config string
}

func (c *awgSetconfCapture) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(args) >= 3 && args[0] == "setconf" {
		data, err := os.ReadFile(args[2])
		if err != nil {
			return nil, err
		}
		c.config = string(data)
	}
	return c.inner.Run(ctx, name, args...)
}
func TestAWG31MissingOrOldModuleStopsBeforeCommand(t *testing.T) {
	for _, ver := range []string{"", "2.0.0", "3.0.20260101"} {
		t.Run(ver, func(t *testing.T) {
			a := NewAmneziaWGAdapter(nil, t.TempDir())
			a.RuntimeConfigPath = filepath.Join(t.TempDir(), "profile.conf")
			_ = os.WriteFile(a.RuntimeConfigPath, []byte(awgNativeFixture()), 0600)
			r := &warpFakeRunner{}
			a.Runner = r
			a.IP = "ip"
			a.WG = "wg"
			a.WGQuick = "wg-quick"
			a.AWGCapabilities = func(context.Context) awgprofile.Capabilities {
				return awgprofile.Capabilities{Backend: "kernel", ToolPath: "wg", ToolVersion: "3.1.0", ModuleLoaded: ver != "", LoadedModuleVersion: ver}
			}
			if err := a.startInterface(context.Background()); err == nil || len(r.calls) > 0 {
				t.Fatal("started before compatibility", err, r.calls)
			}
		})
	}
}
func TestAWGEndpointPinnedAndRebindingRejected(t *testing.T) {
	a := NewAmneziaWGAdapter(nil, t.TempDir())
	p := strings.Replace(awgNativeFixture(), "8.8.4.4:51820", "vpn.example.com:51820", 1)
	a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.4.4")}, nil
	}
	out, err := a.pinAWGEndpoint(context.Background(), p)
	if err != nil || !strings.Contains(out, "8.8.4.4:51820") {
		t.Fatal("pin", err)
	}
	a.Resolver = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := a.pinAWGEndpoint(context.Background(), p); err == nil {
		t.Fatal("mixed public/private DNS accepted")
	}
}
