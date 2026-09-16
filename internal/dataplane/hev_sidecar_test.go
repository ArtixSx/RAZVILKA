package dataplane

import (
	"context"
	"encoding/json"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hevFixture(t *testing.T) *ProxyTunnelAdapter {
	t.Helper()
	a, e := NewProxyTunnelAdapterWithHev("sing-box", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir(), "/opt/libexec/razvilka/hev-socks5-tunnel")
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func TestHevAdapterBuildAndValidateDoesNotRunProcess(t *testing.T) {
	a := hevFixture(t)
	b, e := a.buildSidecarConfig(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(t.TempDir(), "hev.json")
	_ = os.WriteFile(p, b, 0600)
	if e = a.validateSidecarConfig(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	s := a.sidecarProcess()
	if len(s.Args) != 1 || s.Args[0] != a.sidecarConfigPath() || !strings.Contains(s.Binary, "hev-socks5-tunnel") {
		t.Fatal(s)
	}
	if strings.Contains(string(b), "auto_route") {
		t.Fatal("route authority")
	}
}
func TestHevRejectsChangedRuntimeAndSnapshot(t *testing.T) {
	a := hevFixture(t)
	_ = os.MkdirAll(a.runtimeRoot(), 0700)
	_ = os.WriteFile(a.sidecarConfigPath(), []byte(`{"inbounds":[]}`), 0600)
	if a.checkSidecarIdentity() == nil {
		t.Fatal("adopted singbox")
	}
	b, _ := a.hevConfig()
	_ = os.WriteFile(a.sidecarConfigPath(), b, 0600)
	if e := a.checkSidecarIdentity(); e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	v["mapdns"] = map[string]any{"port": 53}
	b, _ = json.Marshal(v)
	_ = os.WriteFile(a.sidecarConfigPath(), b, 0600)
	if a.checkSidecarIdentity() == nil {
		t.Fatal("foreign mapdns")
	}
	if a.checkSnapshotSidecar(proxySnapshot{}) == nil {
		t.Fatal("old snapshot adopted")
	}
	if a.checkSnapshotSidecar(proxySnapshot{SidecarKind: "hev"}) != nil {
		t.Fatal("same backend")
	}
}
func TestHevRefusesStagedEditsAndCancellation(t *testing.T) {
	a := hevFixture(t)
	p := filepath.Join(t.TempDir(), "sidecar.json")
	_ = os.WriteFile(p, []byte(`{}`), 0600)
	if a.validateSidecarConfig(context.Background(), p) == nil {
		t.Fatal("edit accepted")
	}
	b, _ := a.hevConfig()
	_ = os.WriteFile(p, b, 0600)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if a.validateSidecarConfig(ctx, p) == nil {
		t.Fatal("cancellation")
	}
	if _, e := NewProxyTunnelAdapterWithHev("xray", a.Configs, t.TempDir(), "hev"); e == nil {
		t.Fatal("relative executable")
	}
}
func TestLegacySidecarRemainsDefault(t *testing.T) {
	a, e := NewProxyTunnelAdapter("xray", engineconfig.New(t.TempDir(), t.TempDir()), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if a.effectiveSidecar() != "sing-box" || len(a.sidecarProcess().Args) != 3 {
		t.Fatal("default changed")
	}
	if a.checkSnapshotSidecar(proxySnapshot{}) != nil {
		t.Fatal("legacy snapshot")
	}
}
