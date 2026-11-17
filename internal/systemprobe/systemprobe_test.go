package systemprobe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProbeEntwareOpkgDiscoveryResult(t *testing.T) {
	firmware := t.TempDir()
	name := "opkg"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(firmware, name), []byte("lookup only; never execute"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", firmware)
	if _, err := exec.LookPath("opkg"); err != nil {
		t.Fatal("firmware PATH control missing", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, path := range []string{"", "/opt/bin/opkg", "/opt/sbin/opkg"} {
		got := probeContextWithOpkg(ctx, path)
		if got.Opkg != (path != "") {
			t.Fatalf("discovery %q: reported opkg=%t", path, got.Opkg)
		}
	}
}

func TestProbeAlwaysReportsArchitecture(t *testing.T) {
	if Probe().Architecture == "" {
		t.Fatal("empty architecture")
	}
}

func TestKernelFeatureAvailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets")
	if err := os.WriteFile(path, []byte("NFQUEUE\nTPROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !kernelFeatureAvailable("tproxy", path) {
		t.Fatal("TPROXY target was not detected")
	}
	if kernelFeatureAvailable("socket", path) {
		t.Fatal("missing socket match was reported")
	}
}

func TestIsExternalTunnelName(t *testing.T) {
	cases := map[string]bool{
		"nwg3": true, "wg0": true, "tun1": true, "tap0": true, "opkgtun0": true, "awg2": true,
		"eth3": false, "br0": false, "wlan0": false, "widget0": false,
	}
	for dev, want := range cases {
		if got := isExternalTunnelName(dev); got != want {
			t.Fatalf("%s: got %v want %v", dev, got, want)
		}
	}
}
