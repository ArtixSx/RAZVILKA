package systemprobe

import "testing"

func TestProbeAlwaysReportsArchitecture(t *testing.T) {
	if Probe().Architecture == "" {
		t.Fatal("empty architecture")
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
