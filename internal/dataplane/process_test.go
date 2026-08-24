package dataplane

import "testing"

func TestProcessSpecRequiresUniqueMatchArgument(t *testing.T) {
	err := validateProcessSpec(ProcessSpec{ID: "sidecar", Binary: "/opt/bin/sing-box", PIDPath: "/tmp/pid", LogPath: "/tmp/log", Dir: "/tmp"})
	if err == nil {
		t.Fatal("process without a unique match argument was accepted")
	}
}
