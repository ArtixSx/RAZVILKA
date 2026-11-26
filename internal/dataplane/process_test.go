package dataplane

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedProcessIDsAndOwnedPaths(t *testing.T) {
	root := t.TempDir()
	base := ProcessSpec{Binary: "sing-box", Dir: root, PIDPath: filepath.Join(root, "engine.pid"), LogPath: filepath.Join(root, "engine.log"), MatchArg: filepath.Join(root, "engine.json")}
	for _, id := range []string{"sing-box-engine", "sing-box-tun", "xray-engine", "xray-canary", "usque-engine", "probe0"} {
		spec := base
		spec.ID = id
		if err := validateProcessSpec(spec); err != nil {
			t.Fatalf("valid ID %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"../engine", "engine\\file", "engine\x00bad"} {
		spec := base
		spec.ID = id
		if validateProcessSpec(spec) == nil {
			t.Fatalf("unsafe ID %q accepted", id)
		}
	}
	base.ID = "engine"
	for _, modify := range []func(*ProcessSpec){
		func(s *ProcessSpec) { s.PIDPath = filepath.Join(root, "..", "outside.pid") },
		func(s *ProcessSpec) { s.LogPath = filepath.Join(root, "..", "outside.log") },
		func(s *ProcessSpec) { s.MatchArg = filepath.Join(root, "..", "outside.json") },
		func(s *ProcessSpec) { s.PIDPath = root },
	} {
		spec := base
		modify(&spec)
		if validateProcessSpec(spec) == nil {
			t.Fatal("outside process file accepted")
		}
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "outside"), base.LogPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if validateProcessSpec(base) == nil {
		t.Fatal("symlink log accepted")
	}
}

func TestProcessSpecRequiresUniqueMatchArgument(t *testing.T) {
	err := validateProcessSpec(ProcessSpec{ID: "sidecar", Binary: "/opt/bin/sing-box", PIDPath: "/tmp/pid", LogPath: "/tmp/log", Dir: "/tmp"})
	if err == nil {
		t.Fatal("process without a unique match argument was accepted")
	}
}
