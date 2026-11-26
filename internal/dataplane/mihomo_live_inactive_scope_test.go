package dataplane

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMihomoInactiveCanonicalFDComparisonRequiresOriginalBinding(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	a, err := NewProxyTunnelAdapter("mihomo", nil, root)
	if err != nil {
		t.Fatal(err)
	}
	owner := &MihomoProbeAdapter{}
	owner.self, owner.liveProxy, owner.liveManager, owner.liveOptions = owner, a, New(root), &MihomoLiveOptions{}
	a.mihomoOwner = owner
	for _, spec := range []ProcessSpec{a.engineProcess(), a.sidecarProcess()} {
		if validateProxyInactiveProcessScope(spec) == nil {
			t.Fatal("ordinary path validator accepted FD-only profile argument")
		}
		if err := a.validateMihomoInactiveProcessScope(spec); err != nil {
			t.Fatal("exact original FD comparison", err)
		}
		changed := spec
		changed.Args = append(append([]string{}, spec.Args...), "--extra")
		if a.validateMihomoInactiveProcessScope(changed) == nil {
			t.Fatal("noncanonical FD argv accepted")
		}
		changed = spec
		changed.MatchArg = filepath.Join(root, "foreign.json")
		if a.validateMihomoInactiveProcessScope(changed) == nil {
			t.Fatal("foreign profile path accepted")
		}
		copy := *a
		if copy.validateMihomoInactiveProcessScope(spec) == nil {
			t.Fatal("copied adapter adopted original comparison binding")
		}
	}
	owner.liveProxy = nil
	if a.validateMihomoInactiveProcessScope(a.engineProcess()) == nil {
		t.Fatal("detached original accepted")
	}
}
