package dataplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
)

func TestAWGRuntimeRejectionPrecedesNativeAndQuickMutation(t *testing.T) {
	for _, profile := range []string{awgNativeFixture(), testOwnWireGuardProfile("")} {
		for _, kind := range []string{"kernel", "source", "CLI replacement"} {
			a := NewAmneziaWGAdapter(nil, t.TempDir())
			a.RuntimeConfigPath = filepath.Join(t.TempDir(), "profile.conf")
			if err := os.WriteFile(a.RuntimeConfigPath, []byte(profile), 0600); err != nil {
				t.Fatal(err)
			}
			caps := compatibleAWGTestCapabilities(t, a)
			switch kind {
			case "kernel":
				caps.Kernel += "-wrong"
			case "source":
				caps.LoadedSourceVersion = ""
			case "CLI replacement":
				if err := os.WriteFile(a.WG, []byte("changed executable"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			a.AWGCapabilities = func(context.Context) awgprofile.Capabilities { return caps }
			r := &warpFakeRunner{}
			a.Runner, a.IP, a.WGQuick = r, "ip", "wg-quick"
			if err := a.startInterface(context.Background()); err == nil || len(r.calls) != 0 {
				t.Fatal("compatibility rejection mutated kernel or invoked quick", kind, err, r.calls)
			}
			if _, err := os.Stat(a.RuntimeConfigPath + ".setconf"); !os.IsNotExist(err) {
				t.Fatal("secret-bearing setconf written before rejection")
			}
		}
	}
}

func TestAWGActivationRevalidatesBeforeStoppingPreviousRuntime(t *testing.T) {
	a := NewAmneziaWGAdapter(nil, t.TempDir())
	root := t.TempDir()
	caps := compatibleAWGTestCapabilities(t, a)
	caps.Kernel += "-changed-since-validate"
	a.AWGCapabilities = func(context.Context) awgprofile.Capabilities { return caps }
	r := &warpFakeRunner{active: true}
	a.IP, a.Runner = "ip", r
	previous := []byte(testOwnWireGuardProfile(""))
	if err := os.MkdirAll(filepath.Dir(a.RuntimeConfigPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.RuntimeConfigPath, previous, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := warpWGSnapshot{InterfaceWasActive: true, RuntimeExisted: true, RuntimeConfig: previous}
	snapshotData, _ := json.Marshal(snapshot)
	state := PolicyState{Interface: a.Interface, Table: a.Table, PriorityBase: a.PriorityBase, Prefixes: []string{"198.51.100.10/32"}}
	initializePolicyLayout(&state)
	stateData, _ := json.Marshal(state)
	for name, data := range map[string][]byte{"snapshot.json": snapshotData, "policy.staged.json": stateData, "rz-warp.conf.staged": []byte(awgNativeFixture())} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Activate(context.Background(), Plan{}, root); err == nil {
		t.Fatal("changed compatibility accepted")
	}
	after, err := os.ReadFile(a.RuntimeConfigPath)
	if err != nil || string(after) != string(previous) || !r.active || len(r.calls) != 0 {
		t.Fatal("preflight stopped or changed the previous runtime", err, r.calls)
	}
}
