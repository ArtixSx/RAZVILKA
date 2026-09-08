package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func warpCleanupFixture(t *testing.T, awg bool) (*WARPWireGuardAdapter, *warpFakeRunner, PolicyState, string) {
	t.Helper()
	root := t.TempDir()
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backups"))
	a := NewWARPWireGuardAdapter(configs, filepath.Join(root, "state"))
	if awg {
		a = NewAmneziaWGAdapter(configs, filepath.Join(root, "state"))
	}
	r := &warpFakeRunner{active: true}
	a.IP, a.WG, a.Runner, a.NativeOnly = "ip", "wg", r, true
	profile, err := sanitizeWGQuickProfile(testWARPProfile())
	if err != nil {
		t.Fatal(err)
	}
	state := PolicyState{Interface: a.interfaceName(), Table: a.table(), PriorityBase: a.priorityBase(), Prefixes: []string{"198.51.100.20/32"}, RuntimeConfigSHA256: warpRuntimeDigest([]byte(profile))}
	return a, r, state, profile
}
func writeWarpCleanupFixture(t *testing.T, a *WARPWireGuardAdapter, state PolicyState, profile string) {
	t.Helper()
	if err := os.MkdirAll(a.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(state)
	if err := os.WriteFile(a.statePath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.RuntimeConfigPath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
}
func TestWARPDeactivateWithoutOwnershipNeverInspectsForeignInterface(t *testing.T) {
	for _, awg := range []bool{false, true} {
		a, r, _, _ := warpCleanupFixture(t, awg)
		if err := a.Deactivate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !r.active || len(r.calls) != 0 {
			t.Fatal("foreign interface was inspected or stopped", r.calls)
		}
		if _, err := os.Stat(a.StateRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("no-op created private state")
		}
	}
}
func TestWARPDeactivatePartialOrInvalidOwnershipPreservesEverything(t *testing.T) {
	for _, mode := range []string{"runtime-only", "policy-only", "corrupt-policy", "corrupt-runtime", "hashless-legacy", "hash-mismatch", "wrong-interface", "wrong-table", "wrong-priority", "bad-destination", "bad-source", "hooks"} {
		t.Run(mode, func(t *testing.T) {
			a, r, state, profile := warpCleanupFixture(t, false)
			switch mode {
			case "hashless-legacy":
				state.RuntimeConfigSHA256 = ""
			case "hash-mismatch":
				state.RuntimeConfigSHA256 = warpRuntimeDigest([]byte("other"))
			case "wrong-interface":
				state.Interface = "foreign"
			case "wrong-table":
				state.Table = 254
			case "wrong-priority":
				state.PriorityBase = 1
			case "bad-destination":
				state.Rules = []PolicyRule{{Destination: "0.0.0.0/0"}}
			case "bad-source":
				state.Rules = []PolicyRule{{Destination: state.Prefixes[0], Source: "not-a-prefix"}}
			case "hooks":
				profile += "\n[Interface]\nPostDown = unsafe\n"
				state.RuntimeConfigSHA256 = warpRuntimeDigest([]byte(profile))
			}
			writeWarpCleanupFixture(t, a, state, profile)
			switch mode {
			case "runtime-only":
				os.Remove(a.statePath())
			case "policy-only":
				os.Remove(a.RuntimeConfigPath)
			case "corrupt-policy":
				os.WriteFile(a.statePath(), []byte("{broken"), 0o600)
			case "corrupt-runtime":
				os.WriteFile(a.RuntimeConfigPath, nil, 0o600)
			}
			beforePolicy, _, _ := optionalFile(a.statePath())
			beforeRuntime, _, _ := optionalFile(a.RuntimeConfigPath)
			if err := a.Deactivate(context.Background()); !errors.Is(err, errWARPCleanupOwnership) {
				t.Fatal("invalid ownership accepted", err)
			}
			if len(r.calls) != 0 || !r.active {
				t.Fatal("ambiguous state touched foreign interface", r.calls)
			}
			afterPolicy, _, _ := optionalFile(a.statePath())
			afterRuntime, _, _ := optionalFile(a.RuntimeConfigPath)
			if string(beforePolicy) != string(afterPolicy) || string(beforeRuntime) != string(afterRuntime) {
				t.Fatal("refusal changed ownership evidence")
			}
		})
	}
}
func TestWARPFailedInterfaceCreationDoesNotAuthorizeDeactivate(t *testing.T) {
	a, r, _, profile := warpCleanupFixture(t, false)
	r.failStart = true
	root := t.TempDir()
	snapshot, _ := json.Marshal(warpWGSnapshot{})
	os.WriteFile(filepath.Join(root, "snapshot.json"), snapshot, 0o600)
	os.WriteFile(filepath.Join(root, "rz-warp.conf.staged"), []byte(profile), 0o600)
	if err := a.Activate(context.Background(), Plan{}, root); err == nil {
		t.Fatal("synthetic foreign collision succeeded")
	}
	if !r.active {
		t.Fatal("failed creation already deleted foreign interface")
	}
	r.calls = nil
	if err := a.Deactivate(context.Background()); !errors.Is(err, errWARPCleanupOwnership) {
		t.Fatal("partial creation was accepted as owned", err)
	}
	if len(r.calls) != 0 || !r.active {
		t.Fatal("partial runtime intent deleted foreign link", r.calls)
	}
}
func TestWARPDeactivateKeepsEvidenceWhenOwnedStopFails(t *testing.T) {
	a, r, state, profile := warpCleanupFixture(t, true)
	writeWarpCleanupFixture(t, a, state, profile)
	r.failDelete = true
	if err := a.Deactivate(context.Background()); err == nil {
		t.Fatal("failed stop accepted")
	}
	if !r.active {
		t.Fatal("fake stop unexpectedly succeeded")
	}
	for _, path := range []string{a.statePath(), a.RuntimeConfigPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("failed cleanup lost ownership state")
		}
	}
	r.failDelete = false
	r.calls = nil
	if err := a.Deactivate(context.Background()); err != nil {
		t.Fatal("owned cleanup could not retry", err)
	}
	if r.active {
		t.Fatal("owned retry did not stop interface")
	}
}

func TestWARPDeactivateRejectsSymlinkOwnershipBeforeAnyRunnerCall(t *testing.T) {
	for _, kind := range []string{"policy", "runtime"} {
		t.Run(kind, func(t *testing.T) {
			a, r, state, profile := warpCleanupFixture(t, false)
			writeWarpCleanupFixture(t, a, state, profile)
			path := a.statePath()
			if kind == "runtime" {
				path = a.RuntimeConfigPath
			}
			saved := path + ".retained"
			if err := os.Rename(path, saved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(saved, path); err != nil {
				t.Skip("symlink creation unavailable")
			}
			if err := a.Deactivate(context.Background()); !errors.Is(err, errWARPCleanupOwnership) {
				t.Fatal("symlink ownership accepted", err)
			}
			if len(r.calls) != 0 || !r.active {
				t.Fatal("symlink ownership touched interface", r.calls)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("refusal removed link")
			}
			if _, err := os.Stat(saved); err != nil {
				t.Fatal("refusal removed linked original")
			}
		})
	}
}
