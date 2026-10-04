package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

type wgIdentityRunner struct {
	*warpFakeRunner
	identities []byte
	readErr    error
	inventory  []byte
}

func (r *wgIdentityRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if strings.Join(args, " ") == "show all public-key" {
		r.calls = append(r.calls, name+" "+strings.Join(args, " "))
		return r.identities, r.readErr
	}
	if r.inventory != nil && strings.Join(args, " ") == "-j -d link show" {
		return r.inventory, nil
	}
	return r.warpFakeRunner.Run(ctx, name, args...)
}

func TestWGCanaryInUseIdentityRejectsBeforeAnyMutation(t *testing.T) {
	for _, engine := range []string{"wireguard", "warp-wg", "amneziawg"} {
		for _, changed := range []string{"none", "peer", "endpoint", "psk"} {
			t.Run(engine+"/"+changed, func(t *testing.T) {
				a, base, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
				ctx := context.Background()
				if err := a.Snapshot(ctx, plan, root); err != nil {
					t.Fatal(err)
				}
				if err := a.Stage(ctx, plan, root); err != nil {
					t.Fatal(err)
				}
				profile := mustRead(filepath.Join(root, "rz-warp.conf.staged"))
				public, err := wgRuntimePublicKey(profile)
				if err != nil {
					t.Fatal(err)
				}
				text := string(profile)
				switch changed {
				case "peer":
					lines := strings.Split(text, "\n")
					for i, line := range lines {
						if strings.HasPrefix(line, "PublicKey =") {
							lines[i] = "PublicKey = " + public
						}
					}
					text = strings.Join(lines, "\n")
				case "endpoint":
					text = strings.Replace(text, "93.184.216.34:51820", "93.184.216.35:443", 1)
				case "psk":
					text += "PresharedKey = " + public + "\n"
				}
				if err := os.WriteFile(filepath.Join(root, "rz-warp.conf.staged"), []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
				a.EngineID = engine
				base.calls = nil
				a.Runner = &wgIdentityRunner{warpFakeRunner: base, identities: []byte("foreign-live\t" + public + "\n")}
				a.CanaryProbe = func(context.Context, string, string) error { t.Fatal("unsafe probe started"); return nil }
				if err := a.Canary(ctx, plan.RoutePlanFor(engine), root); !errors.Is(err, ErrWGCanaryIdentityInUse) {
					t.Fatal(err)
				}
				assertWGCanaryNoMutations(t, base.calls, root)
			})
		}
	}
}

func assertWGCanaryNoMutations(t *testing.T, calls []string, root string) {
	t.Helper()
	for _, call := range calls {
		if strings.Contains(call, " add ") || strings.Contains(call, " del ") || strings.Contains(call, " delete ") || strings.Contains(call, " setconf ") || strings.Contains(call, " set ") {
			t.Fatal("network changed after preflight rejection", call)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "canary")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate artifacts created before rejection", err)
	}
}

func TestWGCanaryIdentityInventoryFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		err          error
	}{
		{"error", "", errors.New("permission denied")},
		{"malformed", "wg0 invalid", nil},
		{"diagnostic", "unable to access interface", nil},
		{"oversize", strings.Repeat("x", (1<<20)+1), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, base, _, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
			a.Runner = &wgIdentityRunner{warpFakeRunner: base, identities: []byte(tc.output), readErr: tc.err}
			if err := a.ensureWGCanaryIdentityFree(context.Background(), []byte(testOwnWireGuardProfile(""))); !errors.Is(err, ErrWGCanaryIdentityInspection) {
				t.Fatal("unknown inventory allowed candidate")
			}
			assertWGCanaryNoMutations(t, base.calls, root)
		})
	}
}

func TestWGCanaryPublicInventoryAllowsIndependentIdentity(t *testing.T) {
	public, err := wgRuntimePublicKey([]byte(testOwnWireGuardProfile("")))
	if err != nil {
		t.Fatal(err)
	}
	if err := wgCanaryPublicIdentities([]byte("unconfigured\t(none)\nforeign\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), public); err != nil {
		t.Fatal(err)
	}
	if err := wgCanaryPublicIdentities([]byte("duplicate (none)\nduplicate (none)\n"), public); err == nil {
		t.Fatal("duplicate inventory accepted")
	}
}

func TestWGEndpointCanaryRevalidatesWANBeforeMutation(t *testing.T) {
	a, r, _, root := wgEndpointFixture(t)
	r.endpoint.wanDevice = "eth1"
	r.calls = nil
	if err := a.Canary(context.Background(), RoutePlan{}, root); !errors.Is(err, ErrWGEndpointChanged) {
		t.Fatal(err)
	}
	assertWGCanaryNoMutations(t, r.calls, root)
}

func TestWGCanaryIdentityMissingKernelLinkFailsClosed(t *testing.T) {
	a, base, _, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	a.Runner = &wgIdentityRunner{warpFakeRunner: base, inventory: []byte(`[{"ifname":"foreign-wg","linkinfo":{"info_kind":"wireguard"}}]`)}
	if err := a.ensureWGCanaryIdentityFree(context.Background(), []byte(testOwnWireGuardProfile(""))); !errors.Is(err, ErrWGCanaryIdentityInspection) {
		t.Fatal("empty CLI readback hid an existing kernel tunnel")
	}
	assertWGCanaryNoMutations(t, base.calls, root)
}

func TestWGEndpointCanaryRevalidatesExpiredDNSBeforeMutation(t *testing.T) {
	a, r, e, root := wgEndpointFixture(t)
	a.EndpointResolver = func(context.Context, string) ([]netip.Addr, time.Time, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.35")}, time.Time{}, nil
	}
	if !e.ExpiresAt.IsZero() {
		t.Fatal("fixture must exercise noncacheable DNS")
	}
	r.calls = nil
	if err := a.Canary(context.Background(), RoutePlan{}, root); !errors.Is(err, ErrWGEndpointChanged) {
		t.Fatal(err)
	}
	assertWGCanaryNoMutations(t, r.calls, root)
}

func TestWGManagerSamePeerProbePreservesCommittedLKG(t *testing.T) {
	a, r, plan, root := ownWireGuardFixture(t, testOwnWireGuardProfile(""))
	ctx := context.Background()
	store := wireguardprofile.New(filepath.Join(t.TempDir(), "profiles"))
	metadata, err := store.Put(ctx, "named", "named", testOwnWireGuardProfile(""), "")
	if err != nil {
		t.Fatal(err)
	}
	a.Profiles = store
	plan.EngineDrafts = nil
	plan.Routes[0].Resolved = "wireguard:named"
	plan.Routes[0].WireGuardProfileRevision = metadata.Revision
	for _, step := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Activate, a.Commit} {
		if err := step(ctx, plan, root); err != nil {
			t.Fatal(err)
		}
	}
	runtimeBefore := mustRead(a.RuntimeConfigPath)
	stateBefore := mustRead(a.statePath())
	r.calls = nil
	m := New(t.TempDir())
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := m.ProbeCandidate(ctx, plan, a.ID()); !errors.Is(err, ErrWGCanaryIdentityInUse) {
		t.Fatal(err)
	}
	assertWGCanaryNoMutations(t, r.calls, root)
	if !r.active || string(mustRead(a.RuntimeConfigPath)) != string(runtimeBefore) || string(mustRead(a.statePath())) != string(stateBefore) {
		t.Fatal("manager probe changed committed LKG")
	}
}

func TestWGCanaryRejectsAmbiguousPrivateIdentity(t *testing.T) {
	profile := testOwnWireGuardProfile("")
	for _, ambiguous := range []string{
		strings.Replace(profile, "[Interface]", "[Interface]\nPrivateKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=", 1),
		profile + "PrivateKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\n",
		profile + "[Interface]\nPrivateKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\n",
	} {
		if _, err := wgRuntimePublicKey([]byte(ambiguous)); err == nil {
			t.Fatal("ambiguous runtime identity accepted")
		}
	}
}
