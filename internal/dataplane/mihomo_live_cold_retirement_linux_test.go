//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Actual native files/rename/fsync with modeled negative process/kernel input.
// These tests cannot establish hardware absence, authorize a command or mint
// a warm resource. The public offline issuer independently supplies that proof.
func mihomoLiveColdRetirementFixture(t *testing.T) (*Manager, *ProxyTunnelAdapter, Execution, []byte, context.Context, netidentity.Identity) {
	t.Helper()
	e := mihomoColdIntentFixture(t)
	home, _, _, _, _ := mihomoColdHomeFixture(t)
	// Real private native home/receipt; complete process/kernel absence remains
	// explicitly modeled below. No serialized reference becomes an owner.
	e.Resources[0].MihomoLive.NativeHome = home.NativeHome

	m := New(filepath.Join(t.TempDir(), "private"))
	if err := os.MkdirAll(filepath.Join(m.StateRoot, "transactions", e.PlanID), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	for _, name := range []string{"latest-execution.json", filepath.Join("transactions", e.PlanID, "execution.json")} {
		if err := os.WriteFile(filepath.Join(m.StateRoot, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	plan := e.Resources[0].MihomoLive.Plan
	plan.State = "applying"
	planRaw, _ := json.Marshal(plan)
	if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-plan.json"), planRaw, 0600); err != nil {
		t.Fatal(err)
	}
	a := &ProxyTunnelAdapter{EngineID: "mihomo", StateRoot: filepath.Join(m.StateRoot, "mihomo"), SidecarKind: "hev", Interface: "rz-mihomo", Table: 207, Priority: 31200, SOCKSPort: 18083}
	if err := os.MkdirAll(a.runtimeRoot(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.engineProcess().LogPath, []byte("original native log retained"), 0600); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual producer wrapper in metadata archival too. This
	// writes only the historical manifest; native absence is still modeled.
	lease := proxyForwardingLease{Version: 1, Policy: e.Resources[0].MihomoLive.Policy}
	for _, table := range proxyFirewallTables(lease.Policy) {
		lease.Created = append(lease.Created, proxyFirewallTableKey(table))
	}
	if err := a.writeForwardingLease(lease); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	identity := e.Resources[0].MihomoLive.NetworkIdentity
	identity.BootID = "11111111-2222-4333-8444-555555555555"
	return m, a, e, raw, ctx, identity
}

func TestMihomoLiveColdRetirementResumesEveryDurableBoundary(t *testing.T) {
	for _, cut := range []string{"", "manifest", "runtime-renamed", "runtime-directory-ack", "execution.json", "latest-execution.json", "completed"} {
		t.Run(cut, func(t *testing.T) {
			m, a, e, before, ctx, identity := mihomoLiveColdRetirementFixture(t)
			observations := 0
			observe := func(c context.Context, d ExecutionMihomoLiveDefinition) (netidentity.Identity, error) {
				observations++
				if c != ctx || d.Plan.PlanID != e.PlanID {
					t.Fatal("wrong historical intent")
				}
				return identity, c.Err()
			}
			guard := func(c context.Context) error { return c.Err() }
			cutErr := errors.New("lost native publication ACK")
			out, err := m.retireMihomoLiveMetadata(ctx, e.PlanID, e.Digest, a, guard, observe, nil, func(stage string) error {
				if stage == cut {
					return cutErr
				}
				return nil
			})
			if cut != "" {
				if !errors.Is(err, cutErr) || out.PlanID != "" {
					t.Fatal("partial operation reported success", out, err)
				}
				if retired, _, proofErr := m.completedMihomoLiveRetirement(); !retired || cut != "completed" && proofErr == nil {
					t.Fatal("incomplete publication can replay old plan", retired, proofErr)
				}
				identity.BootID = "22222222-3333-4444-8555-666666666666"
				m = New(m.StateRoot)
				out, err = m.retireMihomoLiveMetadata(ctx, e.PlanID, e.Digest, a, guard, observe, nil, nil)
			}
			if err != nil || out.RollbackVerified || out.State != "rolled-back" || out.Resources[0].Phase != "removed" || out.Steps[0].State != "failed" || observations < 2 {
				t.Fatal(out, err, observations)
			}
			if err := m.CheckExecutionRecovery(ctx); err != nil {
				t.Fatal("terminal pair unrecognized", err)
			}
			if retired, id, err := m.completedBootRetirement(); !retired || id != e.PlanID || err != nil {
				t.Fatal("retirement marker not recognized", retired, id, err)
			}
			raw, err := os.ReadFile(filepath.Join(m.StateRoot, "mihomo-live-retirements", e.PlanID, "retirement.json"))
			if err != nil {
				t.Fatal(err)
			}
			var manifest mihomoColdManifest
			if json.Unmarshal(raw, &manifest) != nil || !bytes.Equal(manifest.Before, before) {
				t.Fatal("original history changed")
			}
			if _, err := m.retireMihomoLiveMetadata(ctx, e.PlanID, e.Digest, a, guard, observe, nil, nil); err != nil {
				t.Fatal("idempotent explicit retry", err)
			}
			// A preview cannot make the retired runtime eligible for replay.
			plan := e.Resources[0].MihomoLive.Plan
			plan.State = "planned"
			plan.Note = "new preview"
			preview, _ := json.Marshal(plan)
			if err := os.WriteFile(filepath.Join(m.StateRoot, "latest-plan.json"), preview, 0600); err != nil {
				t.Fatal(err)
			}
			if retired, _, err := m.completedBootRetirement(); !retired || err != nil {
				t.Fatal("preview erased retirement", retired, err)
			}
		})
	}
}

func TestMihomoLiveColdRetirementRefusesChangedNegativeProof(t *testing.T) {
	for _, mode := range []string{"same-boot", "unknown", "identity-changed", "offline-revoked", "foreign-journal", "foreign-runtime"} {
		t.Run(mode, func(t *testing.T) {
			m, a, e, before, ctx, identity := mihomoLiveColdRetirementFixture(t)
			calls := 0
			unknown := errors.New("modeled absence unavailable")
			guard := func(c context.Context) error {
				if mode == "offline-revoked" && calls > 0 {
					return unknown
				}
				return c.Err()
			}
			observe := func(c context.Context, d ExecutionMihomoLiveDefinition) (netidentity.Identity, error) {
				calls++
				if mode == "unknown" {
					return netidentity.Identity{}, unknown
				}
				if mode == "same-boot" {
					return d.NetworkIdentity, nil
				}
				if mode == "identity-changed" && calls > 1 {
					identity.Inode++
				}
				if calls == 2 {
					var name string
					if mode == "foreign-journal" {
						name = filepath.Join(m.StateRoot, "latest-execution.json")
					}
					if mode == "foreign-runtime" {
						name = a.engineProcess().LogPath
					}
					if name != "" {
						data, err := os.ReadFile(name)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(name+".foreign", data, 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(name+".foreign", name); err != nil {
							t.Fatal(err)
						}
					}
				}
				return identity, nil
			}
			if out, err := m.retireMihomoLiveMetadata(ctx, e.PlanID, e.Digest, a, guard, observe, nil, nil); err == nil || out.PlanID != "" {
				t.Fatal("changed proof accepted", out, err)
			}
			raw, err := os.ReadFile(filepath.Join(m.StateRoot, "transactions", e.PlanID, "execution.json"))
			if err != nil || !bytes.Equal(raw, before) {
				t.Fatal("failed proof changed execution", err)
			}
		})
	}
}
