//go:build linux && amd64 && razvilka_native_fixture

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
)

func sameBootCanonicalNativePaths() offlineNFQWS2StopPaths {
	p := offlineStopTestPaths(installpath.Config)
	p.dataplane = filepath.Join(installpath.State, "dataplane")
	p.nodes = filepath.Join(installpath.State, "nodes")
	p.warp = filepath.Join(installpath.State, "warp")
	p.strategyLab = filepath.Join(installpath.State, "strategy-lab.json")
	cm := components.New()
	p.componentState, p.componentBin, p.componentInit, p.componentRepo, p.componentInfo = cm.StateDir, cm.BinDir, cm.InitDir, cm.RepoDir, "/opt/lib/opkg/info"
	return p
}

// The actual updater's independent guard in a new original controller image.
// It neither opens runtime workers nor prepares/changes an update transaction.
func TestMihomoSameBootUpdaterGuardChild(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_SAME_BOOT_GUARD_CHILD") != "1" {
		t.Skip("owned native guard subprocess only")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err := independentSelfUpdateFences(ctx, filepath.Join(installpath.Config, "config.json"), filepath.Join(installpath.State, "dataplane"))
	switch {
	case err == nil:
		t.Log("guard=open")
	case errors.Is(err, dataplane.ErrExecutionJournal):
		t.Log("guard=fenced")
	default:
		t.Fatal("actual guard observation unavailable")
	}
}

type sameBootNativeOutput struct {
	bytes.Buffer
	overflow bool
}

func (b *sameBootNativeOutput) Write(p []byte) (int, error) {
	if len(p) > 32768-b.Len() {
		b.overflow = true
		return 0, errors.New("bounded native helper output exceeded")
	}
	return b.Buffer.Write(p)
}

func TestMihomoSameBootCLINativeOriginalParent(t *testing.T) {
	if os.Getenv("RAZVILKA_MIHOMO_SAME_BOOT_CONSUMER") != "1" {
		t.Skip("actual original parent crash namespace fixture only")
	}
	for _, kind := range []string{"net", "mnt"} {
		self, e1 := os.Readlink("/proc/self/ns/" + kind)
		host, e2 := os.Readlink("/proc/1/ns/" + kind)
		if os.Geteuid() != 0 || e1 != nil || e2 != nil || self == host {
			t.Fatal("genuine private namespace required", kind)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	paths := sameBootCanonicalNativePaths()
	readyPath := filepath.Join(paths.dataplane, ".same-boot-native-ready.json")
	f, err := os.Open(readyPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, 4097))
	closeErr := f.Close()
	var ready struct{ PlanID, Digest string }
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if readErr != nil || closeErr != nil || len(raw) > 4096 || d.Decode(&ready) != nil || d.Decode(new(any)) != io.EOF {
		t.Fatal("closed real producer witness unavailable")
	}
	before, err := os.ReadFile(filepath.Join(paths.dataplane, "latest-execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original dataplane.Execution
	if json.Unmarshal(before, &original) != nil || original.PlanID != ready.PlanID || original.Digest != ready.Digest || original.State != "applying" || len(original.Resources) != 1 || original.Resources[0].MihomoLive == nil || original.Resources[0].Phase != "policy-pending" {
		t.Fatal("fixture did not retain genuine applying policy-pending source")
	}
	// Fixture initialization only: production CLI below uses existing-only
	// journals and never creates a private generation or repairs a Store.
	seed, _, err := openOfflineRuntimeLeases(ctx, paths, func(c context.Context, l privaterestore.Layout) (*privaterestore.Coordinator, error) {
		v, _, e := privaterestore.Open(c, l)
		return v, e
	})
	if err != nil {
		t.Fatal("initialize actual fixture private lifetimes", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	configuration, err := openMihomoLiveColdConfiguration(ctx, paths.config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := configuration.Close(); err != nil {
			t.Error(err)
		}
	}()
	preserveMihomoLiveRetirementFlags(t)
	*retireMihomoLiveParentPlan, *retireMihomoLiveParentDigest = ready.PlanID, ready.Digest
	var stages []string
	expected := []string{"intent", "sidecar", "policy", "forwarding", "archive", "terminal-transaction", "terminal-global"}
	cut := os.Getenv("RAZVILKA_MIHOMO_SAME_BOOT_ACK_CUT")
	switch cut {
	case "", "retirement.json", "runtime-history", "completed.json", "terminal-transaction", "terminal-global":
	default:
		t.Fatal("closed native ACK-cut case required")
	}
	visits := 0
	var result dataplane.Execution
	run := func(original context.Context) error {
		return dataplane.WithMihomoSameBootNativeWitness(original, func(c context.Context, stage string) error {
			visits++
			if visits > 64 {
				return errors.New("bounded original retry phases exceeded")
			}
			already := false
			for _, seen := range stages {
				already = already || seen == stage
			}
			if already && cut == "" || !already && (len(stages) >= len(expected) || stage != expected[len(stages)]) {
				return errors.New("native phase ordering changed")
			}
			if !already {
				stages = append(stages, stage)
			}
			childCtx, stop := context.WithTimeout(c, 15*time.Second)
			defer stop()
			command := exec.CommandContext(childCtx, "/opt/bin/razvilka", "-test.run=^TestMihomoSameBootUpdaterGuardChild$", "-test.v", "-test.count=1", "-test.timeout=12s")
			command.Env = append(os.Environ(), "RAZVILKA_MIHOMO_SAME_BOOT_GUARD_CHILD=1")
			var output sameBootNativeOutput
			command.Stdout = &output
			command.Stderr = &output
			command.WaitDelay = 200 * time.Millisecond
			if err := command.Run(); err != nil || output.overflow {
				return errors.Join(errors.New("actual updater guard child failed"), err)
			}
			want := "guard=fenced"
			if stage == "terminal-global" {
				want = "guard=open"
			}
			if cut != "" {
				latest, e1 := os.ReadFile(filepath.Join(paths.dataplane, "latest-execution.json"))
				transaction, e2 := os.ReadFile(filepath.Join(paths.dataplane, "transactions", ready.PlanID, "execution.json"))
				var current dataplane.Execution
				if e1 != nil || e2 != nil || json.Unmarshal(latest, &current) != nil {
					return errors.Join(e1, e2, errors.New("original retry pair unavailable"))
				}
				want = "guard=fenced"
				if current.State == "rolled-back" && bytes.Equal(latest, transaction) {
					want = "guard=open"
				}
			}
			if !strings.Contains(output.String(), want) {
				return errors.New("actual updater guard did not retain original fence")
			}
			t.Log("actual updater guard phase", stage, want)
			return nil
		}, func(held context.Context) error {
			var e error
			result, e = runMihomoLiveParentRetirementCLI(held, paths, filepath.Join(installpath.State, "self-update-stop"))
			return e
		})
	}
	if cut == "" {
		err = run(ctx)
	} else {
		err = dataplane.WithMihomoSameBootNativeACKCut(ctx, cut, run)
	}
	if err != nil {
		t.Fatalf("actual sameboot CLI %v prepare_stage=%s", err, dataplane.MihomoSameBootRetirementStage(err))
	}
	if result.State != "rolled-back" || result.RollbackVerified || len(stages) != len(expected) {
		t.Fatal("unverified or incomplete terminal acknowledgment")
	}
	latest, err := os.ReadFile(filepath.Join(paths.dataplane, "latest-execution.json"))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := os.ReadFile(filepath.Join(paths.dataplane, "transactions", ready.PlanID, "execution.json"))
	if err != nil || !bytes.Equal(latest, transaction) {
		t.Fatal("actual terminal pair disagrees", err)
	}
	if err := configuration.Current(ctx); err != nil {
		t.Fatal("actual CLI changed original config", err)
	}
	if _, err := os.Lstat(filepath.Join(paths.dataplane, "mihomo")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original runtime not archived without replacement", err)
	}
	if err := dataplane.New(paths.dataplane).CheckExecutionRecovery(ctx); err != nil {
		t.Fatal("fresh controller sees unfinished native recovery", err)
	}
	t.Log("genuine original producer/parent death, actual sameboot CLI five leases and native cleanup, original runtime archive, updater phase fences and terminal pair passed; Ubuntu classification modeled, not router acceptance")
}
