package main

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"path/filepath"
	"testing"
)

func TestPrivateStrategyFifthGenerationRetainsLegacyLeasesAndRestarts(t *testing.T) {
	root := t.TempDir()
	cfg := filepath.Join(root, "config")
	custom := filepath.Join(root, "custom")
	devices := filepath.Join(root, "devices")
	stage := filepath.Join(root, "stage")
	provider := filepath.Join(root, "provider")
	nodes := filepath.Join(root, "nodes")
	warp := filepath.Join(root, "warp")
	strategy := filepath.Join(root, "strategy-lab.json")
	for run := 0; run < 2; run++ {
		old, current, prior, out, err := preparePrivateRecoveries(cfg, custom, devices, stage, provider, nodes, warp, strategy)
		if err != nil || prior != restorejournal.Clean || out != restorejournal.Clean {
			t.Fatal("fifth-generation startup", prior, out, err)
		}
		if len(old.coordinators) != 4 {
			t.Fatal("not all older generations retained")
		}
		attempts := []func() error{
			func() error {
				c, _, e := preparePrivateRecovery(cfg, custom, devices, stage, provider)
				if c != nil {
					c.Close()
				}
				return e
			},
			func() error {
				c, _, e := prepareNodePrivateRecovery(cfg, custom, devices, stage, provider, nodes)
				if c != nil {
					c.Close()
				}
				return e
			},
			func() error {
				c, _, e := prepareNativePrivateRecovery(context.Background(), cfg, custom, devices, stage, provider, nodes, warp)
				if c != nil {
					c.Close()
				}
				return e
			},
			func() error {
				c, _, e := prepareFeedPrivateRecovery(context.Background(), cfg, custom, devices, stage, provider, nodes, warp)
				if c != nil {
					c.Close()
				}
				return e
			},
		}
		for i, attempt := range attempts {
			if attempt() == nil {
				t.Fatalf("legacy generation %d lease unprotected", i)
			}
		}
		if err := current.StartRuntime(); err != nil {
			t.Fatal(err)
		}
		if err := old.StartRuntime(); err != nil {
			t.Fatal(err)
		}
		if err := current.Close(); err != nil {
			t.Fatal(err)
		}
		if err := old.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
