package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestPrivateRecoveryGateBudgetAndParentCancellation(t *testing.T) {
	started := time.Now()
	parent, stop := context.WithCancel(context.Background())
	defer stop()
	ctx, cancel := privateRecoveryGateContext(parent)
	defer cancel()
	finished := time.Now()
	deadline, bounded := ctx.Deadline()
	// This is the CLI contract: permit slow durable opening beyond the old
	// 20-second budget, while retaining a finite two-minute recovery deadline.
	if !bounded || deadline.Before(started.Add(120*time.Second)) || deadline.After(finished.Add(120*time.Second)) {
		t.Fatal("CLI recovery did not receive its bounded flash-opening budget")
	}
	stop()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("CLI gate detached parent cancellation")
	}
}

func TestPrivateRecoveryGateNeverExtendsEarlierDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	parent, stop := context.WithDeadline(context.Background(), deadline)
	defer stop()
	ctx, cancel := privateRecoveryGateContext(parent)
	defer cancel()
	actual, bounded := ctx.Deadline()
	if !bounded || !actual.Equal(deadline) {
		t.Fatal("CLI gate renewed an earlier caller deadline")
	}
}

func TestPrivateRecoveryLaterGenerationsDoNotRenewCanceledGate(t *testing.T) {
	base := t.TempDir()
	config, custom, devices := filepath.Join(base, "config"), filepath.Join(base, "custom"), filepath.Join(base, "devices")
	stage, provider, nodes, warp := filepath.Join(base, "stage"), filepath.Join(base, "provider"), filepath.Join(base, "nodes"), filepath.Join(base, "warp")
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	legacy, outcome, err := preparePrivateRecoveryContext(parent, config, custom, devices, stage, provider)
	if err != nil || legacy == nil || outcome != restorejournal.Clean {
		t.Fatal("initial generation did not open", outcome, err)
	}
	defer legacy.Close()
	cancel() // The budget must survive the boundary between journal generations.
	for _, open := range []func() (*privaterestore.Coordinator, restorejournal.Outcome, error){
		func() (*privaterestore.Coordinator, restorejournal.Outcome, error) {
			return prepareNodePrivateRecoveryContext(parent, config, custom, devices, stage, provider, nodes)
		},
		func() (*privaterestore.Coordinator, restorejournal.Outcome, error) {
			return prepareNativePrivateRecovery(parent, config, custom, devices, stage, provider, nodes, warp)
		},
		func() (*privaterestore.Coordinator, restorejournal.Outcome, error) {
			return prepareFeedPrivateRecovery(parent, config, custom, devices, stage, provider, nodes, warp)
		},
	} {
		c, outcome, err := open()
		if c != nil || outcome != restorejournal.Blocked || !errors.Is(err, restorejournal.ErrAborted) {
			t.Fatal("later generation renewed canceled recovery admission", outcome, err)
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 1 || entries[0].Name() != "private-restore" {
		t.Fatal("canceled chain created later journals or application stores", entries, err)
	}
}

func TestPrivateRecoveryGateExpiredCallerPreservesEvidenceAndNormalRetry(t *testing.T) {
	base := t.TempDir()
	layout := privaterestore.Layout{
		Config: filepath.Join(base, "config"), CustomServices: filepath.Join(base, "custom"),
		Devices: filepath.Join(base, "devices"), StageRoot: filepath.Join(base, "stage"),
		ProviderRoot: filepath.Join(base, "provider"), JournalRoot: filepath.Join(base, "journal"),
	}
	if err := os.Mkdir(layout.JournalRoot, 0700); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(layout.JournalRoot, ".restore.lock")
	marker := []byte("RAZVILKA private restore writer v1\n")
	if err := os.WriteFile(markerPath, marker, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	c, outcome, err := openPrivateRecoveryGate(parent, layout)
	// Open's existing pre-opening cancellation contract is ErrAborted; it
	// must not become a successful empty recovery under a renewed context.
	if c != nil || outcome != restorejournal.Blocked || !errors.Is(err, restorejournal.ErrAborted) {
		t.Fatal("CLI opening replaced an expired caller with a fresh recovery context", outcome, err)
	}
	assertMarker := func() {
		t.Helper()
		after, err := os.Stat(markerPath)
		raw, readErr := os.ReadFile(markerPath)
		if err != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(raw, marker) {
			t.Fatal("CLI recovery replaced or changed retained lease evidence")
		}
	}
	assertMarker()
	c, outcome, err = openPrivateRecoveryGate(context.Background(), layout)
	if err != nil || c == nil || outcome != restorejournal.Clean {
		t.Fatal("unchanged ordinary retry failed", outcome, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	assertMarker()
	for _, path := range []string{layout.Config, layout.CustomServices, layout.Devices, layout.StageRoot, layout.ProviderRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("empty recovery materialized an application store")
		}
	}
}
