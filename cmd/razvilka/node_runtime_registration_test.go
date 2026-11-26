package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

type startupNodeContextKey struct{}

func TestOrdinaryMainRegistersSamePrivateXrayFactoryWithoutRuntimeEffects(t *testing.T) {
	root := t.TempDir()
	store, err := openNodeStore(filepath.Join(root, "config.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"},
		"vless://123e4567-e89b-12d3-a456-426614174000@startup-node.example:443?security=tls&sni=front.example", now, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	const profile = "wan-0123456789ab"
	check := nodestore.CheckRecord{ProbeID: "startup-same-store", ServiceID: "fixture-site", NetworkProfile: profile,
		RoutePathID: "xray:" + snapshot.Nodes[0].ID, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now, ExpiresAt: now.Add(time.Hour)}
	if _, err := store.RecordCheck(context.Background(), snapshot.Nodes[0].ID, check, now); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "nodes-private", "nodes.private.json")
	before, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	configs := engineconfig.New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	stateRoot := filepath.Join(root, "dataplane")
	freshCalls := 0
	fresh := func(ctx context.Context) (string, error) {
		freshCalls++
		if ctx.Value(startupNodeContextKey{}) != "receipt-context" {
			t.Fatal("startup lost the caller's authority context")
		}
		return profile, ctx.Err()
	}
	manager, err := newDataplaneManagerWithNodes(stateRoot, configs, store, fresh)
	if err != nil {
		t.Fatal(err)
	}
	adapter, ok := manager.Adapters["xray"].(*dataplane.ProxyTunnelAdapter)
	if !ok || adapter.Configs != configs || adapter.NodeRoutes == nil || adapter.FreshProfile == nil || adapter.NodeTUNProbe != nil {
		t.Fatal("ordinary startup omitted the concrete factory or added a probe alias")
	}
	if freshCalls != 0 {
		t.Fatal("constructor observed or changed the network")
	}
	ctx := context.WithValue(context.Background(), startupNodeContextKey{}, "receipt-context")
	if got, err := adapter.FreshProfile(ctx); err != nil || got != profile {
		t.Fatal("fresh profile binding failed", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := adapter.FreshProfile(canceled); err == nil {
		t.Fatal("startup callback lost cancellation")
	}
	requests := []dataplane.NodeRouteRequest{{ServiceID: "fixture-site", NodeID: snapshot.Nodes[0].ID, Domains: []string{"service.example"}, Destinations: []string{"1.1.1.1/32"}}}
	material, err := adapter.NodeRoutes(ctx, requests, profile, now.Add(time.Second))
	if err != nil || material.EngineID != "xray" || len(material.Config) == 0 {
		t.Fatal("registered runtime did not use the exact private catalog", err)
	}
	clear(material.Config)
	if _, err := adapter.NodeRoutes(ctx, requests, "wan-aaaaaaaaaaaa", now.Add(time.Second)); err == nil {
		t.Fatal("registered runtime borrowed another network's proof")
	}
	for _, path := range []string{stateRoot, configs.StageRoot, configs.BackupRoot} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("startup/materialization wrote runtime state", err)
		}
	}
	after, err := os.ReadFile(privatePath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("startup/materialization rewrote private nodes", err)
	}
	for _, invalid := range []struct {
		configs *engineconfig.Manager
		root    string
		fresh   func(context.Context) (string, error)
	}{{nil, stateRoot, fresh}, {configs, "relative", fresh}, {configs, stateRoot, nil}} {
		if _, err := newDataplaneManagerWithNodes(invalid.root, invalid.configs, store, invalid.fresh); err == nil {
			t.Fatal("incomplete factory silently fell back to generic Xray")
		}
	}
}
