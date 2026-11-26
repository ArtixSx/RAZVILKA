package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestXrayNodeRuntimeFactoryRequiresExactXrayServiceProof(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "nodes")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(private)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"},
		"vless://123e4567-e89b-12d3-a456-426614174000@node.example:443?security=tls&sni=front.example", now, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snapshot.Nodes[0].ID
	profile := "wan-0123456789ab"
	options := NodeRuntimeFactoryOptions{Configs: engineconfig.New(filepath.Join(root, "configs"), filepath.Join(root, "backups")),
		Nodes: store, StateRoot: filepath.Join(root, "state"), FreshProfile: func(context.Context) (string, error) { return profile, nil }}
	adapter, err := NewXrayNodeRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.ID() != "xray" || adapter.NodeTUNProbe != nil || adapter.FreshProfile == nil || adapter.NodeRoutes == nil {
		t.Fatal("factory lost its concrete scoped Xray owners")
	}
	request := []dataplane.NodeRouteRequest{{ServiceID: "fixture-site", NodeID: id, Domains: []string{"service.example"}, Destinations: []string{"1.1.1.1/32"}}}
	if _, err := adapter.NodeRoutes(context.Background(), request, profile, now); err == nil {
		t.Fatal("missing service proof was accepted")
	}
	check := nodestore.CheckRecord{ProbeID: "factory-fixture", ServiceID: "fixture-site", NetworkProfile: profile, RoutePathID: "sing-box:" + id,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now, ExpiresAt: now.Add(time.Hour)}
	if _, err := store.RecordCheck(context.Background(), id, check, now); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.NodeRoutes(context.Background(), request, profile, now.Add(time.Second)); err == nil {
		t.Fatal("Sing-box proof was borrowed for Xray")
	}
	check.RoutePathID = "xray:" + id
	check.ProbeID = "factory-xray-fixture"
	if _, err := store.RecordCheck(context.Background(), id, check, now); err != nil {
		t.Fatal(err)
	}
	material, err := adapter.NodeRoutes(context.Background(), request, profile, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.Config)
	if material.EngineID != "xray" || !json.Valid(material.Config) || len(material.EndpointHosts) != 1 {
		t.Fatal("exact Xray material is missing")
	}
	if _, err := adapter.NodeRoutes(context.Background(), request, "wan-fedcba987654", now.Add(time.Second)); err == nil {
		t.Fatal("foreign network proof was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.NodeRoutes(ctx, request, profile, now); err == nil {
		t.Fatal("canceled materialization was accepted")
	}
	for _, mutate := range []func(*NodeRuntimeFactoryOptions){func(o *NodeRuntimeFactoryOptions) { o.Configs = nil }, func(o *NodeRuntimeFactoryOptions) { o.Nodes = nil }, func(o *NodeRuntimeFactoryOptions) { o.FreshProfile = nil }, func(o *NodeRuntimeFactoryOptions) { o.StateRoot = "relative" }} {
		changed := options
		mutate(&changed)
		if _, err := NewXrayNodeRuntime(changed); err == nil {
			t.Fatal("incomplete trusted factory was accepted")
		}
	}
}
