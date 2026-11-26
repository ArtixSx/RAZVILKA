package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func nodeHistoryStateFixture(t *testing.T, xray bool) (string, string, string, []byte) {
	t.Helper()
	configRoot, stateRoot := t.TempDir(), t.TempDir()
	nodeRoot := filepath.Join(configRoot, "nodes-private")
	if err := os.Mkdir(nodeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := nodestore.Open(nodeRoot)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now()
	snapshot, err := s.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, "vless://123e4567-e89b-12d3-a456-426614174000@private-state.example:443?security=tls", at, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if xray {
		id := snapshot.Nodes[0].ID
		_, err = s.RecordCheck(context.Background(), id, nodestore.CheckRecord{ProbeID: "cli-xray-history", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "xray:" + id, TestLevel: "service", Stage: "service", Verdict: "PASS", State: "available", CheckedAt: at, ExpiresAt: at.Add(time.Hour)}, at)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(nodeRoot, "nodes.private.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return configRoot, stateRoot, path, raw
}

func TestNodeHistoryStateCLIUsesTypedReaderAndIsReadOnly(t *testing.T) {
	configRoot, stateRoot, path, before := nodeHistoryStateFixture(t, true)
	output, err := selfUpdateMainSubprocess(t, "-check-node-history-state", "-node-history-config-root", configRoot, "-node-history-state-root", stateRoot)
	if err != nil || strings.TrimSpace(string(output)) != `{"ok":true}` {
		t.Fatal("CLI did not admit actual typed history", string(output), err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("compatibility check rewrote nodes", err)
	}
	if err = checkNodeHistoryState(context.Background(), configRoot, stateRoot, 1); err == nil {
		t.Fatal("reader1 admitted retained Xray history")
	}
	for _, reader := range []int{2, 3} {
		if err := checkNodeHistoryState(context.Background(), configRoot, stateRoot, reader); err != nil {
			t.Fatal("RAW Xray history rejected by compatible typed reader", reader, err)
		}
	}
	entries, err := os.ReadDir(stateRoot)
	if err != nil || len(entries) != 0 {
		t.Fatal("read-only CLI bootstrapped state", entries, err)
	}
}

func TestNodeHistoryStateLegacyEmptyAndUnknownRefusal(t *testing.T) {
	configRoot, stateRoot, _, _ := nodeHistoryStateFixture(t, false)
	if err := checkNodeHistoryState(context.Background(), configRoot, stateRoot, 1); err != nil {
		t.Fatal("legacy history rejected", err)
	}
	if err := os.Mkdir(filepath.Join(stateRoot, "backup"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateRoot, "backup", "nodes.private.json"), []byte(`{"private":"private-state.example","future_schema":999}`), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := selfUpdateMainSubprocess(t, "-check-node-history-state", "-node-history-config-root", configRoot, "-node-history-state-root", stateRoot)
	if err == nil || strings.Contains(string(output), "private-state.example") || strings.Contains(string(output), `"ok":true`) {
		t.Fatal("unknown retained image authorized or leaked", string(output), err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if err := checkNodeHistoryState(context.Background(), missing, filepath.Join(missing, "state"), 2); err != nil {
		t.Fatal("empty installation rejected", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("empty inspection created root", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkNodeHistoryState(ctx, missing, filepath.Join(missing, "state"), 2); err == nil {
		t.Fatal("canceled empty inspection authorized")
	}
	if err := checkNodeHistoryState(context.Background(), "relative", stateRoot, 2); err == nil {
		t.Fatal("relative deployment root accepted")
	}
}
