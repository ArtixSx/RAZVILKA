//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/strategylab"
)

// Real main startup and HTTP, inside a fresh network namespace with no WAN.
// This proves panel recovery, not router/LAN readiness or live route recovery.
func TestPrivateStrategyRestoredPanelBoot(t *testing.T) {
	if os.Getenv("RAZVILKA_PRIVATE_PANEL_NATIVE") != "1" {
		t.Skip("isolated Linux panel startup fixture not requested")
	}
	if os.Getenv("RAZVILKA_PRIVATE_PANEL_NAMESPACE") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--net", os.Args[0], "-test.run=^TestPrivateStrategyRestoredPanelBoot$", "-test.v")
		cmd.Env = append(os.Environ(), "RAZVILKA_PRIVATE_PANEL_NAMESPACE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated panel fixture: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("namespace loopback: %v %s", err, out)
	}
	root := t.TempDir()
	state := strategylab.State{SchemaVersion: 4,
		Candidates: map[string]strategylab.Candidate{"candidate": {ID: "candidate", Incarnation: strings.Repeat("a", 32), PoolID: "tcp-tls", Name: "restored-panel-candidate", Arguments: "--filter-tcp=443", Validation: strategylab.Validation{OK: true, Native: true, Generation: strings.Repeat("b", 32)}}},
		Evidence:   []strategylab.Evidence{{CandidateID: "candidate", CandidateIncarnation: strings.Repeat("a", 32), ValidationGeneration: strings.Repeat("b", 32), ServiceID: "example", Protocol: "tcp", IPFamily: "ipv4", Success: true, RouteConfirmed: true, Outcome: "pass", CheckedAt: time.Now().UTC().Format(time.RFC3339)}},
		Selections: map[string]strategylab.Selection{"manual": {ServiceID: "example", CandidateID: "candidate", Protocol: "tcp", IPFamily: "ipv4", Mode: "manual", Frozen: true}},
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "archive-source.json")
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	m, err := strategylab.New(source)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := m.ExportPrivateIfPresent(context.Background())
	if err != nil || archive == nil {
		t.Fatal("archive", err)
	}
	path := filepath.Join(root, "strategy-lab-state")
	destination, err := strategylab.New(path)
	if err != nil {
		t.Fatal(err)
	}
	target, err := destination.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before, err := target.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after, err := target.RestoreImage(context.Background(), *archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.CompareAndSwap(context.Background(), before, after); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{"catalog": "service-catalog.json", "sources": "sources.json", "community-catalog": "community-catalog.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "configs", source))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	const token = "private-strategy-panel-fixture-0123456789abcdef"
	if err := os.WriteFile(filepath.Join(root, "token-file"), []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	for boot := 0; boot < 2; boot++ {
		privateStrategyPanelBoot(t, root, token)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, after.Data) {
		t.Fatal("panel restart changed restored history or manual intent", err)
	}
}

func privateStrategyPanelBoot(t *testing.T, root, token string) {
	t.Helper()
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.Addr().String()
	reserved.Close()
	args := []string{"-test.run=^TestSelfUpdateStartupSubprocess$", "--", "-listen", address}
	for _, name := range []string{"config", "catalog", "sources", "cache", "stage", "backups", "token-file", "credentials-file", "custom-services", "community-catalog", "warp-state", "cloudflare-state", "smart-route-state", "dataplane-state", "devices", "metrics-history", "strategy-lab-state", "audit-log", "dns-state", "node-state", "z2k-root", "component-state", "component-bin", "component-init", "component-repo", "component-info", "self-update-installation", "self-update-file-state", "self-update-helper-state", "self-update-control-state"} {
		args = append(args, "-"+name, filepath.Join(root, name))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), "RAZVILKA_SELF_UPDATE_BOOTSTRAP_TEST=1", "RAZVILKA_SELF_UPDATE_READER_FIXTURE_TEST="+filepath.Join(root, "fixed-readers"))
	output, err := os.CreateTemp(root, "panel-log-")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
		}
	}()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/api/v1/strategy-lab", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			var snapshot strategylab.Snapshot
			if response.StatusCode != 200 || readErr != nil || json.Unmarshal(data, &snapshot) != nil {
				t.Fatalf("restored panel response: %d %v %s", response.StatusCode, readErr, data)
			}
			if len(snapshot.Candidates) != 1 || snapshot.Candidates[0].Validation.OK || snapshot.Candidates[0].Validation.Native || len(snapshot.Evidence) != 1 || len(snapshot.Selections) != 1 || !snapshot.Selections[0].Frozen || snapshot.Selections[0].Healthy {
				t.Fatal("panel lost history/manual choice or revived restored evidence")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	logs, _ := os.ReadFile(output.Name())
	t.Fatalf("restored panel failed to start: %s", logs)
}
