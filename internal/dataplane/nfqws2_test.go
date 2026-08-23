package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type nfqwsFakeRunner struct{ calls []string }

func (r *nfqwsFakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if len(args) > 0 && args[0] == "status" {
		return []byte("service is running"), nil
	}
	if strings.Contains(name, "iptables-save") {
		return []byte("-A nfqws_post -j NFQUEUE --queue-num 300"), nil
	}
	return []byte("ok"), nil
}

func TestNFQWS2AdapterManagedListsAndRollback(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "nfqws2.conf")
	initPath := filepath.Join(root, "S51nfqws2")
	userPath := filepath.Join(root, "user.list")
	ipsetPath := filepath.Join(root, "ipset.list")
	iptablesSave := filepath.Join(root, "iptables-save")
	for path, content := range map[string]string{
		configPath: "ISP_INTERFACE=eth3\n", initPath: "#!/bin/sh\n", userPath: "manual.example\n", ipsetPath: "192.0.2.1\n", iptablesSave: "#!/bin/sh\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runner := &nfqwsFakeRunner{}
	adapter := &NFQWS2Adapter{ConfigPath: configPath, InitPath: initPath, UserListPath: userPath, IPSetListPath: ipsetPath, IPTablesSave: iptablesSave, Runner: runner, HealthProbe: func(context.Context, string) error { return nil }}
	transaction := filepath.Join(root, "transaction")
	if err := os.MkdirAll(transaction, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Routes: []Route{{ServiceName: "YouTube", Resolved: "nfqws2", Domains: []string{"youtube.com", "googlevideo.com"}, CIDRs: []string{"203.0.113.0/24"}, ProbeURL: "https://example.com"}}}
	if err := adapter.Snapshot(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Stage(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Validate(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Activate(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(userPath)
	if !strings.Contains(string(data), "manual.example") || !strings.Contains(string(data), managedBegin+"\ngooglevideo.com\nyoutube.com\n"+managedEnd) {
		t.Fatalf("managed user list=%q", data)
	}
	if err := adapter.Health(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Commit(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Rollback(context.Background(), plan, transaction); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(userPath)
	if string(data) != "manual.example\n" {
		t.Fatalf("rollback user list=%q", data)
	}
	data, _ = os.ReadFile(ipsetPath)
	if string(data) != "192.0.2.1\n" {
		t.Fatalf("rollback ipset list=%q", data)
	}
}

func TestReplaceManagedBlockRejectsBrokenOwnershipMarkers(t *testing.T) {
	if _, err := replaceManagedBlock(managedBegin+"\nexample.com\n", []string{"new.example"}); err == nil {
		t.Fatal("malformed ownership block was accepted")
	}
}

func TestNFQWS2DeactivateRemovesOnlyManagedBlocks(t *testing.T) {
	root := t.TempDir()
	initPath := filepath.Join(root, "S51nfqws2")
	userPath := filepath.Join(root, "user.list")
	ipsetPath := filepath.Join(root, "ipset.list")
	for path, content := range map[string]string{
		initPath:  "#!/bin/sh\n",
		userPath:  "manual.example\n" + managedBegin + "\nmanaged.example\n" + managedEnd + "\n",
		ipsetPath: managedBegin + "\n203.0.113.0/24\n" + managedEnd + "\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runner := &nfqwsFakeRunner{}
	adapter := &NFQWS2Adapter{InitPath: initPath, UserListPath: userPath, IPSetListPath: ipsetPath, Runner: runner}
	if err := adapter.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	user, _ := os.ReadFile(userPath)
	ipset, _ := os.ReadFile(ipsetPath)
	if string(user) != "manual.example\n" || len(ipset) != 0 {
		t.Fatalf("unexpected cleanup: user=%q ipset=%q", user, ipset)
	}
	if len(runner.calls) != 1 || !strings.HasSuffix(runner.calls[0], " restart") {
		t.Fatalf("NFQWS2 was not reloaded once: %v", runner.calls)
	}
	if err := adapter.Deactivate(context.Background()); err != nil || len(runner.calls) != 1 {
		t.Fatalf("deactivation is not idempotent: calls=%v err=%v", runner.calls, err)
	}
}
