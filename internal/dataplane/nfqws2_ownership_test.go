package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nfqws2RunFunc func(context.Context, string, ...string) ([]byte, error)

func (run nfqws2RunFunc) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return run(ctx, name, args...)
}

func newOwnedNFQWS2(t *testing.T) (*NFQWS2Adapter, *nfqwsFakeRunner, string) {
	t.Helper()
	root := t.TempDir()
	a := &NFQWS2Adapter{ConfigPath: filepath.Join(root, "nfqws2.conf"), InitPath: filepath.Join(root, "S51nfqws2"),
		UserListPath: filepath.Join(root, "user.list"), IPSetListPath: filepath.Join(root, "ipset.list")}
	for path, content := range map[string]string{a.ConfigPath: "ISP_INTERFACE=eth3\n", a.InitPath: "#!/bin/sh\n", a.UserListPath: "manual.example\n", a.IPSetListPath: "192.0.2.10\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &nfqwsFakeRunner{}
	a.Runner = runner
	manager := New(filepath.Join(root, "instance-a"))
	if err := manager.Register(a); err != nil {
		t.Fatal(err)
	}
	return a, runner, root
}

func stageOwnedNFQWS2(t *testing.T, a *NFQWS2Adapter, root, domain string) string {
	t.Helper()
	transaction := filepath.Join(root, domain)
	if err := os.MkdirAll(transaction, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Routes: []Route{{Resolved: "nfqws2", Domains: []string{domain}, CIDRs: []string{"203.0.113.0/24"}}}}
	for _, call := range []func(context.Context, Plan, string) error{a.Snapshot, a.Stage, a.Validate} {
		if err := call(context.Background(), plan, transaction); err != nil {
			t.Fatal(err)
		}
	}
	return transaction
}

func readNFQWS2Files(t *testing.T, a *NFQWS2Adapter) [][]byte {
	t.Helper()
	var result [][]byte
	for _, path := range []string{a.ConfigPath, a.UserListPath, a.IPSetListPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, data)
	}
	return result
}

func assertNFQWS2Files(t *testing.T, a *NFQWS2Adapter, before [][]byte) {
	t.Helper()
	for index, data := range readNFQWS2Files(t, a) {
		if !bytes.Equal(data, before[index]) {
			t.Fatalf("shared NFQWS2 resource %d changed", index)
		}
	}
}

func TestNFQWS2EmptyInstanceCannotDeactivateForeignManagedLists(t *testing.T) {
	a, runner, root := newOwnedNFQWS2(t)
	transaction := stageOwnedNFQWS2(t, a, root, "owned.example")
	if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
		t.Fatal(err)
	}
	before := readNFQWS2Files(t, a)
	other := *a
	other.StateRoot = ""
	otherRunner := &nfqwsFakeRunner{}
	other.Runner = otherRunner
	manager := New(filepath.Join(root, "empty-instance-b"))
	if err := manager.Register(&other); err != nil {
		t.Fatal(err)
	}
	report, err := manager.Deactivate(context.Background())
	if err != nil || report.State != "deactivated" || len(otherRunner.calls) != 0 {
		t.Fatalf("empty instance changed runtime: report=%+v err=%v calls=%v", report, err, otherRunner.calls)
	}
	assertNFQWS2Files(t, a, before)
	// A process restart retains this instance's durable ownership.
	restarted := *a
	runner.calls = nil
	if err := restarted.Deactivate(context.Background()); err != nil || len(runner.calls) != 1 {
		t.Fatalf("owned cleanup after restart: err=%v calls=%v", err, runner.calls)
	}
	if err := restarted.Deactivate(context.Background()); err != nil || len(runner.calls) != 1 {
		t.Fatalf("cleanup is not idempotent: %v", err)
	}
}

func TestNFQWS2ConcurrentInstancesSerializeBeforeGlobalWrites(t *testing.T) {
	a, _, root := newOwnedNFQWS2(t)
	b := *a
	b.StateRoot = ""
	b.Runner = &nfqwsFakeRunner{}
	if err := New(filepath.Join(root, "instance-b")).Register(&b); err != nil {
		t.Fatal(err)
	}
	first := stageOwnedNFQWS2(t, a, root, "first.example")
	second := stageOwnedNFQWS2(t, &b, root, "second.example")
	before := readNFQWS2Files(t, a)
	entered, release := make(chan struct{}), make(chan struct{})
	a.activationLeaseReady = func() { close(entered); <-release }
	finished := make(chan error, 1)
	go func() { finished <- a.Activate(context.Background(), Plan{}, first) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("first instance did not reach pre-write barrier")
	}
	err := b.Activate(context.Background(), Plan{}, second)
	var refusal preflightRefusalError
	if !errors.As(err, &refusal) {
		close(release)
		<-finished
		t.Fatalf("second instance did not refuse held shared resource: %v", err)
	}
	assertNFQWS2Files(t, a, before)
	if lease, err := b.readLease(); err != nil || lease != nil {
		close(release)
		<-finished
		t.Fatalf("refused instance acquired a runtime lease: %+v %v", lease, err)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	committed := readNFQWS2Files(t, a)
	if err := b.Activate(context.Background(), Plan{}, second); err == nil {
		t.Fatal("stale second snapshot overwrote the first owner")
	}
	assertNFQWS2Files(t, a, committed)
	if err := a.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNFQWS2PartialActivationHasDurableCleanupAuthority(t *testing.T) {
	a, runner, root := newOwnedNFQWS2(t)
	before := readNFQWS2Files(t, a)
	transaction := stageOwnedNFQWS2(t, a, root, "partial.example")
	// Simulate power loss after the durable intent and the first list write.
	if err := a.prepareActivationLease(transaction); err != nil {
		t.Fatal(err)
	}
	if err := installStagedMode(filepath.Join(transaction, "user.list.staged"), a.UserListPath, 0o644); err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	restarted := *a
	if err := restarted.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertNFQWS2Files(t, a, before)
	if len(runner.calls) != 1 {
		t.Fatalf("partial cleanup reload=%v", runner.calls)
	}
}

func TestNFQWS2ForeignDriftRefusesCleanupAndRollbackBeforeWrites(t *testing.T) {
	for _, resource := range []string{"second-list", "config", "manifest", "init"} {
		t.Run(resource, func(t *testing.T) {
			a, runner, root := newOwnedNFQWS2(t)
			transaction := stageOwnedNFQWS2(t, a, root, "owned.example")
			if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
				t.Fatal(err)
			}
			path, replacement := a.IPSetListPath, managedBegin+"\n# RAZVILKA INSTANCE foreign\n198.51.100.0/24\n"+managedEnd+"\n"
			switch resource {
			case "config":
				path, replacement = a.ConfigPath, "foreign-config\n"
			case "manifest":
				path, replacement = filepath.Join(a.StateRoot, nfqws2LeaseFile), "{broken"
			case "init":
				path, replacement = a.InitPath, "#!/bin/sh\n# replacement\n"
			}
			if err := os.WriteFile(path, []byte(replacement), 0o600); err != nil {
				t.Fatal(err)
			}
			before := readNFQWS2Files(t, a)
			runner.calls = nil
			if err := a.Deactivate(context.Background()); err == nil {
				t.Fatal("foreign drift allowed cleanup")
			}
			if err := a.Rollback(context.Background(), Plan{}, transaction); err == nil {
				t.Fatal("foreign drift allowed rollback")
			}
			assertNFQWS2Files(t, a, before)
			if len(runner.calls) != 0 {
				t.Fatalf("foreign drift restarted shared daemon: %v", runner.calls)
			}
		})
	}
}

func TestNFQWS2RollbackRestoresPriorInstanceLease(t *testing.T) {
	a, _, root := newOwnedNFQWS2(t)
	first := stageOwnedNFQWS2(t, a, root, "first.example")
	if err := a.Activate(context.Background(), Plan{}, first); err != nil {
		t.Fatal(err)
	}
	before := readNFQWS2Files(t, a)
	second := stageOwnedNFQWS2(t, a, root, "second.example")
	if err := a.Activate(context.Background(), Plan{}, second); err != nil {
		t.Fatal(err)
	}
	if err := a.Rollback(context.Background(), Plan{}, second); err != nil {
		t.Fatal(err)
	}
	assertNFQWS2Files(t, a, before)
	lease, err := a.readLease()
	if err != nil || lease == nil || lease.Transaction != first {
		t.Fatalf("prior lease not restored: %+v %v", lease, err)
	}
	if err := a.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNFQWS2LegacyMarkerAndUnknownLockAreNotAuthority(t *testing.T) {
	t.Run("legacy-marker", func(t *testing.T) {
		a, runner, root := newOwnedNFQWS2(t)
		if err := os.WriteFile(a.UserListPath, []byte(managedBegin+"\nlegacy.example\n"+managedEnd+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := readNFQWS2Files(t, a)
		transaction := filepath.Join(root, "legacy")
		if err := os.MkdirAll(transaction, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := a.Snapshot(context.Background(), Plan{}, transaction); err != nil {
			t.Fatal(err)
		}
		runner.calls = nil
		if err := a.Stage(context.Background(), Plan{}, transaction); err == nil {
			t.Fatal("generic marker authorized replacement")
		}
		if err := a.Deactivate(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertNFQWS2Files(t, a, before)
		if len(runner.calls) != 0 {
			t.Fatalf("generic marker authorized reload: %v", runner.calls)
		}
	})
	t.Run("unknown-lock", func(t *testing.T) {
		a, runner, root := newOwnedNFQWS2(t)
		transaction := stageOwnedNFQWS2(t, a, root, "locked.example")
		lock := filepath.Join(filepath.Dir(a.UserListPath), "."+filepath.Base(a.UserListPath)+".razvilka-lock")
		if err := os.WriteFile(lock, []byte("foreign\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := readNFQWS2Files(t, a)
		runner.calls = nil
		if err := a.Activate(context.Background(), Plan{}, transaction); err == nil {
			t.Fatal("unknown shared lock accepted")
		}
		assertNFQWS2Files(t, a, before)
		if len(runner.calls) != 0 {
			t.Fatal("locked activation reached daemon")
		}
	})
}

func TestNFQWS2CleanupReloadFailureRetainsRetryAuthority(t *testing.T) {
	a, runner, root := newOwnedNFQWS2(t)
	transaction := stageOwnedNFQWS2(t, a, root, "retry.example")
	if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
		t.Fatal(err)
	}
	a.Runner = nfqws2RunFunc(func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("reload failed") })
	if err := a.Deactivate(context.Background()); err == nil {
		t.Fatal("failed reload reported successful cleanup")
	}
	if lease, err := a.readLease(); err != nil || lease == nil {
		t.Fatalf("failed reload discarded cleanup authority: %+v %v", lease, err)
	}
	data, _ := os.ReadFile(a.UserListPath)
	if strings.Contains(string(data), managedBegin) {
		t.Fatal("owned list removal did not precede reload failure")
	}
	a.Runner = runner
	if err := a.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
}
