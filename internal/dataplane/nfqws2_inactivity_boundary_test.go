package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These cases describe existing evidence boundaries. They do not provide an
// inactivity observer or model native process/kernel proof as successful.
func TestNFQWS2SuccessfulDeactivateDoesNotProveRuntimeInactive(t *testing.T) {
	a, runner, root := newOwnedNFQWS2(t)
	transaction := stageOwnedNFQWS2(t, a, root, "owned.example")
	if err := a.Activate(context.Background(), Plan{}, transaction); err != nil {
		t.Fatal(err)
	}
	if lease, err := a.readLease(); err != nil || lease == nil {
		t.Fatal("activation did not create the owned resource lease", err)
	}
	runner.calls = nil
	if err := a.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 || runner.calls[0] != a.InitPath+" restart" {
		t.Fatal("deactivation no longer exercises the package restart boundary", runner.calls)
	}
	if lease, err := a.readLease(); err != nil || lease != nil {
		t.Fatal("deactivation did not retire the resource lease", err)
	}
	for _, path := range []string{a.UserListPath, a.IPSetListPath} {
		data, exists, err := nfqws2Read(path)
		block, blockErr := nfqws2Block(data)
		if err != nil || !exists || blockErr != nil || len(block) != 0 {
			t.Fatal("managed list cleanup was not completed", err, blockErr)
		}
	}
	// This is a new status read after a successful Deactivate, not its return
	// value or a cached PID. The package runner can still report running.
	output, err := a.run(context.Background(), a.InitPath, "status")
	if err != nil || !runningOutput(string(output)) {
		t.Fatal("fixture did not preserve a running package after managed-list cleanup", err)
	}
	if len(runner.calls) != 2 || runner.calls[1] != a.InitPath+" status" {
		t.Fatal("post-deactivation status was not freshly read", runner.calls)
	}
}

func TestNFQWS2StoppedRollbackProofDoesNotExcludeForeignQueue(t *testing.T) {
	a, _, root := newOwnedNFQWS2(t)
	a.IPTablesSave = "iptables-save"
	first := stageOwnedNFQWS2(t, a, root, "old.example")
	if err := a.Activate(context.Background(), Plan{}, first); err != nil {
		t.Fatal(err)
	}
	running := false
	foreignRules := []byte("*mangle\n-A foreign_chain -j NFQUEUE --queue-num 300\nCOMMIT\n")
	var calls []string
	a.Runner = nfqws2RunFunc(func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == a.InitPath && len(args) == 1 {
			switch args[0] {
			case "status":
				if running {
					return []byte("service is running"), nil
				}
				return []byte("service is not running"), errors.New("exit 1")
			case "restart":
				running = true
				return []byte("started"), nil
			case "stop":
				running = false
				return []byte("stopped"), nil
			}
		}
		if name == a.IPTablesSave && len(args) == 0 {
			return append([]byte(nil), foreignRules...), nil
		}
		return nil, errors.New("unexpected modeled command")
	})
	// The next transaction snapshots a stopped package and its existing owned
	// lists. Rollback must restore that snapshot, not claim global inactivity.
	next := stageOwnedNFQWS2(t, a, root, "next.example")
	if err := a.Activate(context.Background(), Plan{}, next); err != nil {
		t.Fatal(err)
	}
	if err := a.Rollback(context.Background(), Plan{}, next); err != nil {
		t.Fatal(err)
	}
	before := readNFQWS2Files(t, a)
	leasePath := filepath.Join(a.StateRoot, nfqws2LeaseFile)
	leaseBefore, err := os.ReadFile(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	confirmed, err := a.VerifyRollback(context.Background(), Plan{}, next)
	if err != nil || !confirmed || running {
		t.Fatal("stopped snapshot restoration was not confirmed", err)
	}
	if !strings.Contains(string(foreignRules), "-j NFQUEUE --queue-num 300") || nfqws2QueueRule(foreignRules, "300") {
		t.Fatal("fixture no longer leaves an uninspected foreign chain on the same queue")
	}
	if len(calls) != 2 || calls[0] != a.InitPath+" status" || calls[1] != a.IPTablesSave+" " {
		t.Fatal("rollback proof did not freshly read only package status and IPv4 rules", calls)
	}
	assertNFQWS2Files(t, a, before)
	leaseAfter, err := os.ReadFile(leasePath)
	if err != nil || string(leaseBefore) != string(leaseAfter) {
		t.Fatal("read-only rollback verification changed its ownership evidence", err)
	}
}
