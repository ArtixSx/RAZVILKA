//go:build linux && (amd64 || arm64) && razvilka_native_fixture

package app

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"golang.org/x/sys/unix"
)

var errManagedProbeFailedCleanup = errors.New("native failed Apply cleanup absence unproven")

// This is a fixture selector, never permission to remove a resource. Every
// resource must be terminal, and independent kernel/process reads follow it.
func managedProbeRolledBackExecution(e *dataplane.Execution) bool {
	if e == nil || e.State != "rolled-back" || !e.RollbackVerified || e.PlanID == "" || e.Digest == "" || len(e.Resources) == 0 {
		return false
	}
	seen := make(map[string]bool, len(e.Resources))
	for _, row := range e.Resources {
		if row.ID == "" || row.Kind == "" || seen[row.ID] || row.State != "removed" && row.State != "unused" {
			return false
		}
		seen[row.ID] = true
	}
	return true
}

func managedProbeFailedCleanupState(a *App, r *ManagedNFQWSListRuntime, expected *dataplane.Execution) error {
	if a == nil || r == nil || r.app != a || !r.original() || !managedProbeRolledBackExecution(expected) {
		return errManagedProbeFailedCleanup
	}
	r.mu.Lock()
	retained := r.active != nil || r.pending != nil || r.stopped != nil
	r.mu.Unlock()
	gate := a.Operations.Snapshot()
	if retained || gate.Active != 0 || gate.Exclusive || gate.Fenced || r.manager.HasPendingManagedNFQWS() || a.managedStrategyProbePending() || r.probe != nil && r.probe.Pending() {
		return errManagedProbeFailedCleanup
	}
	status, err := a.Dataplane.Status()
	if err != nil || !reflect.DeepEqual(status.Execution, expected) || !managedProbeRolledBackExecution(status.Execution) {
		return errManagedProbeFailedCleanup
	}
	return nil
}

func managedProbeCloseFailedApply(ctx context.Context, a *App, r *ManagedNFQWSListRuntime, expected *dataplane.Execution, readEmpty func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || readEmpty == nil {
		return errManagedProbeFailedCleanup
	}
	if err := managedProbeFailedCleanupState(a, r, expected); err != nil {
		return err
	}
	if err := readEmpty(ctx); err != nil {
		return err
	}
	if err := managedProbeFailedCleanupAbsent(ctx); err != nil {
		return err
	}
	if err := managedProbeFailedCleanupState(a, r, expected); err != nil {
		return err
	}
	if err := r.Close(ctx); err != nil {
		return err
	}
	// The original inventory descriptors may now be closed. Independently
	// re-read actual complete tables, queue registry and processes instead.
	return errors.Join(managedProbeFailedCleanupAbsent(ctx), managedProbeFailedCleanupState(a, r, expected))
}

func managedProbeFailedCleanupAbsent(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errManagedProbeFailedCleanup
	}
	for _, tool := range []string{"/usr/sbin/iptables-legacy-save", "/usr/sbin/ip6tables-legacy-save"} {
		rules, err := exec.CommandContext(ctx, tool).Output()
		if err != nil {
			return errors.Join(errManagedProbeFailedCleanup, ctx.Err())
		}
		for _, token := range strings.Fields(string(rules)) {
			if token == "NFQUEUE" || token == "QUEUE" || strings.Contains(token, "RZQ_") || strings.Contains(token, "RZP_") {
				return errManagedProbeFailedCleanup
			}
		}
	}
	queue, err := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
	if err != nil || strings.TrimSpace(string(queue)) != "" {
		return errManagedProbeFailedCleanup
	}
	return managedProbeFailedCleanupProcesses(ctx)
}

// The harness isolates networking but shares the host PID namespace. Inspect
// only the current network namespace; never signal/adopt a discovered process.
func managedProbeFailedCleanupProcesses(ctx context.Context) error {
	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil || selfNS == "" {
		return errManagedProbeFailedCleanup
	}
	selfExe, err := os.Stat("/proc/self/exe")
	if err != nil {
		return errManagedProbeFailedCleanup
	}
	proc, err := os.Open("/proc")
	if err != nil {
		return errManagedProbeFailedCleanup
	}
	entries, readErr := proc.ReadDir(8193)
	closeErr := proc.Close()
	if readErr != nil || closeErr != nil || len(entries) > 8192 {
		return errManagedProbeFailedCleanup
	}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		if ctx.Err() != nil {
			return errors.Join(errManagedProbeFailedCleanup, ctx.Err())
		}
		root := filepath.Join("/proc", entry.Name())
		ns, err := os.Readlink(filepath.Join(root, "ns/net"))
		if err != nil {
			// A missing namespace alone can also mean a still-unjoined zombie.
			// Skip only a PID confirmed gone, never unreadable/live entries.
			if managedProbePIDGone(root, err) {
				continue
			}
			return errManagedProbeFailedCleanup
		}
		if ns != selfNS {
			continue
		}
		exe, err := os.Stat(filepath.Join(root, "exe"))
		if err != nil {
			if managedProbePIDGone(root, err) {
				continue
			}
			return errManagedProbeFailedCleanup
		}
		link, err := os.Readlink(filepath.Join(root, "exe"))
		if err != nil {
			if managedProbePIDGone(root, err) {
				continue
			}
			return errManagedProbeFailedCleanup
		}
		name := filepath.Base(strings.TrimSuffix(link, " (deleted)"))
		if os.SameFile(selfExe, exe) || name == "rzv-nfqws2" || name == "nfqws2" || name == "nfqws" {
			return errManagedProbeFailedCleanup
		}
		closingNS, err := os.Readlink(filepath.Join(root, "ns/net"))
		if err != nil || closingNS != ns {
			return errManagedProbeFailedCleanup
		}
	}
	closingNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil || closingNS != selfNS || ctx.Err() != nil {
		return errors.Join(errManagedProbeFailedCleanup, ctx.Err())
	}
	return nil
}

func managedProbePIDGone(root string, original error) bool {
	if !errors.Is(original, os.ErrNotExist) && !errors.Is(original, unix.ESRCH) {
		return false
	}
	_, err := os.Stat(root)
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH)
}

func TestManagedProbeFailedCleanupTerminalVector(t *testing.T) {
	base := func() *dataplane.Execution {
		return &dataplane.Execution{PlanID: "fixture-plan", Digest: "fixture-digest", State: "rolled-back", RollbackVerified: true, Resources: []dataplane.ExecutionResource{{ID: "one", Kind: "nfqws-scoped", State: "removed"}, {ID: "two", Kind: "lan-policy", State: "unused"}}}
	}
	if !managedProbeRolledBackExecution(base()) {
		t.Fatal("complete removed/unused fixture vector refused")
	}
	for _, state := range []string{"active", "pending", "unknown", "rollback-failed", "committed"} {
		e := base()
		e.State = state
		if managedProbeRolledBackExecution(e) {
			t.Fatal("nonterminal state accepted", state)
		}
	}
	for _, mutate := range []func(*dataplane.Execution){
		func(e *dataplane.Execution) { e.RollbackVerified = false },
		func(e *dataplane.Execution) { e.Resources = nil },
		func(e *dataplane.Execution) { e.Resources[1].State = "prepared" },
		func(e *dataplane.Execution) { e.Resources[1].ID = e.Resources[0].ID },
		func(e *dataplane.Execution) { e.Resources[1].Kind = "" },
		func(e *dataplane.Execution) { e.PlanID = "" },
		func(e *dataplane.Execution) { e.Digest = "" },
	} {
		e := base()
		mutate(e)
		if managedProbeRolledBackExecution(e) {
			t.Fatal("incomplete terminal vector accepted")
		}
	}
	if managedProbeRolledBackExecution(nil) {
		t.Fatal("absent execution accepted")
	}
}
