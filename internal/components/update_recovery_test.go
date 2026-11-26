package components

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prepareJournalFixture(t *testing.T) (*Manager, *managedRunner, string) {
	t.Helper()
	m, r, conf := managedFixture(t)
	if _, err := m.CacheRollbackPackage(context.Background(), "nfqws2"); err != nil {
		t.Fatal(err)
	}
	r.available = "1.3.2"
	if _, err := m.List(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	return m, r, conf
}

func restartedManager(m *Manager) *Manager {
	return &Manager{Opkg: m.Opkg, Runner: m.Runner, RepoDir: m.RepoDir, StateDir: m.StateDir, InfoDir: m.InfoDir, Client: m.Client}
}

func allowRecovery(context.Context) error { return nil }

func packageMutations(r *managedRunner) int {
	n := 0
	for _, call := range r.calls {
		if strings.HasPrefix(call, "upgrade ") || strings.HasPrefix(call, "install ") || strings.HasPrefix(call, "remove ") {
			n++
		}
	}
	return n
}

func TestManagedUpdateRequiresSeparateLiveAcceptanceAndPreservesLKG(t *testing.T) {
	m, r, _ := prepareJournalFixture(t)
	old := m.rollbackPackage(Spec{Package: "nfqws2-keenetic"}, "1.3.1")
	result, err := m.ManagedUpdate(context.Background(), "nfqws2", allowRecovery)
	if err != nil || !result.OK || !result.PendingLiveAcceptance || result.TransactionID == "" {
		t.Fatalf("candidate result=%+v err=%v", result, err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatalf("old LKG lost before acceptance: %v", err)
	}
	m = restartedManager(m)
	state, pending, err := m.PendingManagedUpdate()
	if err != nil || !pending || state.Phase != UpdateAwaitingLive || state.TransactionID != result.TransactionID {
		t.Fatalf("state=%+v pending=%v err=%v", state, pending, err)
	}
	view := View{Spec: Spec{ID: "nfqws2"}, Installed: true, InstalledVersion: r.installed}
	m.attachLifecycleVerification(&view)
	if view.Verification != "awaiting-live-acceptance" {
		t.Fatalf("candidate falsely verified: %+v", view)
	}
	request := ManagedRecoveryRequest{Component: "nfqws2", TransactionID: state.TransactionID, Action: "accept-live"}
	if _, err := m.RecoverManagedUpdate(context.Background(), request, allowRecovery, func(context.Context) error { return errors.New("live runtime still old") }); err == nil {
		t.Fatal("failed live check accepted")
	}
	if _, pending, _ := m.PendingManagedUpdate(); !pending {
		t.Fatal("failed acceptance removed fence")
	}
	if _, err := m.RecoverManagedUpdate(context.Background(), request, allowRecovery, allowRecovery); err != nil {
		t.Fatal(err)
	}
	state, pending, err = m.PendingManagedUpdate()
	if err != nil || pending || state.Phase != UpdateAccepted {
		t.Fatalf("acceptance not durable: %+v %v %v", state, pending, err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatal("acceptance unexpectedly deleted retained LKG", err)
	}
}

func TestManagedUpdatePhaseInterruptionsNeverReplayUnknownCommands(t *testing.T) {
	points := []string{
		"before:prepared", "after:prepared", "before:upgrade-started", "after:upgrade-started",
		"before:upgrade-command", "after:upgrade-command", "before:upgrade-finished", "after:upgrade-finished",
		"before:candidate-receipt", "after:candidate-receipt",
		"before:rollback-config-before", "after:rollback-config-before", "before:restore-before:0", "after:restore-before:0",
		"before:rollback-ready", "after:rollback-ready", "before:rollback-started", "after:rollback-started",
		"before:rollback-command", "after:rollback-command", "before:rollback-installed", "after:rollback-installed",
		"before:rollback-config-after", "after:rollback-config-after", "before:restore-after:0", "after:restore-after:0",
		"before:awaiting-rollback-acceptance", "after:awaiting-rollback-acceptance", "before:receipt", "after:receipt",
		"before:rolled-back", "after:rolled-back",
	}
	for _, point := range points {
		t.Run(strings.ReplaceAll(point, ":", "-"), func(t *testing.T) {
			m, runner, conf := prepareJournalFixture(t)
			fired := false
			m.updateFault = func(current string) error {
				if current == point {
					fired = true
					panic("process interrupted")
				}
				return nil
			}
			func() {
				defer func() {
					if recovered := recover(); recovered != "process interrupted" {
						t.Fatalf("unexpected crash %v", recovered)
					}
				}()
				_, _ = m.ManagedUpdateGuardedWithRollback(context.Background(), "nfqws2", func(context.Context) error {
					if runner.installed != "1.3.1" {
						return errors.New("candidate failed")
					}
					return nil
				}, nil, allowRecovery)
			}()
			if !fired {
				t.Fatalf("fault point not reached: %s", point)
			}
			fresh := restartedManager(m)
			beforeCalls := packageMutations(runner)
			state, pending, err := fresh.PendingManagedUpdate()
			if err != nil {
				t.Fatal(err)
			}
			if packageMutations(runner) != beforeCalls {
				t.Fatal("inspection mutated package")
			}
			if !pending {
				if point != "before:prepared" && point != "after:rolled-back" {
					t.Fatalf("interruption lost fence: %+v", state)
				}
				return
			}
			if _, err := fresh.ManagedUpdate(context.Background(), "nfqws2", allowRecovery); !errors.Is(err, ErrUpdatePending) {
				t.Fatalf("restart allowed update: %v", err)
			}
			if _, err := fresh.Apply(context.Background(), "nfqws2"); !errors.Is(err, ErrUpdatePending) {
				t.Fatalf("plain Apply bypassed journal: %v", err)
			}
			if _, err := fresh.Remove(context.Background(), "nfqws2"); !errors.Is(err, ErrUpdatePending) {
				t.Fatalf("Remove bypassed journal: %v", err)
			}
			request := ManagedRecoveryRequest{TransactionID: state.TransactionID, Component: state.Component, Action: "rollback"}
			if state.Phase == UpdateStarted || state.Phase == UpdateRollbackStarted {
				if _, err := fresh.RecoverManagedUpdate(context.Background(), request, allowRecovery, allowRecovery); !errors.Is(err, ErrUpdateUnknown) {
					t.Fatalf("unknown command replayed: %v", err)
				}
				if packageMutations(runner) != beforeCalls {
					t.Fatal("unknown command ran again")
				}
				return
			}
			if state.Phase == UpdatePrepared {
				request.Action = "abandon-prepared"
			}
			if _, err := fresh.RecoverManagedUpdate(context.Background(), request, allowRecovery, allowRecovery); err != nil {
				t.Fatalf("known phase did not recover: %s %v", state.Phase, err)
			}
			if _, pending, err := fresh.PendingManagedUpdate(); err != nil || pending {
				t.Fatalf("recovery not durably settled: %v %v", pending, err)
			}
			if state.Phase != UpdatePrepared {
				data, _ := os.ReadFile(conf)
				if runner.installed != "1.3.1" || string(data) != "USER STRATEGIES\n" {
					t.Fatalf("snapshot not restored: version=%s config=%q", runner.installed, data)
				}
			}
		})
	}
}

func TestManagedRecoveryMatchesAuthorityAndTransaction(t *testing.T) {
	for _, mode := range []string{"wrong-id", "wrong-component", "safe-mode", "stopped", "no-guard", "changed-authority"} {
		t.Run(mode, func(t *testing.T) {
			m, runner, _ := prepareJournalFixture(t)
			result, err := m.ManagedUpdate(context.Background(), "nfqws2", allowRecovery)
			if err != nil {
				t.Fatal(err)
			}
			request := ManagedRecoveryRequest{TransactionID: result.TransactionID, Component: "nfqws2", Action: "rollback"}
			guard := allowRecovery
			switch mode {
			case "wrong-id":
				request.TransactionID = strings.Repeat("0", 32)
			case "wrong-component":
				request.Component = "xray"
			case "safe-mode":
				request.SafeMode = true
			case "stopped":
				request.Stopped = true
			case "no-guard":
				guard = nil
			case "changed-authority":
				guard = func(context.Context) error { return errors.New("revision changed") }
			}
			before := packageMutations(runner)
			if _, err := restartedManager(m).RecoverManagedUpdate(context.Background(), request, guard, allowRecovery); err == nil {
				t.Fatal("unauthorized recovery accepted")
			}
			if packageMutations(runner) != before {
				t.Fatal("unauthorized recovery mutated package")
			}
		})
	}
}

func TestManagedRecoveryStopsWhenAuthorityChangesBetweenConfigAndPackage(t *testing.T) {
	m, runner, _ := prepareJournalFixture(t)
	result, err := m.ManagedUpdate(context.Background(), "nfqws2", allowRecovery)
	if err != nil {
		t.Fatal(err)
	}
	m = restartedManager(m)
	stopped := false
	m.updateFault = func(point string) error {
		if point == "after:restore-before:0" {
			stopped = true
		}
		return nil
	}
	guard := func(context.Context) error {
		if stopped {
			return ErrRecoveryAuthority
		}
		return nil
	}
	before := packageMutations(runner)
	_, err = m.RecoverManagedUpdate(context.Background(), ManagedRecoveryRequest{TransactionID: result.TransactionID, Component: "nfqws2", Action: "rollback"}, guard, allowRecovery)
	if !errors.Is(err, ErrRecoveryAuthority) || packageMutations(runner) != before {
		t.Fatalf("Stop allowed rollback install: %v", err)
	}
	state, pending, _ := m.PendingManagedUpdate()
	if !pending || state.Phase != UpdateRollbackReady {
		t.Fatalf("Stop lost matching repair state: %+v", state)
	}
}

func TestManagedRecoveryRejectsCorruptSnapshotBeforeMutation(t *testing.T) {
	for _, part := range []string{"package", "config", "schema"} {
		t.Run(part, func(t *testing.T) {
			m, runner, _ := prepareJournalFixture(t)
			result, err := m.ManagedUpdate(context.Background(), "nfqws2", allowRecovery)
			if err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(m.updateJournalDir(), "current.json")
			data, _ := os.ReadFile(journal)
			var doc updateJournal
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			switch part {
			case "package":
				err = os.WriteFile(filepath.Join(m.updateJournalDir(), doc.TransactionID, doc.PackageFile), []byte("changed"), 0o600)
			case "config":
				err = os.WriteFile(filepath.Join(m.updateJournalDir(), doc.TransactionID, doc.Configs[0].Blob), []byte("changed"), 0o600)
			case "schema":
				doc.SchemaVersion++
				data, _ = json.Marshal(doc)
				err = os.WriteFile(journal, data, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := packageMutations(runner)
			_, err = restartedManager(m).RecoverManagedUpdate(context.Background(), ManagedRecoveryRequest{TransactionID: result.TransactionID, Component: "nfqws2", Action: "rollback"}, allowRecovery, allowRecovery)
			if err == nil || packageMutations(runner) != before {
				t.Fatalf("corrupt snapshot mutated package: %v", err)
			}
		})
	}
}

func TestManagedJournalSerializesIndependentManagers(t *testing.T) {
	m, runner, _ := prepareJournalFixture(t)
	tx, err := m.lockUpdateJournal()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.close()
	before := packageMutations(runner)
	if _, err := restartedManager(m).ManagedUpdate(context.Background(), "nfqws2", allowRecovery); err == nil {
		t.Fatal("independent writer passed OS lock")
	}
	if packageMutations(runner) != before {
		t.Fatal("competing writer mutated package")
	}
}

func TestUnknownRollbackRequiresExternalInspectionAndQuiescence(t *testing.T) {
	m, runner, _ := prepareJournalFixture(t)
	m.updateFault = func(point string) error {
		if point == "after:rollback-command" {
			panic("interrupted")
		}
		return nil
	}
	func() {
		defer func() {
			if recover() != "interrupted" {
				t.Fatal("interruption not reached")
			}
		}()
		_, _ = m.ManagedUpdate(context.Background(), "nfqws2", func(context.Context) error {
			if runner.installed != "1.3.1" {
				return errors.New("candidate failed")
			}
			return nil
		})
	}()
	m = restartedManager(m)
	state, pending, err := m.PendingManagedUpdate()
	if err != nil || !pending || state.Phase != UpdateRollbackStarted {
		t.Fatalf("unexpected interrupted state: %+v %v", state, err)
	}
	request := ManagedRecoveryRequest{Component: state.Component, TransactionID: state.TransactionID, Action: "verify-rollback", ExternalRepairConfirmed: true}
	before := packageMutations(runner)
	if _, err := m.RecoverManagedUpdate(context.Background(), request, allowRecovery, allowRecovery); !errors.Is(err, ErrUpdateUnknown) {
		t.Fatalf("boolean alone resolved unknown: %v", err)
	}
	request.QuiescenceCheck = func(context.Context) error { return errors.New("orphan postinst still active") }
	if _, err := m.RecoverManagedUpdate(context.Background(), request, allowRecovery, allowRecovery); err == nil {
		t.Fatal("active package script accepted")
	}
	request.QuiescenceCheck = allowRecovery
	request.ExternalRepairConfirmed = false
	if _, err := m.RecoverManagedUpdate(context.Background(), request, allowRecovery, allowRecovery); !errors.Is(err, ErrUpdateUnknown) {
		t.Fatalf("external inspection omitted: %v", err)
	}
	request.ExternalRepairConfirmed = true
	if _, err := m.RecoverManagedUpdate(context.Background(), request, allowRecovery, allowRecovery); err != nil {
		t.Fatal(err)
	}
	if packageMutations(runner) != before {
		t.Fatal("observation replayed a package command")
	}
}

func TestLiveAcceptanceInterruptionKeepsFenceUntilDurableCompletion(t *testing.T) {
	for _, point := range []string{"before:awaiting-live-acceptance", "after:awaiting-live-acceptance", "before:receipt", "after:receipt", "before:accepted", "after:accepted"} {
		t.Run(strings.ReplaceAll(point, ":", "-"), func(t *testing.T) {
			m, _, _ := prepareJournalFixture(t)
			inject := func(current string) error {
				if current == point {
					panic("interrupted")
				}
				return nil
			}
			func() {
				defer func() {
					if recover() != "interrupted" {
						t.Fatal("interruption not reached")
					}
				}()
				if strings.Contains(point, "awaiting-live") {
					m.updateFault = inject
					_, _ = m.ManagedUpdate(context.Background(), "nfqws2", allowRecovery)
					return
				}
				result, err := m.ManagedUpdate(context.Background(), "nfqws2", allowRecovery)
				if err != nil {
					t.Fatal(err)
				}
				m.updateFault = inject
				_, _ = m.RecoverManagedUpdate(context.Background(), ManagedRecoveryRequest{Component: "nfqws2", TransactionID: result.TransactionID, Action: "accept-live"}, allowRecovery, allowRecovery)
			}()
			state, pending, err := restartedManager(m).PendingManagedUpdate()
			if err != nil {
				t.Fatal(err)
			}
			if point == "after:accepted" {
				if pending || state.Phase != UpdateAccepted {
					t.Fatalf("completed acceptance not durable: %+v", state)
				}
			} else if !pending {
				t.Fatalf("acceptance interruption removed fence: %+v", state)
			}
		})
	}
}

func TestCandidateVersionChangingDuringCheckIsNotAccepted(t *testing.T) {
	m, r, _ := prepareJournalFixture(t)
	result, err := m.ManagedUpdate(context.Background(), "nfqws2", func(context.Context) error { r.installed = "1.3.3"; return nil })
	if !errors.Is(err, ErrRollbackUnconfirmed) || result.PendingLiveAcceptance {
		t.Fatalf("unchecked version accepted: %+v %v", result, err)
	}
	state, pending, _ := m.PendingManagedUpdate()
	if !pending || state.Phase != UpdateInstalled {
		t.Fatalf("version race lost fence: %+v", state)
	}
}

func TestPlainApplyCannotUpgradeInstalledManagedComponent(t *testing.T) {
	m, r, _ := prepareJournalFixture(t)
	before := packageMutations(r)
	result, err := m.Apply(context.Background(), "nfqws2")
	if result.OK || !errors.Is(err, ErrManagedUpdateRequired) || !errors.Is(err, ErrNoMutation) {
		t.Fatalf("plain installed update not fenced: %+v %v", result, err)
	}
	if packageMutations(r) != before {
		t.Fatal("plain update modified package")
	}
}
