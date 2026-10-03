package components

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// diskPackageRunner is explicitly a package simulator. Its state is persisted
// so a real child-process exit cannot accidentally retain a memory snapshot.
type diskPackageRunner struct{ root string }

func (r diskPackageRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	path := filepath.Join(r.root, "installed-version")
	if len(args) == 1 {
		switch args[0] {
		case "update":
			return []byte("local fixture feed"), nil
		case "list":
			return []byte("nfqws2-keenetic - 1.3.2 - fixture\n"), nil
		case "list-installed":
			version, err := os.ReadFile(path)
			return []byte("nfqws2-keenetic - " + string(version) + " - fixture\n"), err
		}
	}
	version := ""
	if len(args) == 2 && args[0] == "upgrade" {
		version = "1.3.2"
	}
	if len(args) == 4 && args[0] == "install" {
		version = strings.Split(filepath.Base(args[3]), "_")[1]
	}
	if version == "" {
		return nil, fmt.Errorf("unexpected disk fixture command %v", args)
	}
	log, err := os.OpenFile(filepath.Join(r.root, "package-commands"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	_, writeErr := fmt.Fprintln(log, strings.Join(args, " "))
	err = errors.Join(writeErr, log.Sync(), log.Close())
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(version), 0o600); err != nil {
		return nil, err
	}
	if version == "1.3.2" {
		if err := os.WriteFile(filepath.Join(r.root, "nfqws2.conf"), []byte("MIGRATED\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return []byte("fixture command complete"), nil
}

func processFixtureManager(root string) *Manager {
	return &Manager{Opkg: "fixture-opkg", Runner: diskPackageRunner{root: root}, StateDir: filepath.Join(root, "state"), RepoDir: filepath.Join(root, "repo"), InfoDir: filepath.Join(root, "info")}
}

func TestManagedJournalAbruptProcessExit(t *testing.T) {
	if root := os.Getenv("RAZVILKA_COMPONENT_CRASH_CHILD"); root != "" {
		m := processFixtureManager(root)
		point := os.Getenv("RAZVILKA_COMPONENT_CRASH_POINT")
		m.updateFault = func(current string) error {
			if current == point {
				os.Exit(91)
			}
			return nil
		}
		_, _ = m.ManagedUpdate(context.Background(), "nfqws2", func(context.Context) error {
			data, _ := os.ReadFile(filepath.Join(root, "installed-version"))
			if string(data) != "1.3.1" {
				return errors.New("candidate failed")
			}
			return nil
		})
		t.Fatal("child did not reach interruption point")
	}
	for _, point := range []string{"after:prepared", "before:upgrade-command", "after:upgrade-command", "after:rollback-command", "after:rolled-back"} {
		t.Run(strings.ReplaceAll(point, ":", "-"), func(t *testing.T) {
			_, _, conf := prepareJournalFixture(t)
			root := filepath.Dir(conf)
			if err := os.WriteFile(filepath.Join(root, "installed-version"), []byte("1.3.1"), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestManagedJournalAbruptProcessExit$")
			cmd.Env = append(os.Environ(), "RAZVILKA_COMPONENT_CRASH_CHILD="+root, "RAZVILKA_COMPONENT_CRASH_POINT="+point)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 91 {
				t.Fatalf("child exit=%v output=%s", err, out)
			}
			fresh := processFixtureManager(root)
			state, pending, err := fresh.PendingManagedUpdate()
			if err != nil {
				t.Fatal(err)
			}
			if point == "after:rolled-back" {
				if pending || state.Phase != UpdateRolledBack {
					t.Fatalf("durable completion lost: %+v", state)
				}
				return
			}
			if !pending {
				t.Fatal("abrupt exit lost pending transaction")
			}
			before, _ := os.ReadFile(filepath.Join(root, "package-commands"))
			if _, err := fresh.ManagedUpdate(context.Background(), "nfqws2", allowRecovery); !errors.Is(err, ErrUpdatePending) {
				t.Fatalf("new process bypassed fence or retained stale OS lock: %v", err)
			}
			after, _ := os.ReadFile(filepath.Join(root, "package-commands"))
			if string(after) != string(before) {
				t.Fatal("restart replayed package command")
			}
		})
	}
}
