//go:build linux

package components

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func fixtureSupervisedRunner(path string) execRunner {
	return execRunner{supervisorPath: os.Args[0], supervisorArgs: []string{"-test.run=^TestComponentPackageSupervisorHelper$", "--"}, supervisorEnv: []string{"RAZVILKA_SUPERVISOR_TEST_ROOT=" + filepath.Dir(path)}}
}

func (r nativeOpkgRunner) runSupervised(ctx context.Context, name string, args []string, record packageSupervision, root *ownedfs.Root, path string) ([]byte, error) {
	runner := fixtureSupervisedRunner(path)
	runner.supervisorEnv = append(runner.supervisorEnv, "RAZVILKA_EXPECTED_OFFLINE_ROOT="+r.root)
	prefix := []string{"--conf", r.config, "--offline-root", r.root, "--force-postinstall"}
	return runner.runSupervised(ctx, name, append(prefix, args...), record, root, path)
}

func TestComponentPackageSupervisorHelper(t *testing.T) {
	path := os.Getenv("RAZVILKA_SUPERVISOR_TEST_ROOT")
	if path == "" {
		return
	}
	if !filepath.IsAbs(path) || path == "/" || len(os.Args) < 4 {
		os.Exit(81)
	}
	args := os.Args[len(os.Args)-3:]
	if err := runPackageSupervisorAt(path, args[0], args[1], args[2], true); err != nil {
		os.Exit(82)
	}
	os.Exit(0)
}

func TestPackageDetachedFixture(t *testing.T) {
	stage := os.Getenv("RAZVILKA_DETACHED_STAGE")
	if stage == "" {
		return
	}
	path := os.Getenv("RAZVILKA_DETACHED_ROOT")
	if stage == "fork" || stage == "fork-hung" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPackageDetachedFixture$")
		next := "child"
		if stage == "fork-hung" {
			next = "hung"
		}
		cmd.Env = append(os.Environ(), "RAZVILKA_DETACHED_STAGE="+next)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			os.Exit(83)
		}
		os.Exit(0)
	}
	if err := os.WriteFile(filepath.Join(path, "ready"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		os.Exit(84)
	}
	for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
		if _, err := os.Stat(filepath.Join(path, "release")); err == nil && stage != "hung" {
			_ = os.WriteFile(filepath.Join(path, "done"), nil, 0600)
			os.Exit(0)
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(85)
}

func TestSupervisorCleanupWithoutChildrenInterface(t *testing.T) {
	proc := t.TempDir()
	for pid, parent := range map[int]int{10: 100, 11: 100, 12: 101} {
		if err := os.Mkdir(filepath.Join(proc, strconv.Itoa(pid)), 0700); err != nil {
			t.Fatal(err)
		}
		text := strconv.Itoa(pid) + " (name with ) brackets) S " + strconv.Itoa(parent) + " 100 " + strings.Repeat("0 ", 16) + "42"
		if err := os.WriteFile(filepath.Join(proc, strconv.Itoa(pid), "stat"), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	children := supervisorChildrenAt(proc, 100)
	if len(children) != 2 || children[10] != "42" || children[11] != "42" {
		t.Fatalf("exact PPID cleanup: %v", children)
	}
}

func TestPackageSupervisorHungChildDeadline(t *testing.T) {
	m, _, _ := prepareJournalFixture(t)
	tx, err := m.lockUpdateJournal()
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := lookup("nfqws2")
	images, err := m.snapshotConffiles(spec)
	if err != nil {
		t.Fatal(err)
	}
	m.Runner = execRunner{}
	if err := tx.prepare(spec, "1.3.1", m.rollbackPackage(spec, "1.3.1"), images); err != nil {
		t.Fatal(err)
	}
	if err := tx.phase(UpdateStarted); err != nil {
		t.Fatal(err)
	}
	id := tx.doc.TransactionID
	path := filepath.Join(m.updateJournalDir(), id)
	tx.close()
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	runner := fixtureSupervisedRunner(path)
	runner.supervisorEnv = append(runner.supervisorEnv, "RAZVILKA_DETACHED_STAGE=fork-hung", "RAZVILKA_DETACHED_ROOT="+path)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = runner.runSupervised(ctx, os.Args[0], []string{"-test.run=^TestPackageDetachedFixture$"}, packageSupervision{Schema: 1, TransactionID: id, Component: "nfqws2", Action: "upgrade", Containment: packageContainment, State: "intent"}, root, path)
	if err == nil {
		t.Fatal("timeout was reported as success")
	}
	if err := m.Quiescence(context.Background(), id, "nfqws2"); err != nil {
		t.Fatal("hung child not durably reaped", err)
	}
}

func TestPackageSupervisionDetachedAndSupervisorDeath(t *testing.T) {
	for _, dead := range []bool{false, true} {
		t.Run(strconv.FormatBool(dead), func(t *testing.T) {
			m, _, _ := prepareJournalFixture(t)
			tx, err := m.lockUpdateJournal()
			if err != nil {
				t.Fatal(err)
			}
			spec, _ := lookup("nfqws2")
			images, err := m.snapshotConffiles(spec)
			if err != nil {
				t.Fatal(err)
			}
			m.Runner = execRunner{}
			if err := tx.prepare(spec, "1.3.1", m.rollbackPackage(spec, "1.3.1"), images); err != nil {
				t.Fatal(err)
			}
			if err := tx.phase(UpdateStarted); err != nil {
				t.Fatal(err)
			}
			id := tx.doc.TransactionID
			path := filepath.Join(m.updateJournalDir(), id)
			tx.close()
			root, err := ownedfs.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			runner := fixtureSupervisedRunner(path)
			runner.supervisorEnv = append(runner.supervisorEnv, "RAZVILKA_DETACHED_STAGE=fork", "RAZVILKA_DETACHED_ROOT="+path)
			record := packageSupervision{Schema: 1, TransactionID: id, Component: "nfqws2", Action: "upgrade", Containment: packageContainment, State: "intent"}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := runner.runSupervised(ctx, os.Args[0], []string{"-test.run=^TestPackageDetachedFixture$"}, record, root, path)
				done <- err
			}()
			until := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(path, "ready")); err == nil {
					break
				}
				if time.Now().After(until) {
					t.Fatal("detached child did not start")
				}
				time.Sleep(10 * time.Millisecond)
			}
			defer os.WriteFile(filepath.Join(path, "release"), nil, 0600)
			if err := m.Quiescence(context.Background(), id, "nfqws2"); !errors.Is(err, ErrUpdateUnknown) {
				t.Fatal("live detached child was accepted", err)
			}
			if dead {
				journal, err := openUpdateRoot(m.updateJournalDir(), false)
				if err != nil {
					t.Fatal(err)
				}
				r, err := readSupervision(journal, id, "nfqws2", "upgrade")
				journal.Close()
				if err != nil {
					t.Fatal(err)
				}
				start, _, err := processBirth(r.PID)
				if err != nil || start != r.Start {
					t.Fatal("fixture supervisor identity changed")
				}
				if err := syscall.Kill(r.PID, syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(path, "release"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			err = <-done
			until = time.Now().Add(2 * time.Second)
			for {
				if _, e := os.Stat(filepath.Join(path, "done")); e == nil {
					break
				}
				if time.Now().After(until) {
					t.Fatal("fixture detached child did not exit")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if dead {
				if !errors.Is(err, ErrUpdateUnknown) {
					t.Fatalf("dead helper outcome %v", err)
				}
				if err := m.Quiescence(context.Background(), id, "nfqws2"); !errors.Is(err, ErrUpdateUnknown) {
					t.Fatal("same-boot dead helper must remain fenced", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := m.Quiescence(context.Background(), id, "nfqws2"); err != nil {
					t.Fatal("durably reaped child not accepted", err)
				}
			}
		})
	}
}

func TestSupervisionNewBootProvesOnlyInactivity(t *testing.T) {
	boot, err := bootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r := packageSupervision{State: "running", BootID: boot, PID: 999999, Start: "1"}
	if err := supervisionInactive(context.Background(), r); !errors.Is(err, ErrUpdateUnknown) {
		t.Fatal("PID absence not evidence", err)
	}
	if boot == "00000000-0000-0000-0000-000000000000" {
		r.BootID = "00000000-0000-0000-0000-000000000001"
	} else {
		r.BootID = "00000000-0000-0000-0000-000000000000"
	}
	if err := supervisionInactive(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}
