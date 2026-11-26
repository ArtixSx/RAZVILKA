package restorejournal

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// These are isolated file-backed test adapters, NOT adapters for the app's
// cached stores. The Journal lease is the only writer in this fixture.
type testFileTarget struct {
	mu    sync.Mutex
	root  *ownedfs.Root
	name  string
	after func()
}

func (f *testFileTarget) Read(ctx context.Context) (Image, error) {
	if ctx.Err() != nil {
		return Image{}, ctx.Err()
	}
	data, err := f.root.ReadLimited(f.name, MaxImageBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Image{}, nil
	}
	if err != nil {
		return Image{}, err
	}
	return Image{Exists: true, Data: data}, nil
}

func (f *testFileTarget) CompareAndSwap(ctx context.Context, before, after Image) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, err := f.Read(ctx)
	if err != nil {
		return err
	}
	if !equal(current, before) {
		return injected
	}
	if after.Exists {
		err = f.root.WriteAtomic(f.name, after.Data, 0o600)
	} else {
		err = f.root.Remove(f.name)
	}
	if err != nil {
		return err
	}
	if err := syncJournalDir(f.root); err != nil {
		return err
	}
	if f.after != nil {
		f.after()
	}
	return nil
}

func fileTargets(t *testing.T, base string, hook func(string)) map[string]Target {
	t.Helper()
	root, err := ownedfs.Open(filepath.Join(base, "targets"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	targets := map[string]Target{}
	for _, id := range []string{"a", "b", "c"} {
		f := &testFileTarget{root: root, name: id}
		if hook != nil {
			f.after = func() { hook("target-" + id) }
		}
		targets[id] = f
	}
	return targets
}

func TestJournalCrashHelper(t *testing.T) {
	if os.Getenv("RAZVILKA_RESTORE_TEST_CHILD") != "1" {
		return
	}
	base, point := os.Getenv("RAZVILKA_RESTORE_TEST_DIR"), os.Getenv("RAZVILKA_RESTORE_TEST_POINT")
	checkpoint := func(name string) {
		if point != name {
			return
		}
		fmt.Println("checkpoint:" + name)
		// Block without timers or polling; the parent kills this real process.
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(91)
	}
	targets := fileTargets(t, base, checkpoint)
	j, err := Open(filepath.Join(base, "journal"), testScope, targets)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	write := j.write
	j.write = func(raw []byte) error {
		if err := write(raw); err != nil {
			return err
		}
		if strings.Contains(string(raw), `"state":"prepared"`) {
			checkpoint("prepared")
		}
		if strings.Contains(string(raw), `"state":"committed"`) {
			checkpoint("committed")
		}
		if strings.Contains(string(raw), `"state":"idle"`) {
			checkpoint("idle")
		}
		return nil
	}
	if os.Getenv("RAZVILKA_RESTORE_TEST_RECOVER") == "1" {
		_, err = j.Recover(context.Background())
	} else {
		_, err = j.Execute(context.Background(), changes())
	}
	t.Fatalf("checkpoint not reached: %v", err)
}

func killAt(t *testing.T, base, point string, recovery bool, whileRunning func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalCrashHelper$")
	command.Env = append(os.Environ(), "RAZVILKA_RESTORE_TEST_CHILD=1", "RAZVILKA_RESTORE_TEST_DIR="+base, "RAZVILKA_RESTORE_TEST_POINT="+point)
	if recovery {
		command.Env = append(command.Env, "RAZVILKA_RESTORE_TEST_RECOVER=1")
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "checkpoint:"+point {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child exited before checkpoint")
		}
	case <-ctx.Done():
		t.Fatal("child checkpoint timed out")
	}
	if whileRunning != nil {
		whileRunning()
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("child was not killed")
	}
}

func crashFixture(t *testing.T) (string, map[string]Target) {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"journal", "targets"} {
		if err := os.Mkdir(filepath.Join(base, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for id, value := range map[string][]byte{"a": []byte("old-a"), "c": {}} {
		if err := os.WriteFile(filepath.Join(base, "targets", id), value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return base, fileTargets(t, base, nil)
}

func TestJournalRealProcessCrash(t *testing.T) {
	for _, point := range []string{"prepared", "target-a", "target-b", "target-c", "committed", "idle"} {
		t.Run(point, func(t *testing.T) {
			base, targets := crashFixture(t)
			path := filepath.Join(base, "journal")
			killAt(t, base, point, false, func() {
				if other, err := Open(path, testScope, targets); !errors.Is(err, ErrBusy) {
					if other != nil {
						_ = other.Close()
					}
					t.Fatal("live writer lease bypassed")
				}
			})
			lockBefore, err := os.Stat(filepath.Join(path, leaseFile))
			if err != nil {
				t.Fatal(err)
			}
			j, err := Open(path, testScope, targets)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			out, err := j.Recover(context.Background())
			expect := RolledBack
			if point == "committed" {
				expect = Applied
			}
			if point == "idle" {
				expect = Clean
			}
			if err != nil || out != expect {
				t.Fatalf("%s %v want %s", out, err, expect)
			}
			for id, target := range targets {
				want := map[string]Image{"a": content("old-a"), "b": {}, "c": content("")}[id]
				if point == "committed" || point == "idle" {
					want = changes()[id]
				}
				got, err := target.Read(context.Background())
				if err != nil || !equal(got, want) {
					t.Fatal("incorrect recovered file state")
				}
			}
			if out, err := j.Recover(context.Background()); out != Clean || err != nil {
				t.Fatal("recovery not idempotent")
			}
			lockAfter, err := os.Stat(filepath.Join(path, leaseFile))
			if err != nil || !os.SameFile(lockBefore, lockAfter) {
				t.Fatal("permanent lease was replaced")
			}
		})
	}
}

func TestJournalRealCrashDuringRecovery(t *testing.T) {
	for _, point := range []string{"target-c", "target-b", "target-a", "idle"} {
		t.Run(point, func(t *testing.T) {
			base, targets := crashFixture(t)
			// All targets written, but no committed decision exists yet.
			killAt(t, base, "target-c", false, nil)
			killAt(t, base, point, true, nil)
			j, err := Open(filepath.Join(base, "journal"), testScope, targets)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			out, err := j.Recover(context.Background())
			expect := RolledBack
			if point == "idle" {
				expect = Clean
			}
			if err != nil || out != expect {
				t.Fatalf("%s %v", out, err)
			}
			for id, want := range map[string]Image{"a": content("old-a"), "b": {}, "c": content("")} {
				got, err := targets[id].Read(context.Background())
				if err != nil || !equal(got, want) {
					t.Fatal("partial recovery was not resumed")
				}
			}
		})
	}
}
