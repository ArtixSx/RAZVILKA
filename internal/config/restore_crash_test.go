package config

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type checkpointTarget struct {
	restorejournal.Target
	before func()
	after  func()
	fail   bool
}

func (t checkpointTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if t.before != nil {
		t.before()
	}
	if t.fail {
		return errors.New("synthetic target failure")
	}
	if err := t.Target.CompareAndSwap(ctx, before, after); err != nil {
		return err
	}
	if t.after != nil {
		t.after()
	}
	return nil
}

func configJournalScope(configBinding, auxBinding string) string {
	hash := sha256.Sum256([]byte("config-recovery-test-v1\x00" + configBinding + "\x00" + auxBinding))
	return hex.EncodeToString(hash[:])
}

func TestConfigRecoveryChild(t *testing.T) {
	if os.Getenv("RAZVILKA_CONFIG_CHILD") != "1" {
		return
	}
	base, point := os.Getenv("RAZVILKA_CONFIG_BASE"), os.Getenv("RAZVILKA_CONFIG_POINT")
	pause := func(name string) {
		if point != name {
			return
		}
		fmt.Println("checkpoint:" + name)
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(91)
	}
	s, err := Load(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	after, err := session.DraftImage(context.Background(), map[string]ServiceState{"telegram": {Enabled: true, Route: "usque"}})
	if err != nil {
		t.Fatal(err)
	}
	aux, err := restorejournal.OpenFileTarget(filepath.Join(base, "aux-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer aux.Close()
	writes := 0
	configTarget := checkpointTarget{Target: session, before: func() { pause("prepared") }, after: func() {
		writes++
		if writes == 1 {
			pause("written")
		} else {
			pause("rollback")
		}
	}}
	auxTarget := checkpointTarget{Target: aux, fail: point == "rollback"}
	j, err := restorejournal.Open(filepath.Join(base, "journal"), configJournalScope(session.Binding(), aux.Binding()), map[string]restorejournal.Target{"a_config": configTarget, "z_aux": auxTarget})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	out, err := j.Execute(context.Background(), map[string]restorejournal.Image{"a_config": after, "z_aux": {Exists: true, Data: []byte("new auxiliary value")}})
	if err == nil && out == restorejournal.Applied {
		pause("complete")
	}
	t.Fatalf("checkpoint missed: %s %v", out, err)
}

func killConfigChild(t *testing.T, base, point string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConfigRecoveryChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_CONFIG_CHILD=1", "RAZVILKA_CONFIG_BASE="+base, "RAZVILKA_CONFIG_POINT="+point)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
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
	// A fresh Store can read the atomic file, but cannot write while the other
	// process owns the restore lease, even when its read reflects partial state.
	other, err := Load(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := other.SetSafeMode(false); !errors.Is(err, restorejournal.ErrBusy) {
		t.Fatal("other process wrote through restore lease")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child not killed")
	}
}

func TestConfigRecoveryBeforeCacheLoad(t *testing.T) {
	for _, point := range []string{"prepared", "written", "rollback", "complete"} {
		t.Run(point, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, "config.json")
			s, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.UpdateService("youtube", ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
				t.Fatal(err)
			}
			if err := s.ApplyDraft(); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			if err := os.Mkdir(filepath.Join(base, "journal"), 0o700); err != nil {
				t.Fatal(err)
			}
			killConfigChild(t, base, point)
			// This is the exact bootstrap ordering intended for integration:
			// typed file targets -> recovery -> close targets -> config.Load.
			target, err := OpenRestoreTarget(path)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			aux, err := restorejournal.OpenFileTarget(filepath.Join(base, "aux-state.json"))
			if err != nil {
				t.Fatal(err)
			}
			defer aux.Close()
			j, err := restorejournal.Open(filepath.Join(base, "journal"), configJournalScope(target.Binding(), aux.Binding()), map[string]restorejournal.Target{"a_config": target, "z_aux": aux})
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			out, err := j.Recover(context.Background())
			expect := restorejournal.RolledBack
			if point == "complete" {
				expect = restorejournal.Clean
			}
			if out != expect || err != nil {
				t.Fatalf("%s %v", out, err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			if err := aux.Close(); err != nil {
				t.Fatal(err)
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(path)
			if point != "complete" && !bytes.Equal(before, after) {
				t.Fatal("original config bytes not restored")
			}
			loaded, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Get().Services["telegram"].Enabled != (point == "complete") {
				t.Fatal("stale state loaded after recovery")
			}
			if !loaded.Get().AppliedServices["youtube"].Enabled || !loaded.Get().SafeMode {
				t.Fatal("live/gate fields changed")
			}
			if err := loaded.UpdateService("telegram", ServiceState{Route: "direct"}); err != nil {
				t.Fatal("writes not available after recovery")
			}
		})
	}
}
