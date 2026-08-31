//go:build linux || windows

package cloudflareprovider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestProviderJournalChild(t *testing.T) {
	if os.Getenv("RAZVILKA_CF_JOURNAL_CHILD") != "1" {
		return
	}
	base, point := os.Getenv("RAZVILKA_CF_JOURNAL_BASE"), os.Getenv("RAZVILKA_CF_JOURNAL_POINT")
	pause := func(name string) {
		if point != name {
			return
		}
		fmt.Println("checkpoint:" + name)
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(91)
	}
	target, err := OpenRestoreTarget(filepath.Join(base, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	after, _, err := target.MergeImage(context.Background(), []privatebackup.ProviderSnapshot{restoreSnapshot(2)})
	if err != nil {
		t.Fatal(err)
	}
	realWrite, count := target.write, 0
	target.write = func(image restorejournal.Image) error {
		count++
		pause("prepared")
		if err := realWrite(image); err != nil {
			return err
		}
		if count == 1 {
			pause("replaced")
			if point == "rollback" {
				return errors.New("synthetic post-rename failure")
			}
		} else {
			pause("rollback")
		}
		return nil
	}
	j, err := restorejournal.Open(filepath.Join(base, "journal"), target.Binding(), map[string]restorejournal.Target{"cloudflare": target})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	out, err := j.Execute(context.Background(), map[string]restorejournal.Image{"cloudflare": after})
	if err == nil && out == restorejournal.Applied {
		pause("complete")
	}
	t.Fatalf("missed checkpoint: %s %v", out, err)
}

func killProviderChild(t *testing.T, base, point string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProviderJournalChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_CF_JOURNAL_CHILD=1", "RAZVILKA_CF_JOURNAL_BASE="+base, "RAZVILKA_CF_JOURNAL_POINT="+point)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "checkpoint:"+point {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		waited = true
		t.Fatalf("child checkpoint not reached: %s", stderr.String())
	}
	s, err := OpenStore(filepath.Join(base, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	parsed, _ := ParseImport(SourceUSQUE, usqueFixture())
	if _, err := s.ImportSnapshot(ctx, parsed); !errors.Is(err, ErrBusy) {
		t.Fatalf("cross-process writer not locked: %v", err)
	}
	if _, err := s.BeginRestore(ctx); !errors.Is(err, ErrBusy) {
		t.Fatalf("cross-process recovery not locked: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child not killed")
	}
	waited = true
}

func TestProviderJournalProcessCrashRecovery(t *testing.T) {
	for _, exists := range []bool{false, true} {
		for _, point := range []string{"prepared", "replaced", "rollback", "complete", "external-edit"} {
			t.Run(fmt.Sprintf("exists-%v/%s", exists, point), func(t *testing.T) {
				base := t.TempDir()
				path := filepath.Join(base, "provider")
				for _, dir := range []string{path, filepath.Join(base, "journal")} {
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				before := restorejournal.Image{}
				if exists {
					doc, _ := snapshotsDocument([]privatebackup.ProviderSnapshot{restoreSnapshot(1)})
					data, _ := json.MarshalIndent(doc, "", "  ")
					data = append(data, '\n')
					if err := os.WriteFile(filepath.Join(path, storeFile), data, 0o600); err != nil {
						t.Fatal(err)
					}
					before = restorejournal.Image{Exists: true, Data: data}
				}
				target, err := OpenRestoreTarget(path)
				if err != nil {
					t.Fatal(err)
				}
				after, _, err := target.MergeImage(context.Background(), []privatebackup.ProviderSnapshot{restoreSnapshot(2)})
				if err != nil {
					t.Fatal(err)
				}
				target.Close()
				lockBefore, _ := os.Stat(filepath.Join(path, writerLockFile))
				phase := point
				if phase == "external-edit" {
					phase = "replaced"
				}
				killProviderChild(t, base, phase)
				want := before
				if point == "complete" {
					want = after
				}
				if point == "external-edit" {
					doc, _ := snapshotsDocument([]privatebackup.ProviderSnapshot{restoreSnapshot(3)})
					data, _ := json.Marshal(doc)
					if err := os.WriteFile(filepath.Join(path, storeFile), data, 0o600); err != nil {
						t.Fatal(err)
					}
					want = restorejournal.Image{Exists: true, Data: data}
				}
				// Recovery opens the typed target BEFORE any ordinary provider Store.
				recovered, err := OpenRestoreTarget(path)
				if err != nil {
					t.Fatal(err)
				}
				defer recovered.Close()
				j, err := restorejournal.Open(filepath.Join(base, "journal"), recovered.Binding(), map[string]restorejournal.Target{"cloudflare": recovered})
				if err != nil {
					t.Fatal(err)
				}
				defer j.Close()
				out, err := j.Recover(context.Background())
				wantOutcome := restorejournal.RolledBack
				if point == "complete" {
					wantOutcome = restorejournal.Clean
				}
				if point == "external-edit" {
					wantOutcome = restorejournal.Blocked
				}
				if out != wantOutcome || (point != "external-edit" && err != nil) || (point == "external-edit" && err == nil) {
					t.Fatalf("recovery: %s %v", out, err)
				}
				actual, err := recovered.Read(context.Background())
				if err != nil || !sameSnapshotImage(actual, want) {
					t.Fatal("byte-exact recovery failed", err)
				}
				j.Close()
				recovered.Close()
				lockAfter, _ := os.Stat(filepath.Join(path, writerLockFile))
				if !os.SameFile(lockBefore, lockAfter) {
					t.Fatal("OS marker replaced")
				}
				if point != "external-edit" {
					s, err := OpenStore(path)
					if err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					parsed, _ := ParseImport(SourceUSQUE, usqueFixture())
					if _, err := s.ImportSnapshot(context.Background(), parsed); err != nil {
						t.Fatal("writer did not resume", err)
					}
				}
			})
		}
	}
}
