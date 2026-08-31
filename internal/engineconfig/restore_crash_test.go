package engineconfig

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var crashRefs = []DraftRef{{"nfqws2", "user-list"}, {"sing-box", "main"}, {"usque", "main"}}
var crashItems = []StageItem{
	{EngineID: "nfqws2", FileID: "user-list", Content: "new.example\n"},
	{EngineID: "sing-box", FileID: "main", Content: `{"synthetic_secret":"new proxy"}`},
	{EngineID: "usque", FileID: "main", Content: `{"synthetic_secret":"new session"}`},
}

func TestDraftRecoveryChild(t *testing.T) {
	if os.Getenv("RAZVILKA_DRAFT_CHILD") != "1" {
		return
	}
	base, point := os.Getenv("RAZVILKA_DRAFT_BASE"), os.Getenv("RAZVILKA_DRAFT_POINT")
	pause := func(name string) {
		if name != point {
			return
		}
		fmt.Println("checkpoint:" + name)
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		os.Exit(91)
	}
	m := New(filepath.Join(base, "stage"), filepath.Join(base, "backup"))
	s, err := m.BeginRestore(context.Background(), crashRefs)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	targets := s.Targets()
	images, err := s.Images(crashItems)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for id, target := range targets {
		targets[id] = injectedTarget{Target: target, write: func(inner restorejournal.Target, ctx context.Context, before, after restorejournal.Image) error {
			pause("prepared")
			counts[id]++
			if point == "rollback" && id == "usque_main" {
				return errors.New("synthetic failure")
			}
			if err := inner.CompareAndSwap(ctx, before, after); err != nil {
				return err
			}
			if counts[id] == 1 {
				pause(id)
			} else if id == "sing-box_main" {
				pause("rollback")
			}
			return nil
		}}
	}
	j, err := restorejournal.Open(filepath.Join(base, "journal"), s.Binding(), targets)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	out, err := j.Execute(context.Background(), images)
	if err == nil && out == restorejournal.Applied {
		pause("complete")
	}
	t.Fatalf("checkpoint missed: %s %v", out, err)
}
func killDraftChild(t *testing.T, base, point string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDraftRecoveryChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_DRAFT_CHILD=1", "RAZVILKA_DRAFT_BASE="+base, "RAZVILKA_DRAFT_POINT="+point)
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
			t.Fatal("child stopped before checkpoint")
		}
	case <-ctx.Done():
		t.Fatal("checkpoint timed out")
	}
	m := New(filepath.Join(base, "stage"), filepath.Join(base, "backup"))
	if _, err := m.Stage("nfqws2", "user-list", "other.example"); !errors.Is(err, restorejournal.ErrBusy) {
		t.Fatal("cross-process expert write passed")
	}
	if _, err := m.StageGuided("sing-box", "main", map[string]string{"log.level": "warn"}); !errors.Is(err, restorejournal.ErrBusy) {
		t.Fatal("cross-process guided write passed")
	}
	if err := m.Discard("usque", "main"); !errors.Is(err, restorejournal.ErrBusy) {
		t.Fatal("cross-process discard passed")
	}
	if _, err := m.Stage("nfqws2", "exclude-list", "unrelated.example"); err != nil {
		t.Fatal("unrelated slot locked")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("child not killed")
	}
}
func TestDraftRecoveryRestoresAbsentEmptyAndIncompleteFiles(t *testing.T) {
	for _, point := range []string{"prepared", "nfqws2_user-list", "sing-box_main", "usque_main", "rollback", "complete"} {
		t.Run(point, func(t *testing.T) {
			base := t.TempDir()
			m := New(filepath.Join(base, "stage"), filepath.Join(base, "backup"))
			if _, err := m.Stage("sing-box", "main", "{unfinished"); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Stage("usque", "main", ""); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(base, "journal"), 0o700); err != nil {
				t.Fatal(err)
			}
			before := map[string]restorejournal.Image{}
			for _, ref := range crashRefs {
				image, err := m.readStageImage(context.Background(), ref.EngineID, ref.FileID)
				if err != nil {
					t.Fatal(err)
				}
				before[draftID(ref)] = image
			}
			killDraftChild(t, base, point)
			// No live config, native validator, runtime or App startup is involved.
			fresh := New(m.StageRoot, m.BackupRoot)
			s, err := fresh.BeginRestore(context.Background(), crashRefs)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			expected, err := s.Images(crashItems)
			if err != nil {
				t.Fatal(err)
			}
			j, err := restorejournal.Open(filepath.Join(base, "journal"), s.Binding(), s.Targets())
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			out, err := j.Recover(context.Background())
			want := restorejournal.RolledBack
			if point == "complete" {
				want = restorejournal.Clean
			}
			if out != want || err != nil {
				t.Fatalf("%s %v", out, err)
			}
			for _, ref := range crashRefs {
				got, err := s.Targets()[draftID(ref)].Read(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				want := before[draftID(ref)]
				if point == "complete" {
					want = expected[draftID(ref)]
				}
				if got.Exists != want.Exists || !bytes.Equal(got.Data, want.Data) {
					t.Fatal("draft not restored byte-exactly")
				}
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := fresh.Read("nfqws2", "exclude-list")
			if err != nil || got.Content != "unrelated.example" {
				t.Fatal("unrelated draft touched")
			}
			if _, err := fresh.Stage("usque", "main", "{}"); err != nil {
				t.Fatal("writer unavailable after recovery")
			}
			if _, err := os.Stat(m.BackupRoot); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("draft recovery touched live backup directory")
			}
		})
	}
}
