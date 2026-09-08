package engineconfig

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestRestoreLeaseCoversEveryStageWriter(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	m := New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	if _, err := m.Stage("sing-box", "main", `{"log":{"level":"warn"}}`); err != nil {
		t.Fatal(err)
	}
	other := New(m.StageRoot, m.BackupRoot)
	s, err := m.BeginRestore(ctx, []DraftRef{{"sing-box", "main"}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if second, err := m.BeginRestore(ctx, []DraftRef{{"sing-box", "main"}}); !errors.Is(err, restorejournal.ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal("second session accepted")
	}
	for name, write := range map[string]func() error{
		"expert": func() error { _, err := other.Stage("sing-box", "main", "{}"); return err },
		"guided": func() error {
			_, err := other.StageGuided("sing-box", "main", map[string]string{"log.level": "debug"})
			return err
		},
		"private": func() error {
			_, err := other.StagePrivate([]StageItem{{EngineID: "sing-box", FileID: "main", Content: "{}"}})
			return err
		},
		"discard": func() error { return other.Discard("sing-box", "main") },
		"apply":   func() error { _, err := other.Apply("sing-box", "main", false); return err },
	} {
		if err := write(); !errors.Is(err, restorejournal.ErrBusy) {
			t.Fatalf("%s did not respect lease: %v", name, err)
		}
	}
	// An unrelated public slot remains usable by another Manager.
	if _, err := other.StagePublic([]StageItem{{EngineID: "nfqws2", FileID: "user-list", Content: "public.example"}}); err != nil {
		t.Fatal(err)
	}
	targets := s.Targets()
	before, err := targets["sing-box_main"].Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	images, err := s.Images([]StageItem{{EngineID: "sing-box", FileID: "main", Content: `{"log":{"level":"info"}}`}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := targets["sing-box_main"].Read(ctx)
	if err != nil || !sameImage(before, after) {
		t.Fatal("image builder wrote")
	}
	if err := targets["sing-box_main"].CompareAndSwap(ctx, before, images["sing-box_main"]); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := targets["sing-box_main"].Read(ctx); !errors.Is(err, restorejournal.ErrUnavailable) {
		t.Fatal("closed target readable")
	}
	if _, err := other.StageGuided("sing-box", "main", map[string]string{"log.level": "error"}); err != nil {
		t.Fatal("guided writer did not resume")
	}
	got, err := other.ReadExpert("sing-box", "main")
	if err != nil || !strings.Contains(got.Content, "error") {
		t.Fatal("guided change missing")
	}
}

func TestPrivateStageUndoPreservesDraftsAndRefusesExternalChanges(t *testing.T) {
	for _, mode := range []string{"undo", "external", "rebound"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			m := New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
			// Incomplete JSON is a legitimate editor BEFORE image; do not validate it
			// as an imported profile when rolling it back.
			if _, err := m.Stage("sing-box", "main", "{unfinished"); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(m.stagePath("sing-box", "main"))
			if err != nil {
				t.Fatal(err)
			}
			out, undo, err := m.StagePrivateWithRollback([]StageItem{{EngineID: "sing-box", FileID: "main", Content: `{"private_key":"synthetic"}`}, {EngineID: "nfqws2", FileID: "user-list", Content: "new.example\n"}})
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 2 || !out[0].Sensitive || out[0].Content != "" || out[1].Content == "" {
				t.Fatal("secret stage result leaked or public content hidden")
			}
			if _, err := m.Stage("nfqws2", "exclude-list", "unrelated.example"); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "external":
				other := New(m.StageRoot, m.BackupRoot)
				if _, err := other.Stage("sing-box", "main", `{"outside":true}`); err != nil {
					t.Fatal(err)
				}
				if err := undo(); !errors.Is(err, ErrStageRollback) {
					t.Fatal("undo accepted a newer edit")
				}
				if got, _ := m.Read("nfqws2", "user-list"); got.Content != "new.example\n" {
					t.Fatal("partial undo before conflict check")
				}
				return
			case "rebound":
				original := m.StageRoot
				m.StageRoot = filepath.Join(root, "other-stage")
				if err := undo(); !errors.Is(err, ErrStageRollback) {
					t.Fatal("undo followed changed binding")
				}
				m.StageRoot = original
			}
			if err := undo(); err != nil {
				t.Fatal(err)
			}
			if err := undo(); err != nil {
				t.Fatal("undo is not idempotent")
			}
			raw, _ := os.ReadFile(m.stagePath("sing-box", "main"))
			if !bytes.Equal(raw, before) {
				t.Fatal("incomplete before image not restored")
			}
			if _, err := os.Stat(m.stagePath("nfqws2", "user-list")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("new draft remains")
			}
			if got, _ := m.Read("nfqws2", "exclude-list"); got.Content != "unrelated.example" {
				t.Fatal("unrelated draft lost")
			}
		})
	}
}

func TestDraftTargetsValidateSlotsNotUndoSyntax(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	m := New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	for _, ref := range []DraftRef{{"../escape", "main"}, {"sing-box", "../main"}, {"unknown", "main"}} {
		if target, err := OpenRestoreTarget(m.StageRoot, ref.EngineID, ref.FileID); !errors.Is(err, restorejournal.ErrInvalid) {
			if target != nil {
				target.Close()
			}
			t.Fatal("unknown target accepted")
		}
	}
	if _, err := os.Stat(m.StageRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid slot created directories")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if s, err := m.BeginRestore(cancelled, []DraftRef{{"sing-box", "main"}}); !errors.Is(err, restorejournal.ErrAborted) {
		if s != nil {
			s.Close()
		}
		t.Fatal("cancelled session accepted")
	}
	if s, err := m.BeginRestore(ctx, []DraftRef{{"sing-box", "main"}, {"sing-box", "main"}}); !errors.Is(err, restorejournal.ErrInvalid) {
		if s != nil {
			s.Close()
		}
		t.Fatal("duplicate target accepted")
	}
	target, err := OpenRestoreTarget(m.StageRoot, "sing-box", "main")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	before, err := target.Read(ctx)
	if err != nil || before.Exists {
		t.Fatal("missing draft misread")
	}
	if _, err := target.Image("{unfinished"); !errors.Is(err, restorejournal.ErrInvalid) {
		t.Fatal("invalid imported JSON accepted")
	}
	empty := restorejournal.Image{Exists: true}
	if err := target.CompareAndSwap(ctx, before, empty); err != nil {
		t.Fatal(err)
	}
	got, err := target.Read(ctx)
	if err != nil || !got.Exists || len(got.Data) != 0 {
		t.Fatal("empty draft confused with absent")
	}
	for _, bad := range []restorejournal.Image{{Data: []byte("not absent")}, {Exists: true, Data: make([]byte, maxConfigBytes+1)}} {
		if err := target.CompareAndSwap(ctx, empty, bad); !errors.Is(err, restorejournal.ErrInvalid) {
			t.Fatal("invalid image accepted")
		}
	}
	if err := target.CompareAndSwap(ctx, empty, before); err != nil {
		t.Fatal(err)
	}
}

func TestDraftSessionPreparationReleasesEarlierLeases(t *testing.T) {
	root := t.TempDir()
	m := New(filepath.Join(root, "stage"), filepath.Join(root, "backup"))
	busy, err := OpenRestoreTarget(m.StageRoot, "sing-box", "main")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if s, err := m.BeginRestore(context.Background(), []DraftRef{{"nfqws2", "main"}, {"sing-box", "main"}}); !errors.Is(err, restorejournal.ErrBusy) {
		if s != nil {
			s.Close()
		}
		t.Fatal("busy target accepted")
	}
	if _, err := m.Stage("nfqws2", "main", "NFQWS_ARGS=\"--foo\""); err != nil {
		t.Fatal("failed preparation leaked earlier lease/mutex")
	}
}
