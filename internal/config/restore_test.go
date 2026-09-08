package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestConfigStaleWriterCannotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	first, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	before := second.Get()
	if err := first.UpdateService("youtube", ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func() error{
		func() error { return second.UpdateService("telegram", ServiceState{Route: "usque"}) },
		func() error { return second.SetSafeMode(false) },
		second.ApplyDraft,
		second.DiscardDraft,
		second.Save,
	} {
		if err := mutate(); !errors.Is(err, restorejournal.ErrConflict) {
			t.Fatalf("stale writer not rejected: %v", err)
		}
		if !reflect.DeepEqual(second.Get(), before) {
			t.Fatal("failed stale write changed cache")
		}
	}
	if session, err := second.BeginRestore(context.Background()); !errors.Is(err, restorejournal.ErrConflict) {
		if session != nil {
			session.Close()
		}
		t.Fatal("stale cache entered restore")
	}
	reloaded, err := Load(path)
	if err != nil || !reflect.DeepEqual(first.Get(), reloaded.Get()) {
		t.Fatal("newer state clobbered")
	}
}

func TestConfigRestoreSessionKeepsDiskAndCacheTogether(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{true: "undo", false: "commit"}[rollback], func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "config.json")
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
			beforeCfg := s.Get()
			other, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			session, err := s.BeginRestore(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if again, err := s.BeginRestore(ctx); !errors.Is(err, restorejournal.ErrBusy) {
				if again != nil {
					again.Close()
				}
				t.Fatal("second session admitted")
			}
			if err := other.UpdateService("telegram", ServiceState{Route: "direct"}); !errors.Is(err, restorejournal.ErrBusy) {
				t.Fatal("other Store wrote through lease")
			}
			before, err := session.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			after, err := session.DraftImage(ctx, map[string]ServiceState{"telegram": {Enabled: true, Route: "usque"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := session.CompareAndSwap(ctx, before, after); err != nil {
				t.Fatal(err)
			}
			if rollback {
				if err := session.CompareAndSwap(ctx, after, before); err != nil {
					t.Fatal(err)
				}
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			cfg := s.Get()
			if rollback {
				if !reflect.DeepEqual(cfg, beforeCfg) {
					t.Fatal("rollback cache mismatch")
				}
			} else {
				if !cfg.Services["telegram"].Enabled || cfg.Revision != beforeCfg.Revision+1 {
					t.Fatal("draft not adopted")
				}
				check := cloneConfig(cfg)
				check.Services, check.Revision = beforeCfg.Services, beforeCfg.Revision
				if !reflect.DeepEqual(check, beforeCfg) {
					t.Fatal("draft builder changed applied routes or gate")
				}
			}
			disk, err := Load(path)
			if err != nil || !reflect.DeepEqual(cfg, disk.Get()) {
				t.Fatal("cache/disk mismatch")
			}
			if err := s.UpdateService("telegram", ServiceState{Route: "direct"}); err != nil {
				t.Fatal("session did not release writer")
			}
		})
	}
}

func TestConfigRealTargetWithJournal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	after, err := session.DraftImage(ctx, map[string]ServiceState{"telegram": {Enabled: true, Route: "usque"}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	j, err := restorejournal.Open(root, session.Binding(), map[string]restorejournal.Target{"config": session})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if out, err := j.Execute(ctx, map[string]restorejournal.Image{"config": after}); out != restorejournal.Applied || err != nil {
		t.Fatalf("%s %v", out, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if !s.Get().Services["telegram"].Enabled {
		t.Fatal("journal commit not reflected in Store")
	}
}

func TestConfigTargetRejectsInvalidOrMissingImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	target, err := OpenRestoreTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	before, _ := target.Read(context.Background())
	for _, after := range []restorejournal.Image{{}, {Exists: true, Data: []byte(`{"schema_version":999}`)}, {Exists: true, Data: []byte(`not-json`)}} {
		if err := target.CompareAndSwap(context.Background(), before, after); !errors.Is(err, restorejournal.ErrInvalid) {
			t.Fatal("invalid restore accepted")
		}
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, before.Data) || s.Get().Revision != 0 {
		t.Fatal("invalid restore changed state")
	}
}

type failingPersist struct {
	image   restorejournal.Image
	replace bool
}

func (f *failingPersist) Read(context.Context) (restorejournal.Image, error) { return f.image, nil }
func (f *failingPersist) CompareAndSwap(_ context.Context, _, after restorejournal.Image) error {
	if f.replace {
		f.image = after
	}
	return restorejournal.ErrRecovery
}

func TestConfigAmbiguousWriteBlocksFurtherWrites(t *testing.T) {
	for _, replace := range []bool{false, true} {
		s, err := Load(filepath.Join(t.TempDir(), "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		f := &failingPersist{image: s.diskImage, replace: replace}
		next := s.Get()
		next.Revision++
		data, _ := json.MarshalIndent(next, "", "  ")
		err = s.persistLocked(f, data)
		if replace {
			if !errors.Is(err, restorejournal.ErrRecovery) || !s.writeUncertain {
				t.Fatal("ambiguous commit not fenced")
			}
			if err := s.Save(); !errors.Is(err, restorejournal.ErrRecovery) {
				t.Fatal("uncertain cache wrote again")
			}
			if session, err := s.BeginRestore(context.Background()); !errors.Is(err, restorejournal.ErrRecovery) {
				if session != nil {
					session.Close()
				}
				t.Fatal("uncertain cache restored blindly")
			}
		} else if !errors.Is(err, restorejournal.ErrAborted) || s.writeUncertain {
			t.Fatal("proven unchanged write reported ambiguous")
		}
	}
}
