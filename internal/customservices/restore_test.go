package customservices

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestRegistryCloseRefusesCorruptCacheAndCancelledSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	m := loadRegistry(t, path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := m.BeginRestore(ctx); !errors.Is(err, restorejournal.ErrAborted) {
		if s != nil {
			s.Close()
		}
		t.Fatal("cancelled session accepted")
	}
	s, err := m.BeginRestore(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Noncooperating external writer. Close must fence the old cache on a
	// failed reload, not allow it to overwrite the unknown file afterwards.
	if err := os.WriteFile(path, []byte("corrupt-external-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); !errors.Is(err, restorejournal.ErrRecovery) {
		t.Fatal("bad reload accepted")
	}
	if !m.writeUncertain {
		t.Fatal("cache not fenced")
	}
	if err := m.ReplaceAll(nil, nil); !errors.Is(err, restorejournal.ErrRecovery) {
		t.Fatal("uncertain cache wrote")
	}

	data, _ := os.ReadFile(path)
	if string(data) != "corrupt-external-file" {
		t.Fatal("unknown file overwritten")
	}
}

func fixtureService(id string) catalog.Service {
	return catalog.Service{ID: id, Name: id, Category: "Test", Domains: []string{"test.example"}, Strategy: []string{"auto"}}
}
func loadRegistry(t *testing.T, path string) *Manager {
	t.Helper()
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCatalogStaleWritersAndUndo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.json")
	first := loadRegistry(t, path)
	if _, err := first.Create(fixtureService("custom-before"), nil); err != nil {
		t.Fatal(err)
	}
	stale := loadRegistry(t, path)
	old := stale.List()
	if _, err := first.Create(fixtureService("custom-later"), nil); err != nil {
		t.Fatal(err)
	}
	writes := []func() error{
		func() error { _, err := stale.Create(fixtureService("custom-new"), nil); return err },
		func() error { _, err := stale.Update("custom-before", fixtureService("custom-before")); return err },
		func() error { return stale.Delete("custom-before") },
		func() error {
			_, err := stale.Merge([]catalog.Service{fixtureService("custom-import")}, nil, true)
			return err
		},
		func() error { return stale.ReplaceAll(nil, nil) },
	}
	for _, write := range writes {
		if err := write(); !errors.Is(err, restorejournal.ErrConflict) {
			t.Fatalf("stale write: %v", err)
		}
		if !reflect.DeepEqual(old, stale.List()) {
			t.Fatal("failed write changed cache")
		}
	}
	if session, err := stale.BeginRestore(context.Background()); !errors.Is(err, restorejournal.ErrConflict) {
		if session != nil {
			session.Close()
		}
		t.Fatal("stale restore accepted")
	}
	undo, err := first.MergeWithRollback([]catalog.Service{fixtureService("custom-import")}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	other := loadRegistry(t, path)
	if _, err := other.Create(fixtureService("custom-third"), nil); err != nil {
		t.Fatal(err)
	}
	if err := undo(); !errors.Is(err, restorejournal.ErrConflict) {
		t.Fatal("undo overwrote external edit")
	}
	if !loadRegistry(t, path).Has("custom-third") {
		t.Fatal("external edit lost")
	}
}

func TestCatalogRestoreSession(t *testing.T) {
	ctx := context.Background()
	for _, rollback := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "custom.json")
		m := loadRegistry(t, path)
		if _, err := m.Create(fixtureService("custom-before"), nil); err != nil {
			t.Fatal(err)
		}
		other := loadRegistry(t, path)
		old := m.List()
		session, err := m.BeginRestore(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if second, err := m.BeginRestore(ctx); !errors.Is(err, restorejournal.ErrBusy) {
			if second != nil {
				second.Close()
			}
			t.Fatal("second session accepted")
		}
		if _, err := other.Create(fixtureService("custom-third"), nil); !errors.Is(err, restorejournal.ErrBusy) {
			t.Fatal("write through lease")
		}
		before, err := session.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.MergeImage(ctx, []catalog.Service{fixtureService("custom-bad")}, map[string]bool{"custom-bad": true}, true); !errors.Is(err, restorejournal.ErrInvalid) {
			t.Fatal("reserved ID accepted")
		}
		after, err := session.MergeImage(ctx, []catalog.Service{fixtureService("custom-import")}, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		if !bytes.Equal(raw, before.Data) {
			t.Fatal("builder wrote file")
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
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := session.Read(ctx); !errors.Is(err, restorejournal.ErrUnavailable) {
			t.Fatal("closed session read")
		}
		if rollback {
			if !reflect.DeepEqual(old, m.List()) {
				t.Fatal("rollback cache not restored")
			}
		} else if !m.Has("custom-import") || !m.Has("custom-before") {
			t.Fatal("merge cache lost")
		}
		if !reflect.DeepEqual(m.List(), loadRegistry(t, path).List()) {
			t.Fatal("cache differs from disk")
		}
		if _, err := m.Create(fixtureService("custom-next"), nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCatalogTargetValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.json")
	_ = loadRegistry(t, path)
	target, err := OpenRestoreTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ctx := context.Background()
	before, _ := target.Read(ctx)
	for _, data := range []string{"", "null", "{", `{"schema":99}`, `{"schema":1,"services":[{"id":"bad"}]}`, strings.Repeat(" ", restorejournal.MaxImageBytes+1)} {
		if err := target.CompareAndSwap(ctx, before, restorejournal.Image{Exists: true, Data: []byte(data)}); !errors.Is(err, restorejournal.ErrInvalid) {
			t.Fatal("invalid image accepted")
		}
	}
	if err := target.CompareAndSwap(ctx, before, restorejournal.Image{}); !errors.Is(err, restorejournal.ErrInvalid) {
		t.Fatal("deletion accepted")
	}
	after, _ := target.Read(ctx)
	if !bytes.Equal(before.Data, after.Data) {
		t.Fatal("invalid image wrote")
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
func TestCatalogAmbiguousWriteFencesCache(t *testing.T) {
	for _, replace := range []bool{false, true} {
		m := loadRegistry(t, filepath.Join(t.TempDir(), "custom.json"))
		before := append([]byte(nil), m.diskImage.Data...)
		f := &failingPersist{image: m.diskImage, replace: replace}
		err := m.persistLocked(f, append(append([]byte(nil), before...), '\n'))
		if replace {
			if !errors.Is(err, restorejournal.ErrRecovery) || !m.writeUncertain {
				t.Fatal("ambiguous result accepted")
			}
			if _, err := m.Create(fixtureService("custom-next"), nil); !errors.Is(err, restorejournal.ErrRecovery) {
				t.Fatal("uncertain cache wrote")
			}
			if s, err := m.BeginRestore(context.Background()); !errors.Is(err, restorejournal.ErrRecovery) {
				if s != nil {
					s.Close()
				}
				t.Fatal("uncertain restore")
			}
		} else if !errors.Is(err, restorejournal.ErrAborted) || m.writeUncertain {
			t.Fatal("unchanged write misclassified")
		}
		if !bytes.Equal(before, m.diskImage.Data) {
			t.Fatal("expected snapshot mutated")
		}
	}
}
