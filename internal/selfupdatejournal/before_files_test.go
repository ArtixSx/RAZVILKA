package selfupdatejournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStopBeforeFilesIsJournaledAndNeverReplayed(t *testing.T) {
	f := fixtureAt(t, t.TempDir())
	f.prepare(t)
	called := 0
	if err := f.store.Execute(context.Background(), transaction, "start-candidate-panel", okay, okay); !errors.Is(err, ErrPending) {
		t.Fatal("start accepted before install", err)
	}
	if err := f.store.Execute(context.Background(), transaction, "stop-old-panel", okay, func(context.Context) error { called++; return interrupted }); err != interrupted {
		t.Fatal(err)
	}
	f.reopen(t)
	r, present, err := f.store.Current()
	if err != nil || !present || !r.BeforeFiles || r.Index != 0 || r.Phase != "command-started" {
		t.Fatalf("before-file intent %+v %v", r, err)
	}
	if err := f.store.Install(context.Background(), transaction, okay, okay); !errors.Is(err, ErrUnknown) {
		t.Fatal("unknown stop authorized file replacement", err)
	}
	if err := f.store.Execute(context.Background(), transaction, "stop-old-panel", okay, func(context.Context) error { called++; return nil }); !errors.Is(err, ErrUnknown) || called != 1 {
		t.Fatal("stop replayed", err)
	}
	if err := f.store.ResolveUnknown(context.Background(), transaction, okay, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Execute(context.Background(), transaction, "stop-old-panel", okay, okay); !errors.Is(err, ErrPending) {
		t.Fatal("resolved stop replayed", err)
	}
	if data, _ := os.ReadFile(filepath.Join(f.installation, "bin", "razvilka")); string(data) != "old binary" {
		t.Fatal("file changed before stop proof")
	}
	if err := f.store.Install(context.Background(), transaction, okay, okay); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Execute(context.Background(), transaction, "start-candidate-panel", okay, okay); err != nil {
		t.Fatal(err)
	}
}
