package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
)

func TestComponentReadMetadataIsExactStandaloneAndKeepsLegacyWriter(t *testing.T) {
	if components.ComponentUpdateSchema != 2 || app.ManagedComponentReadVersion != 3 {
		t.Fatal("legacy package writer changed or actual reader unavailable")
	}
	state := filepath.Join(t.TempDir(), "never-initialize")
	if handled, code := runComponentReadCommand([]string{"-component-update-schema"}, state); !handled || code != 0 {
		t.Fatal("compiled metadata required startup or history", handled, code)
	}
	for _, args := range [][]string{{"--component-update-schema"}, {"-component-update-schema=true"}, {"-component-update-schema", "-config=/other"}, {"-component-update-schema", "-self-update-read-version"}, {"-check-component-update-state", "-component-state=/other"}} {
		if handled, code := runComponentReadCommand(args, state); !handled || code != 2 {
			t.Fatal("noncanonical reader invocation admitted", args, handled, code)
		}
	}
	if handled, _ := runComponentReadCommand([]string{"-check-config"}, state); handled {
		t.Fatal("unrelated command intercepted")
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("metadata initialized state", err)
	}
}

func TestComponentReadStateMissingIsReadOnlyAndMalformedFailsBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state := filepath.Join(t.TempDir(), "missing")
	if err := checkComponentReadState(ctx, state, app.ManagedComponentReadVersion); err != nil {
		t.Fatal("empty installed history unreadable", err)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("readonly check created a directory", err)
	}
	if err := checkComponentReadState(ctx, state, 1); err == nil {
		t.Fatal("reader1 admitted package writer2 floor")
	}
	if err := os.MkdirAll(filepath.Join(state, "update-journal"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "update-journal", "current.json")
	data := []byte(`{"schema_version":999,"component":"nfqws2"}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if handled, code := runComponentReadCommand([]string{"-check-component-update-state"}, state); !handled || code != 3 {
		t.Fatal("future/partial state allowed startup", handled, code)
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != string(data) {
		t.Fatal("reader repaired retained state", err)
	}
}
