package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
)

func TestComponentReadMetadataIsExactStandaloneAndKeepsLegacyWriter(t *testing.T) {
	if components.ComponentUpdateSchema != 2 || components.ManagedNFQWSJournalSchema != 3 || app.ManagedComponentReadVersion != 4 {
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

func TestComponentReadSchemaFourInitialIntentRejectsOlderRetainedReaders(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "update-journal")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// Format interoperability fixture only. It grants no installation or
	// recovery authority; the producer must still prove every real effect.
	data := `{"schema_version":4,"transaction_id":"` + strings.Repeat("f", 32) + `","component":"nfqws2","phase":"initial-install-prepared","before_version":"absent","after_version":"1.3.1","updated_at":"2026-10-22T00:00:00Z","nfqws_initial_install":{"source_sha256":"28af67f8e192c838e007f23517b52b1f8c20d030cef5b971dfc93b7f21a79054","source_size":2382102,"derived_sha256":"` + strings.Repeat("a", 64) + `","derived_size":100,"init_sha256":"` + strings.Repeat("b", 64) + `","owner":"` + strings.Repeat("c", 24) + `","architecture":"arm64","status_sha256":"` + strings.Repeat("d", 64) + `","installation_id":"` + strings.Repeat("e", 32) + `","sequence":1,"revision":0,"derivation":"inert-s51-and-root-owner-v1"},"package":"nfqws2-keenetic","package_file":"nfqws2-keenetic_1.3.1_razvilka-inert.ipk","package_sha256":"` + strings.Repeat("a", 64) + `","configs":null,"supervision_version":1}`
	path := filepath.Join(dir, "current.json")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, reader := range []int{2, 3} {
		if err := checkComponentReadState(ctx, state, reader); err == nil {
			t.Fatal("old controller admitted schema4 initial intent", reader)
		}
	}
	if err := checkComponentReadState(ctx, state, 4); err != nil {
		t.Fatal("actual reader4 cannot inspect pending initial intent", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != data {
		t.Fatal("read capability check mutated pending journal", err)
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
