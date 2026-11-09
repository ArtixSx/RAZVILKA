//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// Observation only, after the actual failed producer was joined. Do not open
// a Store (which could create a lock), repair a receipt or dump private data.
func nativeExternalBootstrapFileLedger(t *testing.T, id string) {
	t.Helper()
	path := filepath.Join(installpath.State, "self-update-files", id, "receipt.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<10 {
		t.Log("actual_bootstrap_failure_file_ledger unavailable=true")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		t.Log("actual_bootstrap_failure_file_ledger unavailable=true")
		return
	}
	opened, statErr := f.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	closeErr := f.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(info, opened) || len(raw) > 16<<10 {
		clear(raw)
		t.Log("actual_bootstrap_failure_file_ledger unavailable=true")
		return
	}
	defer clear(raw)
	t.Log(nativeExternalBootstrapLedgerDiagnostic(raw, id))
}

func nativeExternalBootstrapLedgerDiagnostic(raw []byte, id string) string {
	var receipt selfupdatejournal.Receipt
	if len(raw) > 16<<10 || json.Unmarshal(raw, &receipt) != nil || receipt.ID != id {
		return "actual_bootstrap_failure_file_ledger invalid=true"
	}
	phase, command := "unknown", "unknown"
	switch receipt.Phase {
	case "prepared", "paired-prepared", "command-started", "command-finished", "installing", "installed", "accepted", "archived":
		phase = receipt.Phase
	}
	switch receipt.Command {
	case "", "stop-old-panel", "prepare-private-state", "quiesce-old-runtime", "start-candidate-panel":
		command = receipt.Command
	}
	schema, index, commands := receipt.Schema, receipt.Index, len(receipt.Commands)
	if schema < 1 || schema > 4 {
		schema = 0
	}
	if index < 0 || index > 6 {
		index = -1
	}
	if commands > 8 {
		commands = -1
	}
	return fmt.Sprintf("actual_bootstrap_failure_file_ledger schema=%d phase=%s command=%q index=%d commands=%d paired=%t before_files=%t diagnostic_only=true", schema, phase, command, index, commands, receipt.Paired != nil, receipt.BeforeFiles)
}

func TestExternalBootstrapDiagnosticFileLedgerIsClosedAndBounded(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, phase := range []string{"prepared", "command-finished", "paired-prepared", "installed"} {
		raw, _ := json.Marshal(selfupdatejournal.Receipt{Schema: 2, ID: id, Phase: phase, Command: "quiesce-old-runtime", BeforeFiles: true})
		got := nativeExternalBootstrapLedgerDiagnostic(raw, id)
		if !strings.Contains(got, "phase="+phase+" ") || !strings.Contains(got, "command=\"quiesce-old-runtime\"") {
			t.Fatal("fixed observation lost", got)
		}
	}
	raw, _ := json.Marshal(selfupdatejournal.Receipt{Schema: 999, ID: id, Phase: "private/path\nsecret", Command: "private/argv", Index: 999})
	got := nativeExternalBootstrapLedgerDiagnostic(raw, id)
	if strings.Contains(got, "private") || strings.Contains(got, "secret") || strings.Contains(got, "999") || !strings.Contains(got, "phase=unknown") {
		t.Fatal("private bytes escaped", got)
	}
	for _, raw := range [][]byte{bytes.Repeat([]byte("x"), (16<<10)+1), []byte("{}"), []byte("invalid private bytes")} {
		if nativeExternalBootstrapLedgerDiagnostic(raw, id) != "actual_bootstrap_failure_file_ledger invalid=true" {
			t.Fatal("invalid receipt accepted")
		}
	}
}
