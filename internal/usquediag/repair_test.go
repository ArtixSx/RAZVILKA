package usquediag

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

type repairRunner struct {
	initPath      string
	rejectPatched bool
}

func (r repairRunner) Run(_ context.Context, command Command) ([]byte, error) {
	if len(command.Args) == 2 && command.Args[0] == "-n" && command.Args[1] == r.initPath {
		data, err := os.ReadFile(r.initPath)
		if err != nil {
			return nil, err
		}
		if r.rejectPatched && strings.Contains(string(data), "LD_LIBRARY_PATH=/lib:/usr/lib") {
			return nil, errors.New("synthetic syntax rejection")
		}
		return []byte("syntax ok"), nil
	}
	if command.Name == "/bin/ndmc" {
		if len(command.Env) == 0 {
			return nil, errors.New("Entware libraries shadow system libraries")
		}
		return []byte("Keenetic"), nil
	}
	return nil, errors.New("unexpected command")
}

func repairFixture(t *testing.T, runner repairRunner) (*Manager, string, string) {
	t.Helper()
	root := t.TempDir()
	initPath := filepath.Join(root, "S51usque")
	original := "#!/bin/sh\nanswer=$(/bin/ndmc -c 'show version')\n/bin/ndmc -c \"$1\"\n"
	if err := os.WriteFile(initPath, []byte(original), 0o755); err != nil {
		t.Fatal(err)
	}
	runner.initPath = initPath
	manager := &Manager{Runner: runner, InitPath: initPath, NDMCPath: "/bin/ndmc", ShellPath: "/bin/sh", RepairRoot: filepath.Join(root, "repair")}
	return manager, initPath, original
}

func TestNDMCRepairIsJournaledBackedUpAndIdempotent(t *testing.T) {
	m, initPath, original := repairFixture(t, repairRunner{})
	if _, err := m.RepairNDMC(context.Background(), "wrong"); !errors.Is(err, ErrRepairConfirmation) {
		t.Fatal("repair accepted missing confirmation", err)
	}
	result, err := m.RepairNDMC(context.Background(), RepairConfirmation)
	if err != nil || !result.OK || !result.Changed || result.Status != "applied" || result.Outcome != restorejournal.Applied || result.BackupID == "" {
		t.Fatalf("repair=%+v err=%v", result, err)
	}
	patched, err := os.ReadFile(initPath)
	if err != nil || strings.Count(string(patched), "LD_LIBRARY_PATH=/lib:/usr/lib /bin/ndmc") != 2 {
		t.Fatalf("unexpected patch: %v %q", err, patched)
	}
	backupPath := filepath.Join(m.RepairRoot, result.BackupID, "S51usque.before")
	backup, err := os.ReadFile(backupPath)
	if err != nil || string(backup) != original {
		t.Fatal("exact backup missing")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(backupPath)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("backup mode=%o", info.Mode().Perm())
		}
	}
	second, err := m.RepairNDMC(context.Background(), RepairConfirmation)
	if err != nil || !second.OK || second.Changed || second.Status != "not_needed" {
		t.Fatalf("second repair=%+v err=%v", second, err)
	}
}

func TestNDMCRepairVerificationFailureRestoresOriginal(t *testing.T) {
	m, initPath, original := repairFixture(t, repairRunner{rejectPatched: true})
	result, err := m.RepairNDMC(context.Background(), RepairConfirmation)
	if err == nil || !result.RolledBack || result.Outcome != restorejournal.RolledBack {
		t.Fatalf("repair failure=%+v err=%v", result, err)
	}
	after, readErr := os.ReadFile(initPath)
	if readErr != nil || string(after) != original {
		t.Fatal("failed verification did not restore exact init")
	}
}

func TestNDMCRepairCorruptJournalFailsWithoutChangingInit(t *testing.T) {
	m, initPath, original := repairFixture(t, repairRunner{})
	if err := os.Mkdir(m.RepairRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(m.RepairRoot, "restore.private.json")
	marker := []byte(`{"corrupt":`)
	if err := os.WriteFile(journalPath, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RepairNDMC(context.Background(), RepairConfirmation); !errors.Is(err, ErrRepairBlocked) {
		t.Fatal("corrupt journal did not block repair", err)
	}
	after, _ := os.ReadFile(initPath)
	journalAfter, _ := os.ReadFile(journalPath)
	if string(after) != original || string(journalAfter) != string(marker) {
		t.Fatal("blocked repair changed init or journal")
	}
}

func TestRecoverNDMCRepairIsLazyWhenUnused(t *testing.T) {
	root := t.TempDir()
	m := &Manager{RepairRoot: filepath.Join(root, "absent")}
	outcome, err := m.RecoverNDMCRepair(context.Background())
	if err != nil || outcome != restorejournal.Clean {
		t.Fatal(outcome, err)
	}
	if _, err := os.Stat(m.RepairRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unused recovery created state")
	}
}

func TestRecoverNDMCRepairAllowsCleanHistoryAfterUSQUEUninstall(t *testing.T) {
	m, initPath, _ := repairFixture(t, repairRunner{})
	if _, err := m.RepairNDMC(context.Background(), RepairConfirmation); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(initPath); err != nil {
		t.Fatal(err)
	}
	outcome, err := m.RecoverNDMCRepair(context.Background())
	if err != nil || outcome != restorejournal.Clean {
		t.Fatalf("clean repair history blocked startup after uninstall: %s %v", outcome, err)
	}
}

func TestPatchNDMCInitRejectsAmbiguousCalls(t *testing.T) {
	for _, input := range []string{
		"#!/bin/sh\nndmc -c 'show version'\n",
		"#!/bin/sh\nNDMC=/bin/ndmc\n$NDMC -c 'show version'\n",
		"#!/bin/sh\nLD_LIBRARY_PATH=/opt/lib /bin/ndmc -c 'show version'\n",
		"#!/bin/sh\n/bin/ndmc -c a; /bin/ndmc -c b\n",
		"#!/bin/sh\necho /bin/ndmc -c 'show version'\n",
		"#!/bin/sh\nif /bin/ndmc -c 'show version'; then echo ok; fi\n",
		"#!/bin/sh\nTEST=/bin/ndmc\n",
	} {
		if _, _, err := patchNDMCInit([]byte(input)); !errors.Is(err, ErrRepairBlocked) {
			t.Fatalf("ambiguous input accepted: %q err=%v", input, err)
		}
	}
}
