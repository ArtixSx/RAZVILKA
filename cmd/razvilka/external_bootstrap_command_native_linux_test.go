//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Root opt-in only: a real isolated fixed-/opt source0.19.3 with its actual
// live panel and a real built0.20.0 release archive/candidate are required.
// This test creates no review/receipt/helper identity/Stop/runtime facts. The
// public executable must produce them itself. Stopped/safe source intent leaves
// an installed offline pair; live source intent requires real runtime acceptance.
func TestNativeExternalBootstrapPublicExecutableProducer(t *testing.T) {
	id := os.Getenv("RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ID")
	program := os.Getenv("RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_CANDIDATE")
	archive := os.Getenv("RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ARCHIVE")
	sha := os.Getenv("RAZVILKA_NATIVE_EXTERNAL_BOOTSTRAP_ARCHIVE_SHA")
	if id == "" && program == "" && archive == "" && sha == "" {
		t.Skip("Root opt-in real fixed-/opt source and verified package required")
	}
	decodedID, idErr := hex.DecodeString(id)
	decodedSHA, shaErr := hex.DecodeString(sha)
	if os.Geteuid() != 0 || idErr != nil || len(decodedID) != 16 || hex.EncodeToString(decodedID) != id || shaErr != nil || len(decodedSHA) != 32 || hex.EncodeToString(decodedSHA) != sha ||
		!filepath.IsAbs(program) || filepath.Clean(program) != program || !filepath.IsAbs(archive) || filepath.Clean(archive) != archive {
		t.Fatal("invalid native producer coordinates")
	}
	oldSHA := nativePairedRestoreFileHash(t, "/opt/bin/razvilka")
	newSHA := nativePairedRestoreFileHash(t, program)
	if oldSHA == newSHA || nativeExternalBootstrapArchiveHash(t, archive) != sha {
		t.Fatal("source/candidate/package must be distinct verified physical artifacts")
	}
	beforeConfig, _, err := config.Inspect("/opt/etc/razvilka/config.json")
	if err != nil {
		t.Fatal("genuine source config is unreadable", err)
	}
	offline := beforeConfig.SafeMode || beforeConfig.ServiceControl.Stopped
	wantState := "completed-awaiting-owner-retirement"
	if offline {
		wantState = "installed-offline-requires-review"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 21*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, program, "self-update-bootstrap-old193", id, archive, sha)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(strings.SplitN(value, "=", 2)[0]), "RAZVILKA_") {
			command.Env = append(command.Env, value)
		}
	}
	stdout, stderr := &nativePairedRestoreOutput{}, &nativePairedRestoreOutput{}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil || stderr.Len() != 0 {
		exitCode := -1
		if command.ProcessState != nil {
			exitCode = command.ProcessState.ExitCode()
		}
		t.Fatalf("actual public external producer refused; category=%s exit_code=%d; retain isolated fixture", externalBootstrapDiagnosticCategory(stderr.Bytes()), exitCode)
	}
	var result updatecheck.SelfUpdateExternalBootstrapResult
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.ID != id || result.State != wantState {
		t.Fatal("actual producer did not complete its paired handoff")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatal("producer output was not a single closed result")
	}
	adapter := updatecheck.NewSelfUpdateFileAdapterWithAuthority(selfUpdateStopCheck, selfUpdateEffectAdmission, selfUpdateRuntimeInactive)
	store, err := adapter.OpenFileJournal()
	if err != nil {
		t.Fatal("genuine producer did not leave its bound file journal", err)
	}
	defer store.Close()
	receipt, present, err := store.Current()
	if err != nil || !present || receipt.ID != id || receipt.Schema != selfupdatejournal.PairedSchema || receipt.Paired == nil {
		t.Fatal("genuine producer did not publish its complete pair", err)
	}
	if offline && receipt.Phase != "installed" || !offline && receipt.Phase != "accepted" && receipt.Phase != "archived" {
		t.Fatal("genuine pair has an unexpected phase for source intent")
	}
	matched := false
	for _, file := range receipt.Files {
		if file.Target == "bin/razvilka" {
			matched = file.OldHash == oldSHA && file.NewHash == newSHA
		}
	}
	if !matched || nativePairedRestoreFileHash(t, "/opt/bin/razvilka") != newSHA {
		t.Fatal("producer adopted or installed another source/candidate")
	}
	if _, _, _, err := adapter.Review(ctx, id); err != nil {
		t.Fatal("genuine producer retained an unreadable immutable review", err)
	}
	if offline {
		afterConfig, _, err := config.Inspect("/opt/etc/razvilka/config.json")
		if err != nil || beforeConfig.SafeMode != afterConfig.SafeMode || !reflect.DeepEqual(beforeConfig.ServiceControl, afterConfig.ServiceControl) || !reflect.DeepEqual(beforeConfig.NetworkPolicy, afterConfig.NetworkPolicy) || !reflect.DeepEqual(beforeConfig.AppliedNetworkPolicy, afterConfig.AppliedNetworkPolicy) || !reflect.DeepEqual(beforeConfig.DefaultRouteConsent, afterConfig.DefaultRouteConsent) || !reflect.DeepEqual(beforeConfig.InactiveResourceExclusions, afterConfig.InactiveResourceExclusions) {
			t.Fatal("offline installation changed stopped/safe routing intent", err)
		}
		if _, err := os.Lstat("/opt/var/run/razvilka.pid"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("offline installation left a live panel PID")
		}
		if err := store.VerifyInstallation(ctx, id, false); err != nil {
			t.Fatal("offline installation did not independently verify", err)
		}
	} else if err := adapter.Inspect(ctx, id); err != nil {
		t.Fatal("completed helper pair did not independently verify", err)
	}
	stop, present, err := operationgate.ReadSelfUpdateStop(ctx, "/opt/var/lib/razvilka/self-update-stop")
	if err != nil || !present || stop.Stopped {
		t.Fatal("successful bootstrap has unavailable/revoked current control", err)
	}
	t.Log("actual executable produced source0.19.3/candidate0.20.0 pair with source intent preserved; runtime acceptance is asserted only by the live branch, while actual App retirement and current-owner Stop/offline restore remain separate Root checks")
}

func nativeExternalBootstrapArchiveHash(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("native package unavailable", err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > updatecheck.MaximumArchiveBytes {
		t.Fatal("invalid bounded native package")
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(f, updatecheck.MaximumArchiveBytes+1), make([]byte, 64<<10))
	after, statErr := f.Stat()
	current, currentErr := os.Lstat(path)
	if err != nil || statErr != nil || currentErr != nil || n != before.Size() || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("native package changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil))
}
