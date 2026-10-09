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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// Root alone enables/runs this against an isolated native /opt installation.
// Setup must have used the genuine prepare/staging producer and actual
// stopped/reaped helper/panel evidence. This test creates no reviewed records,
// candidate images, Stop/epoch or runtime facts and offers no production path
// override. Empty fixture coordinates mean ordinary CI skips the destructive
// data test. The fixture is left OFFLINE with all displaced artifacts retained.
func TestNativePairedRestorePublicExecutableCaller(t *testing.T) {
	id := os.Getenv("RAZVILKA_NATIVE_PAIRED_RESTORE_ID")
	program := os.Getenv("RAZVILKA_NATIVE_PAIRED_RESTORE_CANDIDATE")
	if id == "" && program == "" {
		t.Skip("Root opt-in isolated production /opt pair required")
	}
	decoded, err := hex.DecodeString(id)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != id || !filepath.IsAbs(program) || filepath.Clean(program) != program || os.Geteuid() != 0 {
		t.Fatal("invalid native fixture coordinates/owner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	adapter := updatecheck.NewSelfUpdateFileAdapterWithAuthority(selfUpdateStopCheck, selfUpdateEffectAdmission, selfUpdateRuntimeInactive)
	store, err := adapter.OpenFileJournal()
	if err != nil {
		t.Fatal("fixture has no existing bound private file owner", err)
	}
	receipt, present, err := store.Current()
	store.Close()
	if err != nil || !present || receipt.ID != id || receipt.Paired == nil || receipt.Schema != 4 {
		t.Fatal("fixture is not the current complete paired transaction")
	}
	var oldSHA, newSHA string
	for _, file := range receipt.Files {
		if file.Target == "bin/razvilka" {
			oldSHA, newSHA = file.OldHash, file.NewHash
		}
	}
	if len(oldSHA) != 64 || len(newSHA) != 64 || oldSHA == newSHA {
		t.Fatal("fixture needs physically distinct source/candidate executables")
	}
	if got := nativePairedRestoreFileHash(t, program); got != newSHA {
		t.Fatal("actual executable caller is not the verified candidate")
	}
	control := selfUpdateDefaultPath("/opt/var/lib/razvilka/self-update-stop")
	stop, stopPresent, err := operationgate.ReadSelfUpdateStop(ctx, control)
	if err != nil || !stopPresent || !stop.Stopped || stop.TransactionID != id {
		t.Fatal("fixture lacks its actual matching durable Stop")
	}
	if _, err := os.Lstat(selfUpdateDefaultPath("/opt/var/run/razvilka.pid")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("old/candidate panel PID file remains; fixture must stop/join before restore")
	}
	cfgPath := selfUpdateDefaultPath("/opt/etc/razvilka/config.json")
	beforeConfig, _, err := config.Inspect(cfgPath)
	if err != nil {
		t.Fatal("current config is unreadable before restore", err)
	}
	// Read-only verification uses the real bound images/identity, not a fixture
	// DTO. The adapter itself will prove all native process/runtime absence.
	if _, _, _, err := adapter.Review(ctx, id); err != nil {
		t.Fatal("fixture has no canonical prepared producer review", err)
	}
	protected := []string{
		"/opt/var/lib/razvilka/self-update", "/opt/var/lib/razvilka/self-update-files", control,
		"/opt/var/lib/razvilka-offline-recovery/" + id,
		"/opt/var/lib/razvilka/warp", "/opt/var/lib/razvilka/dataplane", "/opt/var/lib/razvilka/backups",
		"/opt/var/lib/razvilka/components/update-journal", "/opt/var/lib/razvilka/components/operations", "/opt/var/lib/razvilka/components/rollback-packages",
		"/opt/etc/razvilka/private-restore", "/opt/etc/razvilka/private-restore-nodes-v1", "/opt/etc/razvilka/private-restore-native-v1", "/opt/etc/razvilka/private-restore-feeds-v1", "/opt/etc/razvilka/cloudflare-private",
	}
	before := nativePairedRestoreEvidence(t, ctx, protected)
	stdout, stderr := nativePairedRestoreOutput{}, nativePairedRestoreOutput{}
	command := exec.CommandContext(ctx, program, "self-update-paired-restore", id)
	// The public command runs with production defaults, never fixture-root or
	// synthetic runtime helper environment. Native /opt/kernel setup is Root's.
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "RAZVILKA_") {
			command.Env = append(command.Env, value)
		}
	}
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("public restore caller refused: %v (stdout=%d stderr=%d bytes; private output omitted)", err, stdout.Len(), stderr.Len())
	}
	var result updatecheck.SelfUpdateOfflineRestoreResult
	decoder := json.NewDecoder(&stdout.Buffer)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result.State != "offline-requires-review" || decoder.Decode(&struct{}{}) != io.EOF || stderr.Len() != 0 {
		t.Fatal("public caller did not return its exact offline-only outcome")
	}
	if got := nativePairedRestoreFileHash(t, selfUpdateDefaultPath("/opt/bin/razvilka")); got != oldSHA {
		t.Fatal("old source was not restored as offline data")
	}
	for name, mode := range map[string]os.FileMode{"S99razvilka": 0755, "S99artem-flow": 0755, "S99artem-flow.razvilka-disabled": 0600} {
		path := selfUpdateDefaultPath("/opt/etc/init.d/" + name)
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) && name != "S99razvilka" {
			continue
		}
		info, statErr := os.Lstat(path)
		if err != nil || statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode || !bytes.Contains(data, []byte("paired state restored offline")) || !bytes.HasSuffix(data, []byte("exit 1\n")) {
			t.Fatal("restored source has unguarded init", name)
		}
	}
	afterConfig, _, err := config.Inspect(cfgPath)
	if err != nil || !afterConfig.SafeMode || !afterConfig.ServiceControl.Stopped || afterConfig.Revision != beforeConfig.Revision+1 || !reflect.DeepEqual(beforeConfig.NetworkPolicy, afterConfig.NetworkPolicy) || !reflect.DeepEqual(beforeConfig.AppliedNetworkPolicy, afterConfig.AppliedNetworkPolicy) || !reflect.DeepEqual(beforeConfig.InactiveResourceExclusions, afterConfig.InactiveResourceExclusions) || !reflect.DeepEqual(beforeConfig.DefaultRouteConsent, afterConfig.DefaultRouteConsent) {
		t.Fatal("public restore rewound current exclusions/Stop intent", err)
	}
	after := nativePairedRestoreEvidence(t, ctx, protected)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("public caller modified current protected evidence or offline source archive")
	}
	currentStop, stopPresent, err := operationgate.ReadSelfUpdateStop(ctx, control)
	if err != nil || !stopPresent || currentStop != stop {
		t.Fatal("public restore changed the current Stop epoch")
	}
	if _, err := os.Lstat(selfUpdateDefaultPath("/opt/var/run/razvilka.pid")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("public restore manufactured a live panel PID")
	}
	t.Log("actual public candidate caller restored source offline; original Stop, journals, exclusions and guards verified")
}

type nativePairedRestoreOutput struct{ bytes.Buffer }

func (out *nativePairedRestoreOutput) Write(data []byte) (int, error) {
	if out.Len()+len(data) > 64<<10 {
		return 0, io.ErrShortBuffer
	}
	return out.Buffer.Write(data)
}

func nativePairedRestoreFileHash(t *testing.T, path string) string {
	t.Helper()
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal("evidence file unavailable", filepath.Base(path), err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > 64<<20 {
		t.Fatal("invalid bounded evidence file", filepath.Base(path))
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(file, (64<<20)+1), make([]byte, 64<<10))
	after, statErr := file.Stat()
	current, currentErr := os.Lstat(path)
	if err != nil || statErr != nil || currentErr != nil || n != before.Size() || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("evidence changed while hashing", filepath.Base(path))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func nativePairedRestoreEvidence(t *testing.T, ctx context.Context, paths []string) map[string]string {
	t.Helper()
	result := map[string]string{}
	var count int
	var total int64
	var walk func(string)
	walk = func(path string) {
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			result[path] = "absent"
			return
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() && !info.IsDir() || count >= 40000 {
			t.Fatal("unsafe/bounded protected evidence", filepath.Base(path))
		}
		count++
		result[path] = strconv.FormatUint(uint64(info.Mode().Perm()), 8) + ":"
		if info.Mode().IsRegular() {
			total += info.Size()
			if total > 2<<30 {
				t.Fatal("protected evidence exceeds native fixture bound")
			}
			result[path] += nativePairedRestoreFileHash(t, path)
			return
		}
		result[path] += "directory"
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("protected directory unavailable")
		}
		entries, err := file.ReadDir(4097)
		file.Close()
		if err != nil && err != io.EOF || len(entries) > 4096 {
			t.Fatal("unbounded protected directory")
		}
		for _, entry := range entries {
			walk(filepath.Join(path, entry.Name()))
		}
	}
	for _, path := range paths {
		walk(path)
	}
	return result
}
