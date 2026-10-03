package warp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// Opt-in filesystem/subprocess acceptance. The provider is an in-process test
// double; no socket, daemon, actual registration or router is used. The shell
// backup selector and full rollback reader come from production source.
func TestNativeLocalCloudRetentionHarness(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_CLOUD_RETENTION") != "1" {
		t.Skip("coordinator-owned retention subprocess window is disabled")
	}
	if mode := os.Getenv("RAZVILKA_CLOUD_RETENTION_CHILD"); mode != "" {
		cloudRetentionChild(t, os.Getenv("RAZVILKA_CLOUD_RETENTION_ROOT"), mode)
		return
	}
	sh := os.Getenv("RAZVILKA_CLOUD_RETENTION_SH")
	if sh == "" {
		var err error
		sh, err = exec.LookPath("sh")
		if err != nil {
			t.Fatal("a POSIX shell is required for the opt-in retention harness")
		}
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"timeout-pending", "response-crash"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			cloudRetentionFixture(t, base)
			oldBackup := cloudRetentionSnapshot(t, sh, repo, base, "20000101T000001Z-1")
			// Freeze executable LKG before the one simulated remote effect.
			journal := filepath.Join(base, "var", "lib", "razvilka", "self-update-files")
			cloudRetentionWrite(t, filepath.Join(base, "candidate"), []byte(cloudRetentionBinary+"# candidate\n"), 0700)
			store, err := selfupdatejournal.Open(base, journal)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			id := strings.Repeat("1", 32)
			check := func(context.Context) error { return nil } // inert fixture only
			candidate := filepath.Join(base, "candidate")
			if err := store.Prepare(context.Background(), id, []selfupdatejournal.File{{Target: "bin/razvilka", Candidate: candidate, SHA256: cloudRetentionHash(cloudRetentionRead(t, candidate))}}, check, check); err != nil {
				t.Fatal(err)
			}
			cloudRetentionRunChild(t, base, mode)
			m := cloudRetentionManager(base)
			doc := readNativeTestDocument(t, m)
			pending, present, err := readNativeEnrollment(doc, nativePending)
			if err != nil || !present || !doc.Has(pending.Directory+"/private-key.bin") || doc.Has(pending.Directory+"/registration.private.json") || doc.Has(nativeCurrent) || m.Status(context.Background()).CandidateStaged {
				t.Fatal("child did not stop at the required durable enrollment boundary")
			}
			if doc.Has(pending.Directory+"/response.private.json") != (mode == "response-crash") || len(m.Health().State.Attempts) != 1 {
				t.Fatal("response checkpoint or pre-request accounting was not retained")
			}
			cloudRetentionAddLegacyAndJournals(t, base)
			retained := cloudRetentionTree(t, base, []string{"var/lib/razvilka/warp", "etc/razvilka/private-restore-native-v1", "etc/razvilka/private-restore-feeds-v1"})
			live := cloudRetentionRead(t, m.ProfilePaths[0])
			if err := store.Install(context.Background(), id, check, check); err != nil {
				t.Fatal(err)
			}
			newBackup := cloudRetentionSnapshot(t, sh, repo, base, "20000101T000002Z-2")
			cloudRetentionAssertNoImage(t, newBackup)
			if err := store.Restore(context.Background(), id, check, check); err != nil {
				t.Fatal(err)
			}
			// No live acceptance is claimed: restored stays a pending receipt.
			if receipt, present, err := store.Current(); err != nil || !present || receipt.Phase != "restored" || !receipt.Pending() {
				t.Fatal("executable restore lost its independent pending fence")
			}
			cloudRetentionMutateMutable(t, base)
			cloudRetentionRollback(t, sh, repo, base, oldBackup, true)
			cloudRetentionAssertMutableRestored(t, base)
			cloudRetentionPrune(t, sh, repo, base, newBackup)
			cloudRetentionAssertTree(t, base, retained)
			if !bytes.Equal(live, cloudRetentionRead(t, m.ProfilePaths[0])) {
				t.Fatal("rollback changed the working WARP profile")
			}
			calls := 0
			installNativeTestAPI(m, &calls, false, errors.New("fixture API must not run after rollback"))
			if mode == "timeout-pending" {
				for _, fresh := range []bool{false, true} {
					if _, err := m.Generate(context.Background(), true, fresh); !errors.Is(err, ErrEnrollmentPending) {
						t.Fatal("restart did not preserve the unresolved registration fence")
					}
				}
				if _, err := m.GenerateAutomatic(context.Background(), m.Health().Policy); err == nil {
					t.Fatal("automatic restart bypassed charged attempt accounting")
				}
				cloudRetentionAssertTree(t, base, retained)
			} else {
				if result, err := m.Generate(context.Background(), false, false); err != nil || !result.OK {
					t.Fatal("same-attempt response recovery failed")
				}
				after := readNativeTestDocument(t, m)
				if after.Has(nativePending) || !bytes.Equal(after.Get(nativeCurrent), doc.Get(nativePending)) || !bytes.Equal(after.Get(pending.Directory+"/private-key.bin"), doc.Get(pending.Directory+"/private-key.bin")) || !bytes.Equal(after.Get(pending.Directory+"/response.private.json"), doc.Get(pending.Directory+"/response.private.json")) {
					t.Fatal("recovery replaced the original attempt identity or materials")
				}
			}
			if calls != 0 || string(cloudRetentionRead(t, filepath.Join(base, "simulated-requests"))) != "request\n" {
				t.Fatal("rollback/restart initiated another simulated POST")
			}
		})
	}
	// Current shell schema is fixed: root image keys are unsupported. This is
	// evidence for its actual reader, not a nonexistent generic overlap validator.
	t.Run("whole-directory-manifest-rejected-before-stop", func(t *testing.T) {
		base := t.TempDir()
		cloudRetentionFixture(t, base)
		cloudRetentionRunChild(t, base, "timeout-pending")
		cloudRetentionAddLegacyAndJournals(t, base)
		backup := cloudRetentionSnapshot(t, sh, repo, base, "20000101T000001Z-1")
		manifest := cloudRetentionRead(t, filepath.Join(backup, "manifest"))
		before := cloudRetentionTree(t, base, []string{"bin", "etc", "var/lib/razvilka/warp", "var/lib/razvilka/self-update-files"})
		for _, key := range []string{"WARP_ROOT_PRESENT", "STATEDIR_PRESENT", "APPDIR_PRESENT"} {
			cloudRetentionWrite(t, filepath.Join(backup, "manifest"), append(append([]byte{}, manifest...), []byte(key+"=1\n")...), 0600)
			cloudRetentionRollback(t, sh, repo, base, backup, false)
			cloudRetentionAssertTree(t, base, before)
			if _, err := os.Stat(filepath.Join(base, "stop-called")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsupported root manifest reached the stop effect")
			}
			if _, err := os.Stat(filepath.Join(base, "binary-called")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsupported root manifest reached recovery/schema effects")
			}
		}
		store, err := selfupdatejournal.Open(base, filepath.Join(base, "var", "lib", "razvilka", "self-update-files"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		callbacks := 0
		check := func(context.Context) error { callbacks++; return nil }
		candidate := filepath.Join(base, "bin", "razvilka")
		for _, target := range []string{"etc/razvilka", "var/lib/razvilka", "var/lib/razvilka/warp", "var/lib/razvilka/warp/native-enrollment.private.json"} {
			if err := store.Prepare(context.Background(), strings.Repeat("2", 32), []selfupdatejournal.File{{Target: target, Candidate: candidate, SHA256: cloudRetentionHash(cloudRetentionRead(t, candidate))}}, check, check); !errors.Is(err, selfupdatejournal.ErrMismatch) {
				t.Fatal("file journal accepted a retained directory/root target")
			}
		}
		if callbacks != 0 {
			t.Fatal("rejected directory target reached write authority/quiescence")
		}
		// The writer lock may create its journal marker; retained/live bytes are
		// still unchanged. Do not claim zero journal writes for Prepare rejection.
		cloudRetentionAssertTree(t, base, before, "var/lib/razvilka/self-update-files/.writer.lock")
	})
	t.Run("node-history-reader-refused-before-stop", func(t *testing.T) {
		production := string(cloudRetentionRead(t, filepath.Join(repo, "scripts", "rollback-entware.sh")))
		if !strings.Contains(production, "require_node_history_compatibility()") {
			t.Skip("OPS node-history admission is not integrated in this checkout")
		}
		for _, refusal := range []string{"incompatible", "unsupported"} {
			t.Run(refusal, func(t *testing.T) {
				base := t.TempDir()
				cloudRetentionFixture(t, base)
				cloudRetentionRunChild(t, base, "timeout-pending")
				cloudRetentionAddLegacyAndJournals(t, base)
				backup := cloudRetentionSnapshot(t, sh, repo, base, "20000101T000001Z-1")
				before := cloudRetentionTree(t, base, []string{"bin", "etc", "var/lib/razvilka/warp"})
				cloudRetentionWrite(t, filepath.Join(base, "node-history-refuse"), []byte(refusal), 0600)
				reason := "Retained node history compatibility not confirmed; installation unchanged"
				if refusal == "unsupported" {
					reason = "Target binary cannot read all retained node history; installation unchanged"
				}
				cloudRetentionRollbackReason(t, sh, repo, base, backup, false, reason)
				cloudRetentionAssertTree(t, base, before)
				if _, err := os.Lstat(filepath.Join(base, "node-history-called")); err != nil {
					t.Fatal("negative fixture did not exercise the typed reader gate")
				}
				if _, err := os.Lstat(filepath.Join(base, "stop-called")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("typed reader refusal reached stop")
				}
			})
		}
	})
}

func cloudRetentionManager(base string) *Manager {
	state := filepath.Join(base, "var", "lib", "razvilka")
	m := New(filepath.Join(state, "warp"), filepath.Join(state, "backups"), engineconfig.New(filepath.Join(state, "staging"), filepath.Join(state, "config-backups")))
	m.BinPaths = []string{filepath.Join(base, "no-wgcf")}
	m.ProfilePaths = []string{filepath.Join(base, "etc", "razvilka", "wgcf-live.conf")}
	return m
}

func cloudRetentionChild(t *testing.T, base, mode string) {
	t.Helper()
	m := cloudRetentionManager(base)
	now := time.Now().UTC()
	m.healthNow = func() time.Time { return now }
	p := defaultHealthPolicy()
	p.Enabled, p.AcceptTOS, p.AutoGenerateCandidate, p.AllowAccountRefresh = true, true, true, true
	p.MinFailedServices, p.FailureThreshold = 1, 2
	if _, err := m.UpdateHealthPolicy(p); err != nil {
		t.Fatal(err)
	}
	if _, err := observedFailure(m); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second)
	if decision, err := observedFailure(m); err != nil || !decision.ShouldGenerate {
		t.Fatal("fixture did not become eligible")
	}
	calls := 0
	installNativeTestAPI(m, &calls, mode == "response-crash", context.DeadlineExceeded)
	factory := m.nativeAPI
	m.nativeAPI = func(save func([]byte) error) cloudflareprovider.RegistrationAPI {
		api := factory(func(data []byte) error {
			if err := save(data); err != nil {
				return err
			}
			os.Exit(73) // abrupt death after durable response, before decode/stage/current
			return nil
		})
		return nativeTestAPI(func(ctx context.Context, request cloudflareprovider.RegistrationRequest) (cloudflareprovider.RegistrationResponse, error) {
			f, err := os.OpenFile(filepath.Join(base, "simulated-requests"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return cloudflareprovider.RegistrationResponse{}, err
			}
			_, err = f.WriteString("request\n")
			if err == nil {
				err = f.Sync()
			}
			_ = f.Close()
			if err != nil {
				return cloudflareprovider.RegistrationResponse{}, err
			}
			return api.Register(ctx, request)
		})
	}
	if _, err := m.GenerateAutomatic(context.Background(), p); mode != "timeout-pending" || !errors.Is(err, ErrEnrollmentPending) || calls != 1 {
		t.Fatal("child did not produce the expected pending effect")
	}
}

func cloudRetentionRunChild(t *testing.T, base, mode string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNativeLocalCloudRetentionHarness$", "-test.timeout=12s")
	cmd.Env = append(os.Environ(), "RAZVILKA_CLOUD_RETENTION_CHILD="+mode, "RAZVILKA_CLOUD_RETENTION_ROOT="+base)
	output, err := cmd.CombinedOutput()
	want := 0
	if mode == "response-crash" {
		want = 73
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal("retention child could not execute")
		}
		code = exit.ExitCode()
	}
	if code != want || ctx.Err() != nil || bytes.Contains(output, []byte("private-token-marker")) || bytes.Contains(output, []byte("private-device-marker")) {
		t.Fatal("retention child exit or secret boundary failed")
	}
}

const cloudRetentionBinary = `#!/bin/sh
set -eu
printf 'called\n' >> "$RAZVILKA_BASE/binary-called"
case "$1" in
  -native-enrollment-schema|-self-update-schema|-subscription-schema) printf '1\n' ;;
  -check-node-history-state)
    [ "$#" -eq 5 ] && [ "$2" = -node-history-config-root ] &&
      [ "$3" = "$RAZVILKA_BASE/etc/razvilka" ] && [ "$4" = -node-history-state-root ] &&
      [ "$5" = "$RAZVILKA_BASE/var/lib/razvilka" ] || exit 96
    printf 'checked\n' >> "$RAZVILKA_BASE/node-history-called"
    if [ -f "$RAZVILKA_BASE/node-history-refuse" ]; then
      [ "$(cat "$RAZVILKA_BASE/node-history-refuse")" != unsupported ] || exit 94
      printf '{"ok":false}\n'
    else
      printf '{"ok":true}\n'
    fi ;;
  -recover-private-restore) printf '{"ok":true}\n' ;;
  -deactivate-dataplane) : ;;
  *) exit 94 ;;
esac
`

func cloudRetentionFixture(t *testing.T, base string) {
	t.Helper()
	for _, dir := range []string{"bin", "etc/init.d", "etc/razvilka", "var/lib/razvilka/self-update-files", "var/lib/razvilka/update-backups", "var/lib/razvilka/staging", "var/lib/razvilka/dataplane", "etc/razvilka/cloudflare-private"} {
		if err := os.MkdirAll(filepath.Join(base, filepath.FromSlash(dir)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cloudRetentionWrite(t, filepath.Join(base, "bin", "razvilka"), []byte(cloudRetentionBinary), 0755)
	cloudRetentionWrite(t, filepath.Join(base, "etc", "init.d", "S99razvilka"), []byte("#!/bin/sh\ncase \"$1\" in status) exit 1;; stop) printf 'stop\\n' >> \"$RAZVILKA_BASE/stop-called\";; *) exit 95;; esac\n"), 0755)
	cloudRetentionWrite(t, filepath.Join(base, "etc", "razvilka", "config.json"), []byte("fixture config LKG\n"), 0600)
	cloudRetentionWrite(t, cloudRetentionManager(base).ProfilePaths[0], []byte(validProfile), 0600)
	for _, dir := range cloudMutableDirectories {
		cloudRetentionWrite(t, filepath.Join(base, filepath.FromSlash(dir), "old-file"), []byte("mutable LKG\n"), 0600)
		cloudRetentionWrite(t, filepath.Join(base, filepath.FromSlash(dir), "old-removed-file"), []byte("mutable LKG\n"), 0600)
	}
}

func cloudRetentionAddLegacyAndJournals(t *testing.T, base string) {
	t.Helper()
	// Retained generations are inert byte fixtures, not recovery acceptance.
	legacy := "var/lib/razvilka/warp/native-enrollment/"
	attempt := "attempt-" + strings.Repeat("a", 32)
	for _, name := range []string{"var/lib/razvilka/warp/wgcf-account.toml", legacy + attempt + "/private-key.bin", legacy + attempt + "/response.private.json", legacy + attempt + "/registration.private.json", legacy + attempt + "/provider/accounts.private.json", "etc/razvilka/private-restore-native-v1/restore.private.json", "etc/razvilka/private-restore-native-v1/before.private", "etc/razvilka/private-restore-native-v1/after.private", "etc/razvilka/private-restore-native-v1/.restore.lock", "etc/razvilka/private-restore-feeds-v1/restore.private.json", "etc/razvilka/private-restore-feeds-v1/before.private", "etc/razvilka/private-restore-feeds-v1/after.private", "etc/razvilka/private-restore-feeds-v1/.restore.lock"} {
		path := filepath.Join(base, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		cloudRetentionWrite(t, path, []byte("retained inert fixture\n"), 0600)
	}
	for _, name := range []string{"current.json", "pending.json"} {
		cloudRetentionWrite(t, filepath.Join(base, filepath.FromSlash(legacy+name)), []byte(`{"schema":1,"directory":"`+attempt+`","created_at":"2026-01-01T00:00:00Z","fresh":false}`), 0600)
	}
}

var cloudMutableDirectories = []string{"var/lib/razvilka/staging", "var/lib/razvilka/dataplane", "etc/razvilka/cloudflare-private"}

func cloudRetentionMutateMutable(t *testing.T, base string) {
	t.Helper()
	cloudRetentionWrite(t, filepath.Join(base, "etc", "razvilka", "config.json"), []byte("new config\n"), 0600)
	for _, dir := range cloudMutableDirectories {
		cloudRetentionWrite(t, filepath.Join(base, filepath.FromSlash(dir), "old-file"), []byte("changed mutable\n"), 0600)
		cloudRetentionWrite(t, filepath.Join(base, filepath.FromSlash(dir), "new-file"), []byte("new mutable\n"), 0600)
		if err := os.Remove(filepath.Join(base, filepath.FromSlash(dir), "old-removed-file")); err != nil {
			t.Fatal(err)
		}
	}
}

func cloudRetentionAssertMutableRestored(t *testing.T, base string) {
	t.Helper()
	if string(cloudRetentionRead(t, filepath.Join(base, "etc", "razvilka", "config.json"))) != "fixture config LKG\n" {
		t.Fatal("shell rollback did not restore mutable config LKG")
	}
	for _, dir := range cloudMutableDirectories {
		if string(cloudRetentionRead(t, filepath.Join(base, filepath.FromSlash(dir), "old-file"))) != "mutable LKG\n" {
			t.Fatal("shell rollback did not restore populated mutable directory")
		}
		if string(cloudRetentionRead(t, filepath.Join(base, filepath.FromSlash(dir), "old-removed-file"))) != "mutable LKG\n" {
			t.Fatal("shell rollback did not restore a removed mutable LKG file")
		}
		if _, err := os.Lstat(filepath.Join(base, filepath.FromSlash(dir), "new-file")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("shell rollback did not remove a newly added mutable file")
		}
	}
}

func cloudRetentionPrune(t *testing.T, sh, repo, base, current string) {
	t.Helper()
	oldNames := []string{"19990101T000001Z-1", "19990101T000002Z-2", "19990101T000003Z-3"}
	backupRoot := filepath.Join(base, "var", "lib", "razvilka", "update-backups")
	kept := cloudRetentionTree(t, base, []string{"var/lib/razvilka/update-backups"})
	for _, name := range oldNames {
		if err := os.Mkdir(filepath.Join(backupRoot, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	source := strings.ReplaceAll(string(cloudRetentionRead(t, filepath.Join(repo, "scripts", "upgrade-entware.sh"))), "\r\n", "\n")
	start := strings.Index(source, "prune_update_backups() {\n")
	if start < 0 || strings.Count(source, "prune_update_backups() {\n") != 1 {
		t.Fatal("production prune boundary changed; review the harness")
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatal("production prune function is incomplete")
	}
	script := `set -eu
BASE=$(CDPATH= cd -- "$1" && pwd -P)
BACKUPROOT="$BASE/var/lib/razvilka/update-backups"
BACKUP=$(CDPATH= cd -- "$2" && pwd -P)
RAZVILKA_KEEP_UPDATE_BACKUPS=2
` + source[start:start+end+len("\n}\n")] + "prune_update_backups\n"
	cloudRetentionShell(t, sh, script, []string{base, current}, true, "")
	for _, name := range oldNames {
		if _, err := os.Lstat(filepath.Join(backupRoot, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("production prune did not remove an obsolete fixture snapshot")
		}
	}
	// Exact original snapshot tree, including both LKG manifests/binaries, must
	// remain. Deleting every snapshot is not successful retention.
	cloudRetentionAssertTree(t, base, kept)
}

func cloudRetentionSnapshot(t *testing.T, sh, repo, base, name string) string {
	t.Helper()
	backup := filepath.Join(base, "var", "lib", "razvilka", "update-backups", name)
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(string(cloudRetentionRead(t, filepath.Join(repo, "scripts", "upgrade-entware.sh"))), "\r\n", "\n")
	start, end := strings.Index(source, "backup_file() {\n"), strings.Index(source, "mv \"$BACKUP/manifest.tmp\" \"$BACKUP/manifest\"\n")
	if start < 0 || end < start || strings.Count(source, "backup_file() {\n") != 1 {
		t.Fatal("production snapshot boundary changed; review the harness")
	}
	end += len("mv \"$BACKUP/manifest.tmp\" \"$BACKUP/manifest\"\n")
	prelude := `set -eu
umask 077
BASE=$(CDPATH= cd -- "$1" && pwd -P)
BINDIR="$BASE/bin"; APPDIR="$BASE/etc/razvilka"; INITDIR="$BASE/etc/init.d"
STATEDIR="$BASE/var/lib/razvilka"; BACKUP="$STATEDIR/update-backups/$2"
RAZ_INIT="$INITDIR/S99razvilka"; LEGACY_INIT="$INITDIR/S99artem-flow"; LEGACY_DISABLED="$LEGACY_INIT.razvilka-disabled"
RAZ_BINARY_PRESENT=1; RAZ_INIT_PRESENT=1; CONFIG_PRESENT=1
CATALOG_PRESENT=0; COMMUNITY_PRESENT=0; SOURCES_PRESENT=0; SOURCE_STATE_PRESENT=0
TOKEN_PRESENT=0; CREDENTIALS_PRESENT=0; CUSTOM_SERVICES_PRESENT=0; DEVICES_PRESENT=0
DATAPLANE_STATE_PRESENT=1; STAGING_PRESENT=1; CLOUDFLARE_PRIVATE_PRESENT=1
DNS_STATE_PRESENT=0; AUTONOMY_STATE_PRESENT=0
LEGACY_INIT_PRESENT=0; LEGACY_DISABLED_PRESENT=0; LEGACY_WAS_RUNNING=0; RAZ_WAS_RUNNING=0
`
	cloudRetentionShell(t, sh, prelude+source[start:end], []string{base, name}, true, "")
	cloudRetentionAssertNoImage(t, backup)
	return backup
}

func cloudRetentionRollback(t *testing.T, sh, repo, base, backup string, success bool) {
	t.Helper()
	reason := ""
	if !success {
		reason = "Unknown rollback manifest key:"
	}
	cloudRetentionRollbackReason(t, sh, repo, base, backup, success, reason)
}

func cloudRetentionRollbackReason(t *testing.T, sh, repo, base, backup string, success bool, reason string) {
	t.Helper()
	// Windows checkout CRLF is normalized only in this private executable copy;
	// every production statement and argument remains unchanged.
	production := filepath.Join(base, "production-rollback.sh")
	source := strings.ReplaceAll(string(cloudRetentionRead(t, filepath.Join(repo, "scripts", "rollback-entware.sh"))), "\r\n", "\n")
	cloudRetentionWrite(t, production, []byte(source), 0700)
	code := `set -eu
RAZVILKA_BASE=$(CDPATH= cd -- "$1" && pwd -P)
BACKUP=$(CDPATH= cd -- "$2" && pwd -P)
export RAZVILKA_BASE
exec "$3" "$4" "$BACKUP" --auto
`
	cloudRetentionShell(t, sh, code, []string{base, backup, filepath.ToSlash(sh), filepath.ToSlash(production)}, success, reason)
}

func cloudRetentionShell(t *testing.T, sh, script string, args []string, success bool, reason string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh, append([]string{"-c", script, "cloud-retention"}, args...)...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil || (err == nil) != success || reason != "" && !bytes.Contains(output, []byte(reason)) {
		// Fixtures contain no production secrets; bounded output aids porting.
		t.Fatalf("retention shell boundary failed: %v; %.1024s", err, output)
	}
}

type cloudRetainedFile struct {
	hash string
	info fs.FileInfo
}

type cloudRetainedTree struct {
	roots []string
	files map[string]cloudRetainedFile
}

func cloudRetentionTree(t *testing.T, base string, roots []string) cloudRetainedTree {
	t.Helper()
	files := map[string]cloudRetainedFile{}
	for _, root := range roots {
		err := filepath.WalkDir(filepath.Join(base, filepath.FromSlash(root)), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() && !info.IsDir() {
				return errors.New("unexpected retention fixture file type")
			}
			rel, err := filepath.Rel(base, path)
			if err != nil {
				return err
			}
			hash := ""
			if info.Mode().IsRegular() {
				hash = cloudRetentionHash(cloudRetentionRead(t, path))
			}
			files[filepath.ToSlash(rel)] = cloudRetainedFile{hash, info}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return cloudRetainedTree{append([]string{}, roots...), files}
}

func cloudRetentionAssertTree(t *testing.T, base string, before cloudRetainedTree, allowedNew ...string) {
	t.Helper()
	after := cloudRetentionTree(t, base, before.roots)
	for _, name := range allowedNew {
		if _, existed := before.files[name]; !existed {
			delete(after.files, name)
		}
	}
	if len(after.files) != len(before.files) {
		t.Fatal("retained/LKG tree entry set changed")
	}
	for name, old := range before.files {
		current, present := after.files[name]
		if !present || !os.SameFile(old.info, current.info) || old.info.Mode() != current.info.Mode() || old.hash != current.hash {
			t.Fatal("retained/LKG file content, mode or inode changed:", name)
		}
	}
}

func cloudRetentionAssertNoImage(t *testing.T, backup string) {
	t.Helper()
	err := filepath.WalkDir(backup, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(backup, path)
		name := filepath.ToSlash(rel)
		if strings.Contains(name, "native-enrollment") || strings.Contains(name, "private-restore-") || strings.Contains(name, ".state-") || entry.Name() == "health-policy.json" || entry.Name() == "wgcf-account.toml" || entry.Name() == "warp" {
			return errors.New("snapshot contains retained enrollment bytes")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func cloudRetentionWrite(t *testing.T, path string, data []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func cloudRetentionRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloudRetentionHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
