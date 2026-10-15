package security

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestPrivateReplacementReportsDirectorySyncFailureAfterRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.json")
	if err := writePrivateFile(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected directory sync failure")
	calls := 0
	err := writePrivateFileWithSync(path, []byte("new"), func(root *ownedfs.Root) error {
		calls++
		data, err := root.ReadLimited("private.json", 16)
		if err != nil || string(data) != "new" {
			t.Fatalf("sync ran before completed rename: %q %v", data, err)
		}
		return injected
	})
	if !errors.Is(err, injected) || calls != 1 {
		t.Fatalf("sync failure was hidden: calls=%d err=%v", calls, err)
	}
	// A failed sync is an uncertain durable result, not a promise that the
	// rename was undone. The current process can already observe the new file.
	if data, err := os.ReadFile(path); err != nil || string(data) != "new" {
		t.Fatalf("post-rename image: %q %v", data, err)
	}
	if err := writePrivateFile(path, []byte("retry")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary transaction leaked: %v %v", entries, err)
	}
}

func TestPrivateReplacementDoesNotSyncOrChangeTargetAfterRenameRefusal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "retained"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := writePrivateFileWithSync(path, []byte("new"), func(*ownedfs.Root) error { called = true; return nil })
	if err == nil || called {
		t.Fatalf("rename refusal reported success or reached directory sync: %v %v", err, called)
	}
	if data, err := os.ReadFile(filepath.Join(path, "retained")); err != nil || string(data) != "old" {
		t.Fatalf("target changed: %q %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed transaction leaked: %v %v", entries, err)
	}
}

func TestCredentialSetupDoesNotConfirmAnUnsyncedRename(t *testing.T) {
	dir, now := t.TempDir(), time.Unix(1_800_000_000, 0)
	g := rememberedGate(t, dir, now)
	injected := errors.New("injected credential directory sync failure")
	g.privateDirSync = func(*ownedfs.Root) error { return injected }
	token, err := g.Setup("admin", "correct-horse-battery-staple")
	if !errors.Is(err, injected) || token != "" || !g.SetupRequired() {
		t.Fatalf("setup acknowledged unsynced credentials: token=%t setup=%t err=%v", token != "", g.SetupRequired(), err)
	}
	// The rename happened even though durability could not be confirmed.
	// Reopening real files must accept their actual state, not an invented rollback.
	restarted := rememberedGate(t, dir, now)
	if restarted.SetupRequired() {
		t.Fatal("restart did not observe the credential rename")
	}
	if _, err := restarted.Login("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
}

func persistenceSession(t *testing.T) (*Gate, string, string, time.Time) {
	t.Helper()
	dir, now := t.TempDir(), time.Unix(1_800_000_000, 0)
	g := rememberedGate(t, dir, now)
	if _, err := g.Setup("admin", "correct-horse-battery-staple"); err != nil {
		t.Fatal(err)
	}
	token, err := g.LoginRemembered("admin", "correct-horse-battery-staple", true)
	if err != nil {
		t.Fatal(err)
	}
	return g, token, dir, now
}

func TestRememberedLogoutRequiresDirectorySyncAndCanRetry(t *testing.T) {
	g, token, dir, now := persistenceSession(t)
	injected := errors.New("injected directory sync failure")
	g.privateDirSync = func(*ownedfs.Root) error { return injected }
	if err := g.Logout(sessionRequest(token)); !errors.Is(err, injected) {
		t.Fatalf("logout acknowledged unsynced rename: %v", err)
	}
	if !g.Authenticated(sessionRequest(token)) {
		t.Fatal("failed logout lost the retryable session")
	}
	// This checks a process restart's observed file, not power-loss behavior.
	if rememberedGate(t, dir, now).Authenticated(sessionRequest(token)) {
		t.Fatal("restart did not see the completed rename")
	}
	g.privateDirSync = nil
	if err := g.Logout(sessionRequest(token)); err != nil {
		t.Fatal(err)
	}
	if g.Authenticated(sessionRequest(token)) || rememberedGate(t, dir, now).Authenticated(sessionRequest(token)) {
		t.Fatal("successful retry did not revoke the session")
	}
}

func TestRememberedBatchRevocationRequiresDirectorySync(t *testing.T) {
	g, token, _, _ := persistenceSession(t)
	ordinary, err := g.Login("admin", "correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected directory sync failure")
	g.privateDirSync = func(*ownedfs.Root) error { return injected }
	if count, err := g.RevokeOtherSessions(sessionRequest(ordinary)); !errors.Is(err, injected) || count != 0 {
		t.Fatalf("revocation acknowledged unsynced rename: count=%d err=%v", count, err)
	}
	if !g.Authenticated(sessionRequest(token)) {
		t.Fatal("failed revocation lost the retryable session")
	}
	g.privateDirSync = nil
	if _, err := g.RevokeOtherSessions(sessionRequest(ordinary)); err != nil {
		t.Fatal(err)
	}
	if g.Authenticated(sessionRequest(token)) {
		t.Fatal("successful retry did not revoke the session")
	}
}

func TestPasswordRevocationFallbackRequiresSyncedRemoval(t *testing.T) {
	for _, failRemovalSync := range []bool{false, true} {
		t.Run(strconv.FormatBool(failRemovalSync), func(t *testing.T) {
			g, token, dir, now := persistenceSession(t)
			injected := errors.New("injected directory sync failure")
			calls := 0
			g.privateDirSync = func(root *ownedfs.Root) error {
				calls++
				if calls == 1 {
					return syncPrivateDirectory(root) // Credential replacement.
				}
				if calls == 2 || failRemovalSync {
					return injected
				}
				if _, err := os.Stat(g.sessionsPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("fallback synced before removal: %v", err)
				}
				return syncPrivateDirectory(root)
			}
			fresh, err := g.ChangePassword("correct-horse-battery-staple", "replacement-long-passphrase", sessionRequest(token))
			if calls != 3 {
				t.Fatalf("credential, rewrite and removal were not all synced: calls=%d", calls)
			}
			if failRemovalSync {
				if !errors.Is(err, injected) || fresh != "" {
					t.Fatalf("unsynced fallback reported success: token=%t err=%v", fresh != "", err)
				}
			} else if err != nil || fresh == "" {
				t.Fatalf("synced fallback did not succeed: %v", err)
			}
			restarted := rememberedGate(t, dir, now)
			if restarted.Authenticated(sessionRequest(token)) {
				t.Fatal("process restart resurrected the removed session file")
			}
			if _, err := restarted.Login("admin", "replacement-long-passphrase"); err != nil {
				t.Fatal("credential replacement was not readable after restart", err)
			}
		})
	}
}

// A child process exits at the persistence boundary. This exercises reopening
// real credential/session files, without claiming to simulate power loss.
func TestRememberedRevocationProcessExitBoundary(t *testing.T) {
	if dir := os.Getenv("RAZVILKA_SECURITY_PERSIST_CHILD"); dir != "" {
		now := time.Unix(1_800_000_000, 0)
		g := rememberedGate(t, dir, now)
		g.privateDirSync = func(root *ownedfs.Root) error {
			if os.Getenv("RAZVILKA_SECURITY_PERSIST_SYNC") == "1" {
				if err := syncPrivateDirectory(root); err != nil {
					t.Fatal(err)
				}
			}
			os.Exit(68)
			return nil
		}
		_ = g.Logout(sessionRequest(os.Getenv("RAZVILKA_SECURITY_PERSIST_TOKEN")))
		t.Fatal("child did not reach the rename/sync boundary")
	}
	for _, synced := range []string{"0", "1"} {
		t.Run("directory-synced-"+synced, func(t *testing.T) {
			_, token, dir, now := persistenceSession(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestRememberedRevocationProcessExitBoundary$")
			cmd.Env = append(os.Environ(), "RAZVILKA_SECURITY_PERSIST_CHILD="+dir, "RAZVILKA_SECURITY_PERSIST_SYNC="+synced, "RAZVILKA_SECURITY_PERSIST_TOKEN="+token)
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 68 {
				t.Fatalf("child did not exit at boundary: %v %s", err, bytes.TrimSpace(output))
			}
			if rememberedGate(t, dir, now).Authenticated(sessionRequest(token)) {
				t.Fatal("process restart did not observe the completed rename")
			}
		})
	}
}
