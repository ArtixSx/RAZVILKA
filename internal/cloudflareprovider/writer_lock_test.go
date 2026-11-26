//go:build linux || windows

package cloudflareprovider

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWriterConcurrentImportsDoNotLoseAccounts(t *testing.T) {
	s, path := privateStore(t)
	const writers = 8
	stores := make([]*Store, writers)
	for n := range stores {
		other, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		stores[n] = other
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, writers)
	var wg sync.WaitGroup
	for n, other := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			input := bytes.ReplaceAll(usqueFixture(), []byte("private-device-marker"), []byte(fmt.Sprintf("synthetic-device-%d", n)))
			parsed, err := ParseImport(SourceUSQUE, input)
			if err != nil {
				results <- err
				return
			}
			for {
				_, err = other.ImportSnapshot(ctx, parsed)
				if !errors.Is(err, ErrBusy) {
					results <- err
					return
				}
				select {
				case <-ctx.Done():
					results <- ctx.Err()
					return
				case <-time.After(5 * time.Millisecond):
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	accounts, err := s.List(ctx)
	if err != nil || len(accounts) != writers {
		t.Fatalf("concurrent imports lost an account: count=%d error=%v", len(accounts), err)
	}
}

func TestWriterLockPersistsAndSerializesStoreInstances(t *testing.T) {
	s, path := privateStore(t)
	other, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	release, err := s.lockWrite(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	before, err := os.Stat(filepath.Join(path, writerLockFile))
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := ParseImport(SourceUSQUE, usqueFixture())
	if _, err := other.ImportSnapshot(context.Background(), parsed); !errors.Is(err, ErrBusy) {
		t.Fatalf("second store ignored active writer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.ImportSnapshot(ctx, parsed); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("same store ignored cancellation: %v", err)
	}
	// Older binaries use O_EXCL and must not bypass the new protocol.
	if file, err := os.OpenFile(filepath.Join(path, writerLockFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); !errors.Is(err, os.ErrExist) {
		if file != nil {
			_ = file.Close()
		}
		t.Fatalf("legacy writer not excluded: %v", err)
	}
	release()
	release = nil
	first, err := other.ImportSnapshot(context.Background(), parsed)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ImportSnapshot(context.Background(), parsed)
	if err != nil || second.ID != first.ID {
		t.Fatalf("handover/idempotence: %v", err)
	}
	marker, err := os.ReadFile(filepath.Join(path, writerLockFile))
	if err != nil || string(marker) != writerLockMarker {
		t.Fatal("protocol marker lost")
	}
	after, err := os.Stat(filepath.Join(path, writerLockFile))
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("handover replaced or rewrote the lock inode")
	}
}

func TestWriterPreservesUnknownAndIncompleteLocks(t *testing.T) {
	for _, marker := range []string{"", "foreign writer", writerLockMarker[:12], strings.Repeat("?", len(writerLockMarker)), writerLockMarker + "extra", strings.Repeat("x", 65536)} {
		t.Run(fmt.Sprintf("bytes-%d", len(marker)), func(t *testing.T) {
			s, path := privateStore(t)
			file := filepath.Join(path, writerLockFile)
			if err := os.WriteFile(file, []byte(marker), 0o600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			parsed, _ := ParseImport(SourceUSQUE, usqueFixture())
			if _, err := s.ImportSnapshot(context.Background(), parsed); !errors.Is(err, ErrBusy) {
				t.Fatalf("unrecognized marker accepted: %v", err)
			}
			after, err := os.Stat(file)
			if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
				t.Fatal("unknown lock metadata changed")
			}
			content, err := os.ReadFile(file)
			if err != nil || string(content) != marker {
				t.Fatal("unknown lock bytes changed")
			}
			if _, err := os.Stat(filepath.Join(path, storeFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unknown lock allowed store write")
			}
		})
	}
}

func TestWriterRejectsUnsafeLockTargets(t *testing.T) {
	for _, kind := range []string{"directory", "symlink", "public-permissions"} {
		t.Run(kind, func(t *testing.T) {
			s, path := privateStore(t)
			file := filepath.Join(path, writerLockFile)
			switch kind {
			case "directory":
				if err := os.Mkdir(file, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "foreign-lock")
				if err := os.WriteFile(target, []byte(writerLockMarker), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, file); err != nil {
					t.Skip("symlinks unavailable")
				}
				t.Cleanup(func() {
					content, err := os.ReadFile(target)
					if err != nil || string(content) != writerLockMarker {
						t.Error("symlink target changed")
					}
				})
			case "public-permissions":
				if runtime.GOOS == "windows" {
					t.Skip("POSIX permissions")
				}
				if err := os.WriteFile(file, []byte(writerLockMarker), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(file, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if release, err := s.lockWrite(context.Background()); !errors.Is(err, ErrBusy) {
				if release != nil {
					release()
				}
				t.Fatalf("unsafe lock accepted: %v", err)
			}
			if _, err := os.Lstat(file); err != nil {
				t.Fatal("unsafe lock removed")
			}
		})
	}
}

// The child deliberately keeps its writer handle open until the parent kills
// it. This is a real process-death test, not a deferred unlock simulation.
func TestWriterProcessHelper(t *testing.T) {
	if os.Getenv("RAZVILKA_WRITER_TEST_HELPER") != "1" {
		return
	}
	if len(os.Args) < 4 {
		t.Fatal("missing helper arguments")
	}
	path, phase := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	release, err := s.lockWrite(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	switch phase {
	case "before-commit":
		// Model a partial atomic-write temporary. It must never become live or
		// be indiscriminately deleted by a subsequent writer.
		file, err := s.root.OpenFile(".transaction-crash-fixture", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(`{"schema":`); err != nil {
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		defer file.Close()
	case "after-commit":
		doc, err := s.load()
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseImport(SourceWGCF, wgcfFixture())
		if err != nil {
			t.Fatal(err)
		}
		doc.Accounts = append(doc.Accounts, storedAccount{ID: "cf-" + strings.Repeat("a", 32), Kind: parsed.kind, Raw: parsed.raw, Digest: digest(parsed.raw), ImportedAt: time.Now().UTC()})
		if err := s.commit(context.Background(), doc); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown phase")
	}
	fmt.Println("WRITER_READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestWriterRecoversAfterProcessDeath(t *testing.T) {
	for _, phase := range []string{"before-commit", "after-commit"} {
		t.Run(phase, func(t *testing.T) {
			s, path := privateStore(t)
			ctx := context.Background()
			seed, _ := ParseImport(SourceUSQUE, usqueFixture())
			original, err := s.ImportSnapshot(ctx, seed)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(path, storeFile))
			if err != nil {
				t.Fatal(err)
			}
			lockBefore, err := os.Stat(filepath.Join(path, writerLockFile))
			if err != nil {
				t.Fatal(err)
			}
			processCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(processCtx, os.Args[0], "-test.run=^TestWriterProcessHelper$", "--", path, phase)
			cmd.Env = append(os.Environ(), "RAZVILKA_WRITER_TEST_HELPER=1")
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				_ = stdin.Close()
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			lines := bufio.NewScanner(stdout)
			if !lines.Scan() || lines.Text() != "WRITER_READY" {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				waited = true
				t.Fatalf("child not ready: %s", stderr.String())
			}
			candidate, _ := ParseImport(SourceWGCF, wgcfFixture())
			if _, err := s.ImportSnapshot(ctx, candidate); !errors.Is(err, ErrBusy) {
				t.Fatalf("other process not excluded: %v", err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err == nil {
				t.Fatal("child did not terminate abnormally")
			}
			waited = true
			current, err := os.ReadFile(filepath.Join(path, storeFile))
			if err != nil {
				t.Fatal(err)
			}
			if phase == "before-commit" && !bytes.Equal(before, current) {
				t.Fatal("partial write changed live state")
			}
			deadline := time.Now().Add(2 * time.Second)
			var added Account
			for {
				added, err = s.ImportSnapshot(ctx, candidate)
				if !errors.Is(err, ErrBusy) || time.Now().After(deadline) {
					break
				}
				time.Sleep(10 * time.Millisecond) // Windows may release killed handles asynchronously.
			}
			if err != nil {
				t.Fatalf("writer did not recover after process death: %v", err)
			}
			if phase == "after-commit" && added.ID != "cf-"+strings.Repeat("a", 32) {
				t.Fatal("committed account duplicated after crash")
			}
			again, err := s.ImportSnapshot(ctx, seed)
			if err != nil || again.ID != original.ID {
				t.Fatal("original account lost")
			}
			accounts, err := s.List(ctx)
			if err != nil || len(accounts) != 2 {
				t.Fatalf("unexpected recovered accounts: %v", err)
			}
			for _, account := range accounts {
				if account.Verification != "imported-unverified" {
					t.Fatal("recovery promoted verification")
				}
			}
			lockAfter, err := os.Stat(filepath.Join(path, writerLockFile))
			if err != nil || !os.SameFile(lockBefore, lockAfter) {
				t.Fatal("recovery replaced lock file")
			}
			if phase == "before-commit" {
				orphan, err := os.ReadFile(filepath.Join(path, ".transaction-crash-fixture"))
				if err != nil || string(orphan) != `{"schema":` {
					t.Fatal("unowned temporary removed or adopted")
				}
			}
		})
	}
}
