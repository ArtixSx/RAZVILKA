//go:build linux

package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// A runner fixture, not genuine Main/HTTP future-update acceptance. Only the
// private temporary root is written, and no production /opt path is touched.
func ordinaryNativeRunnerImage(t *testing.T) (string, string, string) {
	t.Helper()
	if os.Geteuid() != 0 || checkRootOwnedPath("/root") != nil {
		t.Skip("isolated root-owned native runner fixture requires /root")
	}
	base, err := os.MkdirTemp("/root", "razvilka-ordinary-runner-")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(base) != "/root" || !strings.HasPrefix(filepath.Base(base), "razvilka-ordinary-runner-") {
		t.Fatal("unexpected private fixture root")
	}
	t.Cleanup(func() {
		if filepath.Dir(base) == "/root" && strings.HasPrefix(filepath.Base(base), "razvilka-ordinary-runner-") {
			if err := os.RemoveAll(base); err != nil {
				t.Error(err)
			}
		}
	})
	shell, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(shell)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "sh")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	return base, path, digestBytes(data)
}

func TestNativeOrdinaryImageCommandRevocationJoinsActualChild(t *testing.T) {
	base, path, sha := ordinaryNativeRunnerImage(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pidPath := filepath.Join(base, "child.pid")
	var child int
	starts, afters := 0, 0
	revoked := errors.New("original fixture owner revoked")
	started := time.Now()
	_, err := ordinaryImageCommand(ctx, path, sha, []string{"-c", `printf '%s\n' "$$" > "$1"; exec sleep 30`, "fixture", pidPath}, "ordinary-prepare-check", func(c context.Context, effect string, begin func() error) error {
		if c.Err() != nil || effect != "ordinary-prepare-check" {
			return errOrdinaryPreparation
		}
		starts++
		return begin()
	}, func() error { return nil }, func() error {
		data, err := os.ReadFile(pidPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		child, err = strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || child <= 1 {
			return errOrdinaryPreparation
		}
		return revoked
	}, func() error { afters++; return nil })
	if !errors.Is(err, revoked) || starts != 1 || afters != 0 || child <= 1 || time.Since(started) > 3*time.Second {
		t.Fatal("revocation did not join original Start/Wait", err, starts, afters, child)
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(child, &status, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Fatal("original Wait was not consumed", err)
	}
	if err := syscall.Kill(child, 0); err != syscall.ESRCH {
		t.Fatal("joined child remains active", err)
	}
}

func TestNativeOrdinaryImageCommandRejectsReplacedHeldPathBeforeStart(t *testing.T) {
	base, path, sha := ordinaryNativeRunnerImage(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(base, "replacement")
	if err := os.WriteFile(replacement, data, 0700); err != nil {
		t.Fatal(err)
	}
	checks, starts := 0, 0
	_, err = ordinaryImageCommand(ctx, path, sha, []string{"-c", "exit 0"}, "ordinary-prepare-check", func(context.Context, string, func() error) error { starts++; return nil }, func() error {
		checks++
		if checks == 2 {
			return os.Rename(replacement, path)
		}
		return nil
	}, func() error { return nil }, func() error { return nil })
	if err == nil || starts != 0 || checks != 2 {
		t.Fatal("same-byte replaced inode admitted Start", err, starts, checks)
	}
}

func TestNativeOrdinaryAutonomyProvesCurrentProtectedSidecar(t *testing.T) {
	base, _, _ := ordinaryNativeRunnerImage(t)
	candidate := filepath.Join(base, "autonomy-check.bin")
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, data, 0700); err != nil {
		t.Fatal(err)
	}
	sha := digestBytes(data)
	config := filepath.Join(base, "etc/razvilka/config.json")
	sidecar := config + ".automation.json.autonomy.json"
	if err := os.MkdirAll(filepath.Dir(config), 0700); err != nil {
		t.Fatal(err)
	}
	adapter := &SelfUpdateFileAdapter{installation: base, owned: checkRootOwnedPath}
	for _, tc := range []struct {
		name, content string
		wantedStarts  int
		wantErr       bool
	}{
		{name: "missing"},
		{name: "late-compatible-source", content: "fixture-compatible-autonomy", wantedStarts: 1},
		{name: "incompatible-source", content: "fixture-incompatible-autonomy", wantedStarts: 1, wantErr: true},
		{name: "unexpected-reply", content: "fixture-extra-output", wantedStarts: 1, wantErr: true},
		{name: "same-byte-replacement-during-admission", content: "fixture-compatible-autonomy", wantErr: true},
		{name: "foreign-config", content: "fixture-compatible-autonomy", wantErr: true},
		{name: "symbolic-link", content: "fixture-compatible-autonomy", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.content != "" {
				t.Cleanup(func() {
					if err := os.Remove(sidecar); err != nil {
						t.Error(err)
					}
				})
				if tc.name == "symbolic-link" {
					target := filepath.Join(base, "foreign-sidecar")
					if err := os.WriteFile(target, []byte(tc.content), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, sidecar); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(sidecar, []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfgPath := config
			if tc.name == "foreign-config" {
				cfgPath += ".other"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			starts := 0
			err := adapter.checkOrdinaryAutonomy(ctx, cfgPath, candidate, sha, func(c context.Context, effect string, begin func() error) error {
				if c.Err() != nil || effect != ordinaryAutonomyEffect {
					return errOrdinaryPreparation
				}
				if tc.name == "same-byte-replacement-during-admission" {
					newSidecar := sidecar + ".next"
					if err := os.WriteFile(newSidecar, []byte(tc.content), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(newSidecar, sidecar); err != nil {
						t.Fatal(err)
					}
				}
				err := begin()
				if err == nil {
					starts++
				}
				return err
			}, func() error { return nil })
			if starts != tc.wantedStarts || tc.wantErr != errors.Is(err, errOrdinaryAutonomy) || !tc.wantErr && err != nil {
				t.Fatal("unexpected sidecar compatibility outcome", starts, err)
			}
			if tc.content != "" {
				data, err := os.ReadFile(sidecar)
				if err != nil || string(data) != tc.content {
					t.Fatal("compatibility probe changed retained sidecar", err)
				}
			}
		})
	}
}

func TestNativeOrdinaryAutonomyReleaseReaderUnderControlLease(t *testing.T) {
	release := os.Getenv("RAZVILKA_TEST_AUTONOMY_RELEASE_BINARY")
	if release == "" {
		t.Skip("release-reader check requires a native CLI binary from the tested checkout")
	}
	base, _, _ := ordinaryNativeRunnerImage(t)
	candidate := filepath.Join(base, "razvilka")
	data, err := os.ReadFile(release)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, data, 0700); err != nil {
		t.Fatal(err)
	}
	sha := digestBytes(data)
	config := filepath.Join(base, "etc/razvilka/config.json")
	if err := os.MkdirAll(filepath.Dir(config), 0700); err != nil {
		t.Fatal(err)
	}
	policy := autonomy.Default()
	policy.PreferredRoutes = []string{"usque"}
	policy.AllowInitialMASQUERegistration = true
	sidecar := config + ".automation.json.autonomy.json"
	image, err := json.Marshal(map[string]any{"schema": 1, "owner": "razvilka-autonomy-v1", "policy": policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sidecar, image, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	control := filepath.Join(base, "control")
	ready, err := operationgate.InitializeSelfUpdateControl(ctx, control)
	if err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef0123456789abcdef"
	starts := 0
	admit := func(c context.Context, effect string, begin func() error) error {
		return operationgate.WithSelfUpdateEffectAdmission(c, control, id, ready.InstallationID, ready.Sequence, effect, func() error {
			starts++
			return begin()
		})
	}
	current := func() error {
		found, present, err := operationgate.ReadSelfUpdateStop(ctx, control)
		if err != nil || !present || found.Stopped || found.Sequence != ready.Sequence || found.InstallationID != ready.InstallationID {
			return operationgate.ErrSelfUpdateStopChanged
		}
		return nil
	}
	a := &SelfUpdateFileAdapter{installation: base, owned: checkRootOwnedPath}
	if err := a.checkOrdinaryAutonomy(ctx, config, candidate, sha, admit, current); err != nil || starts != 1 {
		t.Fatal("real candidate did not read saved consent under the original lease", starts, err)
	}
	entries, err := os.ReadDir(filepath.Dir(config))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(sidecar) {
		t.Fatal("real candidate created config or side effects", entries, err)
	}
	if _, err := operationgate.RequestSelfUpdateStop(ctx, control, id, 7); err != nil {
		t.Fatal(err)
	}
	if err := a.checkOrdinaryAutonomy(ctx, config, candidate, sha, admit, current); !errors.Is(err, operationgate.ErrSelfUpdateStopChanged) || starts != 1 {
		t.Fatal("retired control lease started a reader", starts, err)
	}
}
