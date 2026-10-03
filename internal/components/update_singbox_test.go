package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type singBoxRollbackRunner struct{ *singBoxPackageRunner }

func (r singBoxRollbackRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(args) == 4 && args[0] == "install" && args[1] == "--force-downgrade" {
		r.calls = append(r.calls, strings.Join(args, " "))
		r.installed = strings.Split(filepath.Base(args[3]), "_")[1]
		return []byte("old package unpacked"), os.WriteFile(filepath.Join(r.initDir, singBoxInitName), []byte(singBoxInitFixture), 0o755)
	}
	return r.singBoxPackageRunner.Run(ctx, name, args...)
}

func managedSingBoxFixture(t *testing.T) (*Manager, *singBoxPackageRunner) {
	t.Helper()
	m, r := singBoxManagerFixture(t)
	m.InfoDir = t.TempDir()
	r.installed = "1.13.3-2"
	m.Runner = singBoxRollbackRunner{r}
	if err := os.WriteFile(filepath.Join(m.InitDir, singBoxInitName), []byte(strings.Replace(singBoxInitFixture, "ENABLED=yes", "ENABLED=no", 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.rollbackDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.rollbackDir(), "sing-box-go_1.13.3-2_all.ipk"), []byte("old package fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	return m, r
}

func checkSingBoxRollback(m *Manager, r *singBoxPackageRunner) func(context.Context) error {
	return func(context.Context) error {
		if r.installed != "1.13.3-2" {
			return errors.New("candidate rejected")
		}
		data, err := os.ReadFile(filepath.Join(m.InitDir, singBoxInitName))
		if err != nil || !strings.Contains(string(data), "ENABLED=no") {
			return errors.New("package rollback enabled global Sing-box init")
		}
		return nil
	}
}

func TestManagedSingBoxRollbackDisablesReinstalledPackageAutostart(t *testing.T) {
	m, r := managedSingBoxFixture(t)
	_, err := m.ManagedUpdate(context.Background(), "sing-box", checkSingBoxRollback(m, r))
	if !errors.Is(err, ErrRollbackVerified) {
		t.Fatalf("rollback init not verified: %v", err)
	}
	state, pending, err := m.PendingManagedUpdate()
	if err != nil || pending || state.Phase != UpdateRolledBack {
		t.Fatalf("rollback not complete: %+v %v", state, err)
	}
}

func TestManagedSingBoxFailedUpgradeKeepsUnknownFenceAndDisablesInit(t *testing.T) {
	m, r := managedSingBoxFixture(t)
	r.fail = true
	_, err := m.ManagedUpdate(context.Background(), "sing-box", allowRecovery)
	if !errors.Is(err, ErrUpdateUnknown) || !errors.Is(err, ErrRollbackUnconfirmed) {
		t.Fatalf("partial package outcome not unknown: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(m.InitDir, singBoxInitName))
	if err != nil || !strings.Contains(string(data), "ENABLED=no") {
		t.Fatal("interrupted unpack left global init enabled", err)
	}
	for _, call := range r.calls {
		if strings.HasPrefix(call, "install --force") {
			t.Fatal("unknown upgrade automatically retried as rollback")
		}
	}
}

func TestManagedSingBoxInitInterruptionRecoversWithoutPackageReplay(t *testing.T) {
	for _, point := range []string{"before:rollback-init", "after:rollback-init"} {
		t.Run(strings.ReplaceAll(point, ":", "-"), func(t *testing.T) {
			m, r := managedSingBoxFixture(t)
			m.updateFault = func(current string) error {
				if current == point {
					panic("interrupted")
				}
				return nil
			}
			func() {
				defer func() {
					if recover() != "interrupted" {
						t.Fatal("interruption not reached")
					}
				}()
				_, _ = m.ManagedUpdate(context.Background(), "sing-box", checkSingBoxRollback(m, r))
			}()
			fresh := restartedManager(m)
			fresh.InitDir = m.InitDir
			state, pending, err := fresh.PendingManagedUpdate()
			if err != nil || !pending || state.Phase != UpdateRestoreAfter {
				t.Fatalf("init interruption not retained: %+v %v", state, err)
			}
			installs := 0
			for _, call := range r.calls {
				if strings.HasPrefix(call, "install --force") {
					installs++
				}
			}
			_, err = fresh.RecoverManagedUpdate(context.Background(), ManagedRecoveryRequest{Component: "sing-box", TransactionID: state.TransactionID, Action: "rollback"}, allowRecovery, checkSingBoxRollback(fresh, r))
			if err != nil {
				t.Fatal(err)
			}
			after := 0
			for _, call := range r.calls {
				if strings.HasPrefix(call, "install --force") {
					after++
				}
			}
			if installs != 1 || after != 1 {
				t.Fatalf("rollback package was replayed around init recovery: before=%d after=%d", installs, after)
			}
		})
	}
}
