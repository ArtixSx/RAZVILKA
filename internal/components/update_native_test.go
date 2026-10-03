package components

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This opt-in integration test executes the supplied native opkg binary. The
// package manager always receives an explicit disposable offline root and a
// local-only feed; no system package database or production config is used.
// It tests real package scripts/config migration, not physical power failure.
type nativeOpkgRunner struct{ config, root string }

func (r nativeOpkgRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(r.root) || r.root == "/" {
		return nil, fmt.Errorf("unsafe native opkg test root")
	}
	prefix := []string{"--conf", r.config, "--offline-root", r.root, "--force-postinstall"}
	return exec.CommandContext(ctx, name, append(prefix, args...)...).CombinedOutput()
}

func TestNativeOpkgManagedUpdateJournal(t *testing.T) {
	if os.Getenv("RAZVILKA_NATIVE_OPKG_TEST") != "1" {
		t.Skip("opt-in native opkg integration; use scripts/test-component-update-native.sh")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("native opkg integration requires Linux")
	}
	opkg, err := exec.LookPath(os.Getenv("RAZVILKA_TEST_OPKG"))
	if err != nil {
		t.Fatal("RAZVILKA_TEST_OPKG must name a native opkg binary", err)
	}
	if _, err := exec.LookPath("ar"); err != nil {
		t.Fatal("native package fixture requires ar", err)
	}
	for _, interrupted := range []bool{false, true} {
		t.Run(fmt.Sprintf("interrupt-%v", interrupted), func(t *testing.T) {
			work := t.TempDir()
			root, feed := filepath.Join(work, "root"), filepath.Join(work, "feed")
			for _, dir := range []string{root, feed, filepath.Join(work, "info")} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			oldPackage := nativeFixturePackage(t, work, "1.0.0")
			newPackage := nativeFixturePackage(t, feed, "2.0.0")
			data, err := os.ReadFile(newPackage)
			if err != nil {
				t.Fatal(err)
			}
			index := fmt.Sprintf("Package: nfqws2-keenetic\nVersion: 2.0.0\nArchitecture: all\nMaintainer: RAZVILKA test\nDescription: isolated journal fixture\nFilename: %s\nSize: %d\nMD5Sum: %x\nSHA256sum: %x\n\n", filepath.Base(newPackage), len(data), md5.Sum(data), sha256.Sum256(data))
			if err := os.WriteFile(filepath.Join(feed, "Packages"), []byte(index), 0o600); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(work, "opkg.conf")
			text := "dest root /\nlists_dir ext /var/lib/opkg/lists\narch all 1\nsrc fixture file://" + filepath.ToSlash(feed) + "\n"
			if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			runner := nativeOpkgRunner{config: config, root: root}
			if out, err := runner.Run(context.Background(), opkg, "install", oldPackage); err != nil {
				t.Fatalf("native install: %v\n%s", err, out)
			}
			conf := filepath.Join(root, "etc", "nfqws2.conf")
			if data, err := os.ReadFile(conf); err != nil || string(data) != "MIGRATED BY NATIVE PACKAGE\n" {
				t.Fatalf("native postinst did not execute inside offline root: %q %v", data, err)
			}
			if err := os.WriteFile(conf, []byte("USER STRATEGIES\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			// Production opkg uses absolute paths. Translate its fixture conffile
			// path to the disposable root for the application's snapshot layer.
			if err := os.WriteFile(filepath.Join(work, "info", "nfqws2-keenetic.conffiles"), []byte(conf+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			m := &Manager{Opkg: opkg, Runner: runner, StateDir: filepath.Join(work, "state"), RepoDir: filepath.Join(work, "repo"), InfoDir: filepath.Join(work, "info"), Client: offlineReleases()}
			if err := os.MkdirAll(m.rollbackDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			oldBytes, err := os.ReadFile(oldPackage)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.rollbackDir(), filepath.Base(oldPackage)), oldBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			check := func(context.Context) error {
				data, err := os.ReadFile(conf)
				if err != nil || string(data) != "USER STRATEGIES\n" {
					return fmt.Errorf("native package migrated user configuration")
				}
				return nil
			}
			if interrupted {
				m.updateFault = func(point string) error {
					if point == "after:upgrade-command" {
						panic("native interruption boundary")
					}
					return nil
				}
				func() {
					defer func() {
						if recover() != "native interruption boundary" {
							t.Fatal("native upgrade never reached interruption")
						}
					}()
					_, _ = m.ManagedUpdate(context.Background(), "nfqws2", check)
				}()
				fresh := restartedManager(m)
				state, pending, err := fresh.PendingManagedUpdate()
				if err != nil || !pending || state.Phase != UpdateStarted {
					t.Fatalf("native interrupted journal: %+v %v %v", state, pending, err)
				}
				if _, err := fresh.ManagedUpdate(context.Background(), "nfqws2", check); err == nil {
					t.Fatal("native upgrade was replayed")
				}
				versions, err := fresh.installedPackageVersions(context.Background())
				if err != nil || versions["nfqws2-keenetic"] != "2.0.0" {
					t.Fatalf("native durable readback: %v %v", versions, err)
				}
			} else {
				_, err := m.ManagedUpdate(context.Background(), "nfqws2", check)
				if !strings.Contains(fmt.Sprint(err), "rolled back to 1.0.0") {
					t.Fatalf("native rollback not verified: %v", err)
				}
				fresh := restartedManager(m)
				state, pending, err := fresh.PendingManagedUpdate()
				if err != nil || pending || state.Phase != UpdateRolledBack || check(context.Background()) != nil {
					t.Fatalf("native rollback persistence: %+v %v %v", state, pending, err)
				}
			}
		})
	}
}

func nativeFixturePackage(t *testing.T, directory, version string) string {
	t.Helper()
	build := filepath.Join(directory, "build-"+version)
	if err := os.MkdirAll(build, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTar := func(name string, entries map[string]string) {
		f, err := os.Create(filepath.Join(build, name))
		if err != nil {
			t.Fatal(err)
		}
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		for path, data := range entries {
			mode := int64(0o644)
			if path == "./postinst" {
				mode = 0o755
			}
			if err := tw.WriteHeader(&tar.Header{Name: path, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(data)); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	control := fmt.Sprintf("Package: nfqws2-keenetic\nVersion: %s\nArchitecture: all\nMaintainer: RAZVILKA test\nDescription: isolated native journal fixture\n", version)
	postinst := "#!/bin/sh\nset -eu\n[ -n \"${IPKG_INSTROOT:-}\" ] && [ \"$IPKG_INSTROOT\" != / ] || exit 99\nprintf 'MIGRATED BY NATIVE PACKAGE\\n' > \"$IPKG_INSTROOT/etc/nfqws2.conf\"\n"
	writeTar("control.tar.gz", map[string]string{"./control": control, "./conffiles": "/etc/nfqws2.conf\n", "./postinst": postinst})
	writeTar("data.tar.gz", map[string]string{"./etc/nfqws2.conf": "FACTORY CONFIG\n"})
	if err := os.WriteFile(filepath.Join(build, "debian-binary"), []byte("2.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "nfqws2-keenetic_"+version+"_all.ipk")
	cmd := exec.Command("ar", "rc", path, "debian-binary", "control.tar.gz", "data.tar.gz")
	cmd.Dir = build
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture ipk: %v %s", err, out)
	}
	return path
}
