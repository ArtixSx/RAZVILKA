package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type stockNativeRunner struct {
	calls     int
	arguments []string
	mutate    func()
	err       error
}

func (r *stockNativeRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls++
	r.arguments = append([]string(nil), args...)
	if r.mutate != nil {
		r.mutate()
	}
	return []byte("command line parameters verified"), r.err
}

func stockNativeFixture(t *testing.T) (*Manager, *stockNativeRunner, string, []string) {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "opt")
	runner := &stockNativeRunner{}
	m := New()
	m.InitDir = filepath.Join(prefix, "etc", "init.d")
	m.InfoDir = filepath.Join(prefix, "lib", "opkg", "info")
	m.StateDir = filepath.Join(prefix, "razvilka", "components")
	m.Runner = runner
	init, err := os.ReadFile(filepath.Join("testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(m.InfoDir, "nfqws2-keenetic.control"):                "Package: nfqws2-keenetic\nVersion: 1.3.1\n",
		filepath.Join(m.InfoDir, "nfqws2-keenetic.list"):                   "/opt/etc/init.d/S51nfqws2\n/opt/etc/nfqws2/nfqws2.conf\n/opt/etc/nfqws2/lua/zapret-lib.lua.gz\n/opt/tmp/nfqws2_binary/nfqws2-aarch64\n",
		filepath.Join(m.InfoDir, "nfqws2-keenetic.postinst"):               `BINFILE="/opt/usr/bin/nfqws2"` + "\n" + `cp -f "/opt/tmp/nfqws2_binary/nfqws2-$ARCH" "$BINFILE"` + "\n",
		filepath.Join(m.InitDir, "S51nfqws2"):                              string(init),
		filepath.Join(prefix, "usr", "bin", "nfqws2"):                      "reviewed synthetic binary\n",
		filepath.Join(prefix, "etc", "nfqws2", "lua", "zapret-lib.lua.gz"): "reviewed synthetic compressed Lua\n",
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--lua-init=@" + filepath.Join(prefix, "etc", "nfqws2", "lua", "zapret-lib.lua"), "--filter-tcp=443", "--lua-desync=multisplit:pos=1,midsld"}
	return m, runner, prefix, args
}

func TestStockNFQWSNativeOwnerUsesRelocatedBinaryAndOneFixedDryRun(t *testing.T) {
	m, runner, _, args := stockNativeFixture(t)
	review, err := m.ReviewStockNFQWSNative(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	defer review.Close()
	args[1] = "--daemon"
	if err := review.DryRun(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 || !reflect.DeepEqual(runner.arguments[:2], []string{"--dry-run", "--intercept=0"}) || strings.Contains(strings.Join(runner.arguments, " "), "--daemon") {
		t.Fatal(runner.arguments)
	}
	if err := review.DryRun(context.Background()); err == nil || runner.calls != 1 {
		t.Fatal("review replayed")
	}
	if _, err := m.ReviewStockNFQWSNative(context.Background(), runner.arguments[2:]); err == nil {
		t.Fatal("original component writer was not retained")
	}
	if err := review.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := m.ReviewStockNFQWSNative(context.Background(), runner.arguments[2:])
	if err != nil {
		t.Fatal("writer not released", err)
	}
	second.Close()
}

func TestStockNFQWSNativeOwnerRevokesChangedOriginalMaterial(t *testing.T) {
	for _, which := range []string{"binary", "lua", "init", "metadata", "new-uncompressed-lua", "directory"} {
		t.Run(which, func(t *testing.T) {
			if which == "directory" && runtime.GOOS == "windows" {
				t.Skip("Windows prevents renaming the opened original directory")
			}
			m, runner, prefix, args := stockNativeFixture(t)
			review, err := m.ReviewStockNFQWSNative(context.Background(), args)
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			path := map[string]string{"binary": filepath.Join(prefix, "usr", "bin", "nfqws2"), "lua": filepath.Join(prefix, "etc", "nfqws2", "lua", "zapret-lib.lua.gz"), "init": filepath.Join(m.InitDir, "S51nfqws2"), "metadata": filepath.Join(m.InfoDir, "nfqws2-keenetic.control"), "new-uncompressed-lua": filepath.Join(prefix, "etc", "nfqws2", "lua", "zapret-lib.lua")}[which]
			if which == "directory" {
				dir := filepath.Join(prefix, "usr", "bin")
				if err := os.Rename(dir, dir+"-old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("foreign material\n"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := review.DryRun(context.Background()); err == nil || runner.calls != 0 {
				t.Fatal("changed material executed", err, runner.calls)
			}
		})
	}
}

func TestStockNFQWSNativeOwnerRejectsUnsupportedOrUnknownBeforeExecution(t *testing.T) {
	m, runner, prefix, args := stockNativeFixture(t)
	for _, arg := range []string{"--intercept=0", "--dry-run", "--daemon", "--lua-init=error('foreign')", "--lua-init=@/tmp/foreign.lua"} {
		if review, err := m.ReviewStockNFQWSNative(context.Background(), append(args, arg)); err == nil {
			review.Close()
			t.Fatalf("accepted %s", arg)
		}
		if runner.calls != 0 {
			t.Fatal("executed refusal")
		}
	}
	review, err := m.ReviewStockNFQWSNative(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	defer review.Close()
	runner.err = errors.New("native refused")
	if err := review.DryRun(context.Background()); err == nil || runner.calls != 1 {
		t.Fatal("native refusal accepted")
	}
	review.Close()
	control := filepath.Join(prefix, "lib", "opkg", "info", "nfqws2-keenetic.control")
	if err := os.WriteFile(control, []byte("Package: nfqws2-keenetic\nVersion: 9.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReviewStockNFQWSNative(context.Background(), args); !errors.Is(err, ErrStockNFQWSVersion) {
		t.Fatal("unsupported wrapper was not explicit", err)
	}
	if err := os.WriteFile(control, []byte("Package: nfqws2-keenetic\nVersion: 1.3.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.InitDir, "S51nfqws2"), []byte("#!/bin/sh\n# edited stock init\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReviewStockNFQWSNative(context.Background(), args); !errors.Is(err, ErrStockNFQWSInit) {
		t.Fatal("unrecognized init was not explicit", err)
	}
}
