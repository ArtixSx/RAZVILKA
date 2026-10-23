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
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

type stockNativeRunner struct {
	calls     int
	arguments []string
	mutate    func()
	err       error
}

func TestStockNFQWSNativeOwnerRecognizesOnlyExactDeterministicGuardedInit(t *testing.T) {
	m, runner, _, args := stockNativeFixture(t)
	path := filepath.Join(m.InitDir, "S51nfqws2")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := engineconfig.NFQWSFirstStartInit(original, "0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"marker-only", "one-guard-changed", "extra-command", "duplicate-marker"} {
		t.Run(which, func(t *testing.T) {
			changed := string(guarded)
			switch which {
			case "marker-only":
				changed = string(original) + "# BEGIN RAZVILKA NFQWS2 TCP443 INIT v1\n# RAZVILKA INSTANCE 0123456789abcdef01234567\n# END RAZVILKA NFQWS2 TCP443 INIT v1\n"
			case "one-guard-changed":
				changed = strings.Replace(changed, `if [ -n "$UDP_PORTS" ]; then`, `if true; then`, 1)
			case "extra-command":
				changed += "\nexec /tmp/foreign\n"
			case "duplicate-marker":
				changed += "# BEGIN RAZVILKA NFQWS2 TCP443 INIT v1\n# RAZVILKA INSTANCE 0123456789abcdef01234567\n"
			}
			if err := os.WriteFile(path, []byte(changed), 0755); err != nil {
				t.Fatal(err)
			}
			if review, err := m.ReviewStockNFQWSNative(context.Background(), args); !errors.Is(err, ErrStockNFQWSInit) {
				if review != nil {
					review.Close()
				}
				t.Fatal("marker/edited init admitted", err)
			}
			if runner.calls != 0 {
				t.Fatal("refusal executed a command")
			}
		})
	}
	if err := os.WriteFile(path, guarded, 0755); err != nil {
		t.Fatal(err)
	}
	review, err := m.ReviewStockNFQWSNative(context.Background(), args)
	if err != nil {
		t.Fatal("genuine guarded init refused or refusal leaked writer", err)
	}
	defer review.Close()
	if err := review.DryRun(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 || !reflect.DeepEqual(runner.arguments[:2], []string{"--dry-run", "--intercept=0"}) {
		t.Fatal("guarded init changed parameter-check-only mode", runner.arguments)
	}
}

func TestStockNFQWSNativeOwnerRetainsActualGuardedBytesDuringDryRun(t *testing.T) {
	for _, phase := range []string{"before", "during"} {
		t.Run(phase, func(t *testing.T) {
			m, runner, _, args := stockNativeFixture(t)
			path := filepath.Join(m.InitDir, "S51nfqws2")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			guarded, err := engineconfig.NFQWSFirstStartInit(original, "0123456789abcdef01234567")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, guarded, 0755); err != nil {
				t.Fatal(err)
			}
			review, err := m.ReviewStockNFQWSNative(context.Background(), args)
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			// Both variants are individually known, but replacing the actual
			// captured guarded file cannot reuse its earlier review.
			mutate := func() {
				if err := os.WriteFile(path, original, 0755); err != nil {
					t.Fatal(err)
				}
			}
			wantCalls := 0
			if phase == "before" {
				mutate()
			} else {
				runner.mutate = mutate
				wantCalls = 1
			}
			if err := review.DryRun(context.Background()); err == nil || runner.calls != wantCalls {
				t.Fatal("changed original guarded bytes remained admitted", err, runner.calls)
			}
		})
	}
}

func TestStockNFQWSNativeOwnerCurrentIsOriginalWriterBoundAndRevocable(t *testing.T) {
	m, runner, prefix, args := stockNativeFixture(t)
	review, err := m.ReviewStockNFQWSNative(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	defer review.Close()
	if err := review.CheckCurrent(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 0 {
		t.Fatal("currentness executed a command")
	}
	if err := os.WriteFile(filepath.Join(prefix, "usr", "bin", "nfqws2"), []byte("foreign binary\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := review.CheckCurrent(context.Background()); err == nil {
		t.Fatal("retained review admitted a changed binary")
	}
	if err := review.Close(); err != nil {
		t.Fatal(err)
	}
	if err := review.CheckCurrent(context.Background()); err == nil {
		t.Fatal("closed review survived")
	}
}

func replaceStockNativeInit(t *testing.T, path string, data []byte) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := os.WriteFile(path, data, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
		return
	}
	stage := path + ".test-staged"
	if err := os.WriteFile(stage, data, info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(stage, path); err != nil {
		t.Fatal(err)
	}
}

func TestStockNFQWSNativeOwnerAllowsOnlyOwnedInitTransition(t *testing.T) {
	for _, which := range []string{"owned-init", "wrong-owner", "foreign-init", "changed-binary", "changed-lua"} {
		t.Run(which, func(t *testing.T) {
			m, runner, prefix, args := stockNativeFixture(t)
			path := filepath.Join(m.InitDir, "S51nfqws2")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			const owner = "0123456789abcdef01234567"
			guarded, err := engineconfig.NFQWSFirstStartInit(original, owner)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS == "windows" {
				// Windows will not replace an open init. Model recognition of
				// the already-guarded original here; Linux exercises both atomic
				// stock -> guarded -> stock inode transitions below.
				replaceStockNativeInit(t, path, guarded)
			}
			review, err := m.ReviewStockNFQWSNative(context.Background(), args)
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			if err := review.CheckCurrentWithOwnedInit(context.Background(), owner); err != nil {
				t.Fatal(err)
			}
			replaceStockNativeInit(t, path, guarded)
			switch which {
			case "wrong-owner":
				if err := review.CheckCurrentWithOwnedInit(context.Background(), "1123456789abcdef01234567"); err == nil {
					t.Fatal("owner rebound")
				}
				return
			case "foreign-init":
				replaceStockNativeInit(t, path, append(guarded, []byte("echo foreign\n")...))
			case "changed-binary":
				if err := os.WriteFile(filepath.Join(prefix, "usr", "bin", "nfqws2"), []byte("changed binary\n"), 0755); err != nil {
					t.Fatal(err)
				}
			case "changed-lua":
				if err := os.WriteFile(filepath.Join(prefix, "etc", "nfqws2", "lua", "zapret-lib.lua.gz"), []byte("changed Lua\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			err = review.CheckCurrentWithOwnedInit(context.Background(), owner)
			if (err == nil) != (which == "owned-init") {
				t.Fatal("init transition changed asset authority", which, err)
			}
			if runner.calls != 0 {
				t.Fatal("currentness executed command")
			}
			if which == "owned-init" && runtime.GOOS != "windows" {
				replaceStockNativeInit(t, path, original)
				if err := review.CheckCurrent(context.Background()); err != nil {
					t.Fatal("exact original restoration refused", err)
				}
			}
		})
	}
}

func TestStockNFQWSNativeOwnerPublicClosedReviewNeverRebindsAssets(t *testing.T) {
	m, runner, _, args := stockNativeFixture(t)
	args = append(args, "--hostlist-domains=selected.example")
	review, err := m.ReviewStockNFQWSNative(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	defer review.Close()
	stock, err := os.ReadFile(filepath.Join("..", "engineconfig", "testdata", "nfqws2-first-start-1.3.1.conf"))
	if err != nil {
		t.Fatal(err)
	}
	const owner = "0123456789abcdef01234567"
	closed, err := engineconfig.NFQWSFirstStartConfig(stock, owner, []string{"selected.example"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range [][]byte{closed, append(append([]byte(nil), closed...), []byte("touch /tmp/foreign\n")...), []byte("foreign")} {
		if err := review.ReviewClosedFirstStartParameters(context.Background(), config, owner); err == nil {
			t.Fatal("canonical /opt assets rebound to unrelated temporary captured paths")
		}
	}
	if runner.calls != 0 {
		t.Fatal("unreviewed closed parameters executed")
	}
}

func TestStockNFQWSNativeOwnerClosedParameterReviewUsesOriginalAssets(t *testing.T) {
	for _, which := range []string{"rollback-positive", "updated-exclusions", "missing-positive", "different-filter", "extra-udp", "different-recipe", "changed-binary"} {
		t.Run(which, func(t *testing.T) {
			m, runner, prefix, args := stockNativeFixture(t)
			args = append(args, "--hostlist-domains=new.example")
			review, err := m.ReviewStockNFQWSNative(context.Background(), args)
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			if err := review.DryRun(context.Background()); err != nil {
				t.Fatal(err)
			}
			runner.calls = 0
			candidate := append([]string(nil), args...)
			candidate[len(candidate)-1] = "--hostlist-domains=old.example"
			switch which {
			case "updated-exclusions":
				candidate = append(candidate, "--hostlist-exclude-domains=bank.example", "--ipset-exclude-ip=192.0.2.0/24")
			case "missing-positive":
				candidate = candidate[:len(candidate)-1]
			case "different-filter":
				candidate[1] = "--filter-tcp=80"
			case "extra-udp":
				candidate = append(candidate, "--filter-udp=443")
			case "different-recipe":
				candidate = append(candidate, "--lua-desync=circular:fails=2:time=300:retrans=3:nld=2")
			case "changed-binary":
				if err := os.WriteFile(filepath.Join(prefix, "usr", "bin", "nfqws2"), []byte("changed binary\n"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// Private relocated-source model: the public canonical compiler fixes
			// /opt assets, which must never be rebound to this temporary prefix.
			err = review.reviewClosedFirstStartArguments(ctx, candidate)
			allowed := which == "rollback-positive" || which == "updated-exclusions"
			if (err == nil) != allowed {
				t.Fatal(which, err)
			}
			if allowed {
				if runner.calls != 1 || !reflect.DeepEqual(runner.arguments[:2], []string{"--dry-run", "--intercept=0"}) || !strings.Contains(strings.Join(runner.arguments, " "), "--hostlist-domains=old.example") {
					t.Fatal("old exact parameters not checked", runner.arguments)
				}
			} else if runner.calls != 0 {
				t.Fatal("refused changes reached native command")
			}
		})
	}
}

func TestStockNFQWSNativeOwnerRecognizesRetiredInertBeforeNewOwner(t *testing.T) {
	for _, which := range []string{"new-owner", "stock-downgrade", "foreign-before"} {
		t.Run(which, func(t *testing.T) {
			m, runner, _, args := stockNativeFixture(t)
			path := filepath.Join(m.InitDir, "S51nfqws2")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			const beforeOwner = "0123456789abcdef01234567"
			const newOwner = "1123456789abcdef01234567"
			inert, err := engineconfig.NFQWSFirstStartInit(original, beforeOwner)
			if err != nil {
				t.Fatal(err)
			}
			if which == "foreign-before" {
				inert = append(inert, []byte("echo foreign\n")...)
			}
			if err := os.WriteFile(path, inert, 0755); err != nil {
				t.Fatal(err)
			}
			review, err := m.ReviewStockNFQWSNative(context.Background(), args)
			if which == "foreign-before" {
				if err == nil {
					review.Close()
					t.Fatal("former marker admitted foreign script")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer review.Close()
			if err := review.CheckCurrentWithOwnedInit(context.Background(), newOwner); err != nil {
				t.Fatal("exact retired inert before-image rejected", err)
			}
			if err := review.CheckCurrentWithOwnedInit(context.Background(), beforeOwner); err == nil {
				t.Fatal("new owner rebound to former owner")
			}
			if runtime.GOOS != "windows" {
				after := original
				if which == "new-owner" {
					after, err = engineconfig.NFQWSFirstStartInit(original, newOwner)
					if err != nil {
						t.Fatal(err)
					}
				}
				replaceStockNativeInit(t, path, after)
				err = review.CheckCurrent(context.Background())
				if (err == nil) != (which == "new-owner") {
					t.Fatal("retired owner transition widened script permission", which, err)
				}
			}
			if runner.calls != 0 {
				t.Fatal("recognition executed a command")
			}
		})
	}
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
