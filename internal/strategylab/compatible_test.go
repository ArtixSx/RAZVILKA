package strategylab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func compatibilityBase(root string) []string {
	return []string{"--lua-init=@" + filepath.Join(root, "zapret-lib.lua"), "--lua-init=@" + filepath.Join(root, "zapret-antidpi.lua"), "--lua-init=@" + filepath.Join(root, "zapret-auto.lua"), "--blob=tls_clienthello:@" + filepath.Join(root, "tls_clienthello.bin")}
}

func TestCompatibilityDryRunDoesNotProveLua(t *testing.T) {
	base := compatibilityBase(t.TempDir())
	arguments := []string{"--filter-tcp=443", "--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}
	calls := [][]string{}
	v := CompatibleValidator{Binary: "reviewed-nfqws2", BaseArguments: base, TrustedAssets: true, Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(calls) == 2 {
			return []byte("Lua syntax error"), errors.New("exit 1")
		}
		return []byte("command line parameters verified"), nil
	}}
	before := append([]string(nil), base...)
	result := v.Validate(context.Background(), arguments)
	if result.OK || result.LuaChecked || len(calls) != 2 || calls[0][0] != "--dry-run" || calls[0][1] != "--intercept=0" || calls[1][0] != "--intercept=0" || !reflect.DeepEqual(base, before) {
		t.Fatalf("dry-run was promoted or options mutated: %+v calls=%v", result, calls)
	}
	check := calls[1][len(calls[1])-1]
	for _, expected := range []string{"type(circular)=='function'", "type(fake)=='function'", "type(tls_clienthello)=='string'"} {
		if !strings.Contains(check, expected) {
			t.Fatalf("missing compatibility assertion %q: %s", expected, check)
		}
	}
}

func TestCompatibilityRejectsUnsupportedInterceptBeforeInitializingLua(t *testing.T) {
	calls := 0
	v := CompatibleValidator{Binary: "nfqws2", TrustedAssets: true, BaseArguments: compatibilityBase(t.TempDir()), Run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
		calls++
		return []byte("unknown option intercept"), errors.New("exit 1")
	}}
	result := v.Validate(context.Background(), []string{"--lua-desync=fake:blob=0x00000000"})
	if result.OK || result.LuaChecked || calls != 1 {
		t.Fatalf("unsupported binary initialized Lua: %+v calls=%d", result, calls)
	}
}

func TestCompatibilityRequiresReviewedDataOnlyBase(t *testing.T) {
	for _, kind := range []string{"untrusted", "custom-lua", "runtime", "missing-auto", "inline", "manual"} {
		t.Run(kind, func(t *testing.T) {
			v := CompatibleValidator{Binary: "nfqws2", TrustedAssets: true, BaseArguments: compatibilityBase(t.TempDir()), Run: func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("unsafe base executed")
				return nil, nil
			}}
			args := []string{"--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}
			switch kind {
			case "untrusted":
				v.TrustedAssets = false
			case "custom-lua":
				v.BaseArguments = append(v.BaseArguments, "--lua-init=@"+filepath.Join(t.TempDir(), "custom.lua"))
			case "runtime":
				v.BaseArguments = append(v.BaseArguments, "--intercept=1")
			case "missing-auto":
				v.BaseArguments = append(v.BaseArguments[:2], v.BaseArguments[3:]...)
			case "inline":
				v.BaseArguments = append(v.BaseArguments, "--lua-init=reboot()")
			case "manual":
				args = []string{"--lua-desync=luaexec:code=reboot()"}
			}
			if result := v.Validate(context.Background(), args); result.OK || result.LuaChecked {
				t.Fatalf("unsafe validation passed: %+v", result)
			}
		})
	}
}

// This opt-in fixture never creates NFQUEUE/firewall rules or starts a service.
// The coordinator supplies a genuine binary and a reviewed upstream Lua tree.
func TestNFQWSNativeCompatibilityNoIntercept(t *testing.T) {
	binary, root := os.Getenv("RAZVILKA_NFQWS_NATIVE_BINARY"), os.Getenv("RAZVILKA_NFQWS_NATIVE_ASSETS")
	if binary == "" || root == "" {
		t.Skip("opt-in genuine NFQWS2 binary and reviewed assets required")
	}
	if !filepath.IsAbs(binary) || !filepath.IsAbs(root) {
		t.Fatal("native fixture requires absolute paths")
	}
	args := []string{"--filter-tcp=443", "--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}
	v := CompatibleValidator{Binary: binary, BaseArguments: compatibilityBase(root), TrustedAssets: true}
	result := v.Validate(context.Background(), args)
	if !result.OK || !result.Native || !result.LuaChecked {
		t.Fatalf("genuine installed options/assets rejected: %+v", result)
	}
	// Disposable, publicly traversable directory: nfqws2 drops privilege. Do
	// not widen permissions of a user's data or of the supplied installed tree.
	fixture, err := os.MkdirTemp("", "razvilka-nfqws-compat-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(fixture); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(fixture, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua", "tls_clienthello.bin"} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	v.BaseArguments = compatibilityBase(fixture)
	for _, content := range []string{"this is not Lua syntax !", "-- valid Lua, but fake is missing\n"} {
		if err := os.WriteFile(filepath.Join(fixture, "zapret-antidpi.lua"), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		result := v.Validate(context.Background(), args)
		if result.OK || result.LuaChecked {
			t.Fatalf("broken/missing Lua passed genuine initialization: %+v", result)
		}
	}
	if err := os.Remove(filepath.Join(fixture, "tls_clienthello.bin")); err != nil {
		t.Fatal(err)
	}
	if result := v.Validate(context.Background(), args); result.OK {
		t.Fatalf("missing blob passed: %+v", result)
	}
}
