package strategylab

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type compatibilityProviderFunc func(context.Context, string, ...string) (CompatibilityCompletion, error)

func (f compatibilityProviderFunc) Run(ctx context.Context, binary string, args ...string) (CompatibilityCompletion, error) {
	return f(ctx, binary, args...)
}

func compatibilityBase(root string) []string {
	return []string{"--lua-init=@" + filepath.Join(root, "zapret-lib.lua"), "--lua-init=@" + filepath.Join(root, "zapret-antidpi.lua"), "--lua-init=@" + filepath.Join(root, "zapret-auto.lua"), "--blob=tls_clienthello:@" + filepath.Join(root, "tls_clienthello.bin")}
}

func TestCompatibilityDryRunDoesNotProveLua(t *testing.T) {
	base := compatibilityBase(t.TempDir())
	arguments := []string{"--filter-tcp=443", "--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}
	calls := [][]string{}
	v := CompatibleValidator{Binary: "reviewed-nfqws2", BaseArguments: base, TrustedAssets: true, Provider: compatibilityProviderFunc(func(_ context.Context, _ string, args ...string) (CompatibilityCompletion, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(calls) == 2 {
			return CompatibilityCompletion{Output: []byte("Lua syntax error"), Started: true, Quiescent: true}, errors.New("exit 1")
		}
		return CompatibilityCompletion{Output: []byte("command line parameters verified"), Started: true, Quiescent: true}, nil
	})}
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
	v := CompatibleValidator{Binary: "nfqws2", TrustedAssets: true, BaseArguments: compatibilityBase(t.TempDir()), Provider: compatibilityProviderFunc(func(_ context.Context, _ string, _ ...string) (CompatibilityCompletion, error) {
		calls++
		return CompatibilityCompletion{Output: []byte("unknown option intercept"), Started: true, Quiescent: true}, errors.New("exit 1")
	})}
	result := v.Validate(context.Background(), []string{"--lua-desync=fake:blob=0x00000000"})
	if result.OK || result.LuaChecked || calls != 1 {
		t.Fatalf("unsupported binary initialized Lua: %+v calls=%d", result, calls)
	}
}

func TestCompatibilityRequiresReviewedDataOnlyBase(t *testing.T) {
	for _, kind := range []string{"untrusted", "custom-lua", "runtime", "missing-auto", "inline", "manual"} {
		t.Run(kind, func(t *testing.T) {
			v := CompatibleValidator{Binary: "nfqws2", TrustedAssets: true, BaseArguments: compatibilityBase(t.TempDir()), Provider: compatibilityProviderFunc(func(context.Context, string, ...string) (CompatibilityCompletion, error) {
				t.Fatal("unsafe base executed")
				return CompatibilityCompletion{}, nil
			})}
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
	selected := os.Getenv("RAZVILKA_NFQWS_NATIVE_CASE")
	dry, expectExitError := false, false
	switch selected {
	case "dry-run":
		dry = true
	case "lua-init":
	case "lua-syntax", "missing-function":
		expectExitError = true
	case "missing-blob":
		dry, expectExitError = true, true
	default:
		t.Fatal("select exactly one reviewed native case: dry-run/lua-init/lua-syntax/missing-function/missing-blob")
	}
	args := []string{"--filter-tcp=443", "--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}
	v := CompatibleValidator{Binary: binary, BaseArguments: compatibilityBase(root), TrustedAssets: true}
	result := v.Validate(context.Background(), args)
	if result.OK || result.Native || result.LuaChecked || result.Code != "SUPERVISION_REQUIRED" {
		t.Fatalf("plain native process was accepted without supervision: %+v", result)
	}
	if expectExitError {
		// Only this selected case gets a disposable, publicly traversable tree:
		// nfqws2 drops privilege. The supplied installed tree stays untouched.
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
		var mutationErr error
		switch selected {
		case "lua-syntax":
			mutationErr = os.WriteFile(filepath.Join(fixture, "zapret-antidpi.lua"), []byte("this is not Lua syntax !"), 0644)
		case "missing-function":
			mutationErr = os.WriteFile(filepath.Join(fixture, "zapret-antidpi.lua"), []byte("-- valid Lua, but fake is missing\n"), 0644)
		case "missing-blob":
			mutationErr = os.Remove(filepath.Join(fixture, "tls_clienthello.bin"))
		}
		if mutationErr != nil {
			t.Fatal(mutationErr)
		}
		v.BaseArguments = compatibilityBase(fixture)
	}
	assertions, err := compatibilityAssertions(v.BaseArguments, args)
	if err != nil {
		t.Fatal(err)
	}
	command := []string{"--intercept=0"}
	if dry {
		command = append([]string{"--dry-run"}, command...)
	}
	command = append(command, v.BaseArguments...)
	command = append(command, args...)
	if !dry {
		command = append(command, "--lua-init="+assertions)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	provider := &CompatibilityProcessProvider{}
	completion, err := provider.Run(ctx, binary, command...)
	var exitError *exec.ExitError
	if !completion.Started || completion.Quiescent || !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || errors.As(err, &exitError) != expectExitError || ctx.Err() != nil {
		t.Fatalf("native exit/fence mismatch: completion=%+v err=%v", completion, err)
	}
	// Exactly one invocation per explicit coordinator run. A subsequent case
	// requires external cleanup review; a fresh provider cannot supply proof.
	if replay, err := provider.Run(context.Background(), binary); replay.Started || !errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
		t.Fatal("native fixture bypassed unknown fence")
	}
}
