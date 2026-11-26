package strategylab

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func closedCompatibilityCommand(t *testing.T, base, candidate []string, dry bool) []string {
	t.Helper()
	command := []string{"--intercept=0"}
	if dry {
		command = append([]string{"--dry-run"}, command...)
	}
	command = append(command, base...)
	command = append(command, candidate...)
	if !dry {
		assertions, err := compatibilityAssertions(base, candidate)
		if err != nil {
			t.Fatal(err)
		}
		command = append(command, "--lua-init="+assertions)
	}
	return command
}

func TestCompatibilityClosedMatchesValidatorCommands(t *testing.T) {
	base := compatibilityBase(t.TempDir())
	candidate := []string{"--filter-tcp=443", "--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}
	before := slices.Clone(base)
	var phases []string
	var commands [][]string
	stop := errors.New("argument capture ends before native compatibility")
	v := CompatibleValidator{Binary: "command-shape-only", BaseArguments: base, TrustedAssets: true, Provider: compatibilityProviderFunc(func(_ context.Context, _ string, command ...string) (CompatibilityCompletion, error) {
		phase, err := compatibilityCommandPhase(base, command)
		if err != nil {
			return CompatibilityCompletion{Quiescent: true}, err
		}
		phases = append(phases, phase)
		commands = append(commands, slices.Clone(command))
		// This is an argument-generation test double, not a native fixture.
		// The second phase always rejects; no compatibility PASS is fabricated.
		if phase == "lua-init" {
			return CompatibilityCompletion{Started: true, Quiescent: true}, stop
		}
		return CompatibilityCompletion{Started: true, Quiescent: true}, nil
	})}
	result := v.Validate(context.Background(), candidate)
	if result.OK || result.Native || result.LuaChecked || result.QuiescenceUnknown || result.Code != "COMPATIBILITY_REJECTED" || !slices.Equal(phases, []string{"dry-run", "lua-init"}) {
		t.Fatalf("argument capture acquired native authority: result=%+v phases=%v", result, phases)
	}
	if !slices.Equal(base, before) || !slices.Equal(commands[0], closedCompatibilityCommand(t, base, candidate, true)) || !slices.Equal(commands[1], closedCompatibilityCommand(t, base, candidate, false)) {
		t.Fatal("validator command shape or immutable base changed")
	}
}

func TestCompatibilityClosedAcceptsTokenLimitAndSpacedBasePath(t *testing.T) {
	base := compatibilityBase(filepath.Join(t.TempDir(), "reviewed assets"))
	candidate := slices.Repeat([]string{"--lua-desync=fake:blob=0x00000000"}, 96)
	for _, dry := range []bool{true, false} {
		command := closedCompatibilityCommand(t, base, candidate, dry)
		before := slices.Clone(command)
		want := "lua-init"
		if dry {
			want = "dry-run"
		}
		phase, err := compatibilityCommandPhase(base, command)
		if err != nil || phase != want || !slices.Equal(command, before) {
			t.Fatalf("valid argv/base path rejected or changed: phase=%q err=%v", phase, err)
		}
	}
}

func TestCompatibilityClosedRejectsProviderBypass(t *testing.T) {
	base := compatibilityBase(t.TempDir())
	candidate := []string{"--filter-tcp=443", "--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}
	lua := closedCompatibilityCommand(t, base, candidate, false)
	dry := closedCompatibilityCommand(t, base, candidate, true)
	final := lua[len(lua)-1]
	withCandidate := func(args ...string) []string {
		command := append([]string{"--intercept=0"}, base...)
		command = append(command, args...)
		return append(command, final)
	}
	replace := func(command []string, index int, value string) []string {
		copy := slices.Clone(command)
		copy[index] = value
		return copy
	}
	remove := func(command []string, index int) []string {
		copy := slices.Clone(command)
		return append(copy[:index], copy[index+1:]...)
	}
	reordered := slices.Clone(lua)
	reordered[1], reordered[2] = reordered[2], reordered[1]
	checks := strings.Split(strings.TrimPrefix(final, "--lua-init="), ";")
	slices.Reverse(checks)
	cases := []struct {
		name    string
		command []string
	}{
		{"nil", nil},
		{"all-empty", []string{"", "", ""}},
		{"no-intercept", lua[1:]},
		{"intercept-one", replace(lua, 0, "--intercept=1")},
		{"intercept-space", replace(lua, 0, "--intercept=0 ")},
		{"duplicate-dry-run", append([]string{"--dry-run"}, dry...)},
		{"dry-run-out-of-order", append([]string{"--intercept=0", "--dry-run"}, lua[1:]...)},
		{"altered-base", replace(lua, 1, "--lua-init=@"+filepath.Join(t.TempDir(), "zapret-lib.lua"))},
		{"reordered-base", reordered},
		{"missing-base", remove(lua, 1)},
		{"extra-base", withCandidate(append(slices.Clone(base[:1]), candidate...)...)},
		{"empty-candidate", withCandidate()},
		{"empty-candidate-token", withCandidate(append(slices.Clone(candidate), "")...)},
		{"comment-candidate-token", withCandidate(append(slices.Clone(candidate), "#ignored")...)},
		{"packed-candidate-token", withCandidate(strings.Join(candidate, " "))},
		{"quoted-token", withCandidate("--filter-tcp=443", "\"--lua-desync=circular:fails=2:time=300\"", candidate[2])},
		{"escaped-token", withCandidate(candidate[0], candidate[1], "--lua-desync=fake:blob=tls_client\\hello")},
		{"candidate-dry-run", withCandidate(append(slices.Clone(candidate), "--dry-run")...)},
		{"candidate-intercept", withCandidate(append(slices.Clone(candidate), "--intercept=0")...)},
		{"extra-runtime", withCandidate(append(slices.Clone(candidate), "--daemon")...)},
		{"custom-lua-file", withCandidate(append(slices.Clone(candidate), "--lua-init=@/reviewed/custom.lua")...)},
		{"custom-lua-function", withCandidate("--lua-desync=luaexec")},
		{"empty-filter-value", withCandidate("--filter-tcp=", candidate[1], candidate[2])},
		{"only-data-filter", withCandidate("--filter-tcp=443")},
		{"extra-final-runtime", append(slices.Clone(lua), "--dry-run")},
		{"missing-assertions", lua[:len(lua)-1]},
		{"assertion-tamper", replace(lua, len(lua)-1, final+";os.exit(0)")},
		{"assertion-spacing", replace(lua, len(lua)-1, strings.Replace(final, "assert(", "assert (", 1))},
		{"assertion-reorder", replace(lua, len(lua)-1, "--lua-init="+strings.Join(checks, ";"))},
		{"assertion-duplicate", append(slices.Clone(lua), final)},
		{"dry-run-with-assertions", append(slices.Clone(dry), final)},
		{"too-many-candidate-arguments", withCandidate(slices.Repeat([]string{candidate[2]}, 97)...)},
		{"oversized-candidate-token", withCandidate("--lua-desync=fake:host=" + strings.Repeat("a", 8193))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.command)
			phase, err := compatibilityCommandPhase(base, tc.command)
			if err == nil || phase != "" {
				t.Fatalf("provider bypass accepted as %q: %v", phase, tc.command)
			}
			if !slices.Equal(tc.command, before) {
				t.Fatal("rejected command was modified")
			}
		})
	}
}

func TestCompatibilityClosedChecksBaseWithoutGrantingTrust(t *testing.T) {
	base := compatibilityBase(t.TempDir())
	candidate := []string{"--lua-desync=circular:fails=2:time=300", "--lua-desync=fake:blob=tls_clienthello"}
	cases := []struct {
		name string
		base []string
	}{
		{"nil", nil},
		{"empty-token", []string{""}},
		{"relative-lua", append([]string{"--lua-init=@zapret-lib.lua"}, base[1:]...)},
		{"custom-lua", append(slices.Clone(base), "--lua-init=@"+filepath.Join(t.TempDir(), "custom.lua"))},
		{"inline-lua", append(slices.Clone(base), "--lua-init=assert(true)")},
		{"runtime", append(slices.Clone(base), "--intercept=0")},
		{"relative-blob", append(slices.Clone(base[:3]), "--blob=tls_clienthello:@tls_clienthello.bin")},
		{"custom-blob", append(slices.Clone(base[:3]), "--blob=custom:@"+filepath.Join(t.TempDir(), "custom.bin"))},
		{"missing-lib", slices.Clone(base[1:])},
		{"missing-auto", append(slices.Clone(base[:2]), base[3:]...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The command repeats even the invalid base exactly, so equality
			// alone cannot replace the existing reviewed-assets grammar.
			command := append([]string{"--dry-run", "--intercept=0"}, tc.base...)
			command = append(command, candidate...)
			phase, err := compatibilityCommandPhase(tc.base, command)
			if err == nil || phase != "" {
				t.Fatalf("invalid immutable base accepted as %q", phase)
			}
		})
	}
}
