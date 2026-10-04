package strategylab

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// CompatibleValidator checks reviewed installed Lua with interception disabled.
// Dry-run alone never establishes Lua compatibility. TrustedAssets is granted
// by the component owner after provenance/ownership review, not by a browser.
// Installed Lua can execute code even with intercept=0, so arbitrary local
// expert scripts must not be passed here. No runtime assets or network rules
// are changed; a supervised provider persists its private execution receipts.
type CompatibleValidator struct {
	Binary        string
	BaseArguments []string
	TrustedAssets bool
	Timeout       time.Duration
	Provider      CompatibilityProvider
}

// InstalledBaseArguments snapshots the local data without evaluating shell.
// It grants no provenance trust; pass the same immutable copy to validator and
// probe executor only after the component owner's review.
func InstalledBaseArguments() ([]string, error) {
	base := installedBaseArguments()
	if _, err := compatibilityAssertions(base, []string{"--lua-desync=fake:blob=0x00000000"}); err != nil {
		return nil, err
	}
	return append([]string(nil), base...), nil
}

func (v CompatibleValidator) Validate(parent context.Context, arguments []string) (result Validation) {
	result = Validation{Arguments: append([]string(nil), arguments...), CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if parent.Err() != nil {
		result.Code = "VALIDATION_CANCELLED"
		return result
	}
	if !v.TrustedAssets {
		result.Code = "ASSET_REVIEW_REQUIRED"
		return result
	}
	// All accepted arguments are unquoted tokens in this data-only grammar.
	if ExportableArguments(strings.Join(arguments, " ")) != nil {
		result.Code = "MANUAL_STRATEGY_REQUIRED"
		return result
	}
	base := v.BaseArguments
	if base == nil {
		base = installedBaseArguments()
	}
	assertions, err := compatibilityAssertions(base, arguments)
	if err != nil {
		result.Code, result.Output = "ASSETS_INCOMPATIBLE", err.Error()
		return result
	}
	binary := strings.TrimSpace(v.Binary)
	if binary == "" {
		binary = findNFQWS2()
	}
	if binary == "" {
		result.Code = "NFQWS2_NOT_INSTALLED"
		return result
	}
	if v.Provider == nil {
		// The existing package supervisor is opkg/transaction-only. Do not
		// forge that authority or launch Lua through plain CommandContext.
		result.Code = "SUPERVISION_REQUIRED"
		return result
	}
	timeout := v.Timeout
	if timeout <= 0 || timeout > ProbeTimeout {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	run := func(args []string) (CompatibilityCompletion, error) {
		type response struct {
			completion CompatibilityCompletion
			err        error
		}
		done := make(chan response, 1)
		go func() {
			completion, err := v.Provider.Run(ctx, binary, args...)
			done <- response{completion: completion, err: err}
		}()
		var returned response
		select {
		case returned = <-done:
		case <-ctx.Done():
			timer := time.NewTimer(compatibilityCleanupWait)
			defer timer.Stop()
			select {
			case returned = <-done:
			case <-timer.C:
				result.QuiescenceUnknown = true
				return CompatibilityCompletion{}, errors.Join(ErrCompatibilityQuiescenceUnknown, ctx.Err())
			}
		}
		completion, err := returned.completion, returned.err
		if !completion.Quiescent || errors.Is(err, ErrCompatibilityQuiescenceUnknown) {
			result.QuiescenceUnknown = true
			return completion, errors.Join(ErrCompatibilityQuiescenceUnknown, err)
		}
		if err == nil && !completion.Started {
			return completion, errors.New("provider returned success without an executed command")
		}
		return completion, err
	}
	// Dry-run comes first: upstream treats unknown options differently outside
	// dry-run. Test intercept=0 support before permitting Lua initialization.
	args := append([]string{"--dry-run", "--intercept=0"}, base...)
	args = append(args, arguments...)
	completion, err := run(args)
	if err == nil && ctx.Err() == nil {
		args = append([]string{"--intercept=0"}, base...)
		args = append(args, arguments...)
		args = append(args, "--lua-init="+assertions)
		completion, err = run(args)
	}
	result.Output = shortProbeText(string(completion.Output))
	if result.QuiescenceUnknown {
		result.Code = "QUIESCENCE_UNKNOWN"
		return result
	}
	if ctx.Err() != nil {
		result.Code = "VALIDATION_CANCELLED"
		return result
	}
	if err != nil {
		result.Code = "COMPATIBILITY_REJECTED"
		if result.Output == "" {
			result.Output = shortProbeText(err.Error())
		}
		return result
	}
	result.OK, result.Native, result.LuaChecked, result.Code = true, true, true, "COMPATIBLE"
	return result
}

func compatibilityAssertions(base, arguments []string) (string, error) {
	loaded := map[string]bool{}
	for _, arg := range base {
		key, value, found := strings.Cut(arg, "=")
		if !found {
			return "", fmt.Errorf("unsupported base option %q", key)
		}
		switch key {
		case "--lua-init":
			if !strings.HasPrefix(value, "@") || !filepath.IsAbs(value[1:]) {
				return "", fmt.Errorf("base Lua must be an absolute reviewed file")
			}
			switch filepath.Base(value[1:]) {
			case "zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua":
				loaded[filepath.Base(value[1:])] = true
			default:
				return "", fmt.Errorf("custom Lua stays manual")
			}
		case "--blob":
			name, file, ok := strings.Cut(value, ":@")
			if !ok || !filepath.IsAbs(file) {
				return "", fmt.Errorf("blob must be an absolute reviewed file")
			}
			switch name {
			case "tls_clienthello", "quic_initial", "http_fake", "wireguard_initiation":
			default:
				return "", fmt.Errorf("custom blob stays manual")
			}
		default:
			return "", fmt.Errorf("runtime base option %q is forbidden", key)
		}
	}
	if !loaded["zapret-lib.lua"] || !loaded["zapret-antidpi.lua"] {
		return "", fmt.Errorf("reviewed zapret-lib.lua and zapret-antidpi.lua required")
	}
	checks := []string{}
	seen := map[string]bool{}
	check := func(name, kind string) {
		if !seen[name] {
			checks = append(checks, fmt.Sprintf("assert(type(%s)=='%s','missing %s')", name, kind, name))
			seen[name] = true
		}
	}
	for _, arg := range arguments {
		value, ok := strings.CutPrefix(arg, "--lua-desync=")
		if !ok {
			continue
		}
		fields := strings.Split(value, ":")
		if (fields[0] == "circular" || fields[0] == "autocircular") && !loaded["zapret-auto.lua"] {
			return "", fmt.Errorf("adaptive orchestrator requires zapret-auto.lua")
		}
		check(fields[0], "function")
		for _, field := range fields[1:] {
			key, val, _ := strings.Cut(field, "=")
			if (key == "blob" || key == "seqovl_pattern") && val != "0x00000000" {
				check(val, "string")
			}
		}
	}
	if len(checks) == 0 {
		return "", fmt.Errorf("adaptive strategy must invoke a reviewed Lua function")
	}
	return strings.Join(checks, ";"), nil
}
