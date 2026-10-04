package strategylab

import (
	"errors"
	"slices"
	"strings"
)

// compatibilityCommandPhase closes the provider's command surface to the two
// shapes emitted by CompatibleValidator. The immutable base is owner-supplied;
// accepting this grammar grants no binary/assets provenance or launch authority.
func compatibilityCommandPhase(base, command []string) (string, error) {
	phase, offset := "lua-init", 0
	if len(command) > 0 && command[0] == "--dry-run" {
		phase, offset = "dry-run", 1
	}
	if len(command) <= offset || command[offset] != "--intercept=0" {
		return "", errors.New("compatibility command requires its exact no-intercept prefix")
	}
	offset++
	if len(command)-offset < len(base) {
		return "", errors.New("compatibility command omits its immutable base")
	}
	if !slices.Equal(command[offset:offset+len(base)], base) {
		return "", errors.New("compatibility command changes its immutable base")
	}
	offset += len(base)
	end := len(command)
	if phase == "lua-init" {
		if end <= offset || !strings.HasPrefix(command[end-1], "--lua-init=") {
			return "", errors.New("compatibility Lua command requires final generated assertions")
		}
		end--
	}
	if end <= offset {
		return "", errors.New("compatibility command requires candidate arguments")
	}
	candidate := command[offset:end]
	if len(candidate) > 96 {
		return "", errors.New("compatibility command exceeds the candidate argument limit")
	}
	raw := strings.Join(candidate, " ")
	if ExportableArguments(raw) != nil {
		return "", errors.New("compatibility command contains unsupported candidate arguments")
	}
	// ExportableArguments parses text, so quoted, escaped, empty or packed argv
	// elements could otherwise disappear or change meaning during its check.
	parsed, err := parseArguments(raw)
	if err != nil || !slices.Equal(parsed, candidate) {
		return "", errors.New("compatibility candidate arguments are not exact data-only tokens")
	}
	assertions, err := compatibilityAssertions(base, candidate)
	if err != nil {
		return "", err
	}
	if phase == "lua-init" && command[len(command)-1] != "--lua-init="+assertions {
		return "", errors.New("compatibility command changes its generated Lua assertions")
	}
	return phase, nil
}
