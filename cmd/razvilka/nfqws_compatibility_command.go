package main

import (
	"os"
	"path/filepath"
	"strings"
)

// The installed helper takes only the private invocation ID. Its configured
// StrategyLab/control paths locate the real saved command; they supply no
// candidate, assets, permission or successful compatibility result.
func runNFQWSCompatibilityCommand(args []string, supervise func(string, string, string) int) int {
	if len(args) != 1 || len(args[0]) != 32 || strings.Trim(args[0], "0123456789abcdef") != "" || supervise == nil {
		return 2
	}
	state := getenv("RAZVILKA_STRATEGY_LAB_STATE", "/opt/var/lib/razvilka/strategy-lab.json")
	if !filepath.IsAbs(state) || filepath.Clean(state) != state || strings.TrimSpace(state) != state || strings.ContainsAny(state, "\x00\r\n") {
		return 3
	}
	files, err := configuredSelfUpdateFiles(os.Getenv("RAZVILKA_SELF_UPDATE_INSTALLATION"), os.Getenv("RAZVILKA_SELF_UPDATE_FILE_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_HELPER_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE"))
	if err != nil {
		return 3
	}
	return supervise(args[0], state, files.ControlRoot)
}
