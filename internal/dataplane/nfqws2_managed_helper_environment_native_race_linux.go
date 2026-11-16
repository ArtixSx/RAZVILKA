//go:build linux && razvilka_native_fixture && race

package dataplane

import (
	"os"
	"slices"
	"strings"
)

// Diagnostic only: Go's race runtime defaults to a 1000ms exit sleep, equal to
// the unchanged original helper join grace. This opt-in removes ONLY that test
// runtime delay, before the same Cmd.Start. Race detection and its default exit
// status 66 remain enabled; original Wait/ECHILD/ACK and cleanup are mandatory.
// No inherited GORACE string or other caller-controlled option reaches helper.
func nfqws2ManagedHelperEnvironment(original []string) ([]string, error) {
	switch os.Getenv("RAZVILKA_NATIVE_RACE_HELPER_EXIT") {
	case "":
		return original, nil
	case "0":
		for _, entry := range original {
			if strings.HasPrefix(entry, "GORACE=") {
				return nil, ErrNFQWSManagedProcessUnknown
			}
		}
		return append(slices.Clone(original), "GORACE=atexit_sleep_ms=0"), nil
	default:
		return nil, ErrNFQWSManagedProcessUnknown
	}
}
