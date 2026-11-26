package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/installpath"
)

// The early helper accepts an invocation identity only. Trusted startup
// settings select the existing owner/control roots; the producer revalidates
// persisted intent and Stop authority before any process effect.
func runNFQWSManagedProcessCommand(args []string, supervise func(string, string, string) int) int {
	if len(args) != 1 || len(args[0]) != 32 || strings.Trim(args[0], "0123456789abcdef") != "" || supervise == nil {
		return 2
	}
	base := getenv("RAZVILKA_DATAPLANE_STATE", installpath.State+"/dataplane")
	if strings.TrimSpace(base) != base {
		return 3
	}
	state, err := filepath.Abs(filepath.Join(base, "runtime", "nfqws2"))
	if err != nil {
		return 3
	}
	f, err := configuredSelfUpdateFiles(os.Getenv("RAZVILKA_SELF_UPDATE_INSTALLATION"), os.Getenv("RAZVILKA_SELF_UPDATE_FILE_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_HELPER_STATE"), os.Getenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE"))
	if err != nil {
		return 3
	}
	return supervise(args[0], state, f.ControlRoot)
}
