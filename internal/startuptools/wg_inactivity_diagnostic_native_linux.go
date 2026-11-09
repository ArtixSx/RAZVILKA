//go:build linux && razvilka_native_fixture

package startuptools

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// Diagnostic only: the ordinary producer has already joined the real child and
// completed its source checks. Neither output nor exit status grants absence.
func wgInactivityNativeDiagnostic(args []string, stdout, stderr *output, commandErr, scopeErr error) {
	mode := os.Getenv("RAZVILKA_NFQWS_NEVER_ISSUED_NATIVE")
	if mode != "intent" && mode != "settlement-sync" || commandErr == nil {
		return
	}
	// This fixture needs only failed complete numeric table reads. Never emit
	// generic WG commands, tool diagnostics or arbitrary command arguments.
	i := 0
	for i < len(args) && (args[i] == "-N" || args[i] == "-details" || args[i] == "-4" || args[i] == "-6" || args[i] == "-j") {
		i++
	}
	if len(args)-i != 4 || args[i] != "route" || args[i+1] != "show" || args[i+2] != "table" {
		return
	}
	table, parseErr := strconv.Atoi(args[i+3])
	if parseErr != nil || table < 1 || table > 252 || strconv.Itoa(table) != args[i+3] {
		return
	}
	exit := -1
	if actual, ok := commandErr.(*exec.ExitError); ok && actual.ProcessState != nil {
		exit = actual.ExitCode()
	}
	clip := func(data []byte) []byte {
		if len(data) > 256 {
			return data[:256]
		}
		return data
	}
	fmt.Fprintf(os.Stderr, "actual_wg_inactivity_read args=%q exit=%d scope_ok=%t stdout=%q stderr=%q stdout_bytes=%d stderr_bytes=%d overflow=%t\n", args, exit, scopeErr == nil, clip(stdout.data), clip(stderr.data), len(stdout.data), len(stderr.data), stdout.overflow || stderr.overflow)
}
