//go:build linux && razvilka_native_fixture

package dataplane

import (
	"fmt"
	"syscall"
)

// The original Wait goroutine publishes state before closing done. Never inspect
// ProcessState until that join signal; never print child output, PID or errors.
func mihomoLiveSidecarExitSummary(n *mihomoLiveSidecar) (available bool, exitCode, signal int) {
	if n == nil || n.self != n || !n.started {
		return false, 0, 0
	}
	select {
	case <-n.done:
	default:
		return false, 0, 0
	}
	if n.state == nil {
		return false, 0, 0
	}
	status, ok := n.state.Sys().(syscall.WaitStatus)
	if !ok {
		return false, 0, 0
	}
	if status.Signaled() {
		return true, n.state.ExitCode(), int(status.Signal())
	}
	return true, n.state.ExitCode(), 0
}

func mihomoLiveSidecarExitDiagnostic(n *mihomoLiveSidecar) {
	available, code, signal := mihomoLiveSidecarExitSummary(n)
	fmt.Printf("actual_mihomo_sidecar_exit available=%t exit_code=%d signal=%d\n", available, code, signal)
}
