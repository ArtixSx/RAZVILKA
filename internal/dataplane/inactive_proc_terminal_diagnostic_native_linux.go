//go:build linux && razvilka_native_fixture

package dataplane

// Documentary reasons from the original failed Terminal observation only.
// No PID, argv, path, raw stat, new read, retry or terminal permission.
func inactiveProcTerminalRefused(h *linuxInactiveProcPID, reason string) bool {
	if h == nil || h.pass == nil {
		return false
	}
	switch reason {
	case "process-terminal-invalid", "process-terminal-self", "process-terminal-observed-dead", "process-terminal-observed-multithread-zombie",
		"process-terminal-named-not-gone", "process-terminal-gone-closing", "process-terminal-read", "process-terminal-parse",
		"process-terminal-unbound-birth", "process-terminal-birth-changed", "process-terminal-live-state", "process-terminal-multithread-zombie",
		"process-terminal-identity-closing", "process-terminal-zombie-closing",
		"process-terminal-pf-exiting", "process-terminal-no-pf-exiting", "process-terminal-state-running", "process-terminal-state-sleeping",
		"process-terminal-state-disk-wait", "process-terminal-state-stopped", "process-terminal-state-dead", "process-terminal-state-other":
		_ = mihomoSameBootNativeFailure(h.pass.ctx, reason, ErrProxyRuntimeInactive)
	}
	return false
}

// The same already-read stat image, inspected only in the native diagnostic
// build before its existing clear. PF_EXITING is NOT terminal permission:
// exit_mm can precede release of descriptors/sockets and thread-group teardown.
func inactiveProcTerminalExiting(raw []byte, pid int) bool {
	_, flags, _, err := proxyInactiveProcStat(raw, pid)
	return err == nil && flags&0x4 != 0
}

func inactiveProcTerminalLiveRefused(h *linuxInactiveProcPID, state byte, exiting bool) bool {
	inactiveProcTerminalRefused(h, "process-terminal-live-state")
	if exiting {
		inactiveProcTerminalRefused(h, "process-terminal-pf-exiting")
	} else {
		inactiveProcTerminalRefused(h, "process-terminal-no-pf-exiting")
	}
	switch state {
	case 'R':
		inactiveProcTerminalRefused(h, "process-terminal-state-running")
	case 'S':
		inactiveProcTerminalRefused(h, "process-terminal-state-sleeping")
	case 'D':
		inactiveProcTerminalRefused(h, "process-terminal-state-disk-wait")
	case 'T', 't':
		inactiveProcTerminalRefused(h, "process-terminal-state-stopped")
	case 'X', 'x':
		inactiveProcTerminalRefused(h, "process-terminal-state-dead")
	default:
		inactiveProcTerminalRefused(h, "process-terminal-state-other")
	}
	return false
}
