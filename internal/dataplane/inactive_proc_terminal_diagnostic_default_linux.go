//go:build linux && !razvilka_native_fixture

package dataplane

// Ordinary builds do not inspect a context or record diagnostic state.
func inactiveProcTerminalRefused(*linuxInactiveProcPID, string) bool { return false }

func inactiveProcTerminalExiting([]byte, int) bool { return false }

func inactiveProcTerminalLiveRefused(*linuxInactiveProcPID, byte, bool) bool { return false }
