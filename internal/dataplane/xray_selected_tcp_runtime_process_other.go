//go:build !linux

package dataplane

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// The actual child can be joined on non-Linux hosts; Linux routing/process
// readback is never inferred from that terminal unit observation.
func xraySelectedTCPWaitResult(pid int, state *os.ProcessState, waitErr error) bool {
	if pid <= 1 || state == nil || state.Pid() != pid || !state.Exited() {
		return false
	}
	if waitErr == nil {
		return state.Success()
	}
	var exit *exec.ExitError
	return !state.Success() && errors.As(waitErr, &exit) && exit.ProcessState == state
}
func (*xraySelectedTCPProcess) observe(context.Context, *netidentity.Provider, netidentity.Identity) (xraySelectedTCPProcessObservation, error) {
	return xraySelectedTCPProcessObservation{}, errXraySelectedTCPRuntime
}
