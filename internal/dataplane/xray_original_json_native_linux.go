//go:build linux

package dataplane

import (
	"io"
	"os"
	"os/exec"
	"syscall"
)

// Construction only, no Start or Wait. Both original resource publishers use
// this after their independent typed/source/admission checks. An extensionless
// regular FD path is not supported by Xray's native file loader, so the exact
// authored config is stdin and remains independently observable as FD0/FD4.
func xrayHeldJSONCommand(binary, directory string, executable, config *os.File, log io.Writer) (*exec.Cmd, error) {
	if executable == nil || config == nil {
		return nil, errXraySelectedTCPRuntime
	}
	if _, err := config.Seek(0, 0); err != nil {
		return nil, err
	}
	return &exec.Cmd{Path: "/proc/self/fd/3", Args: []string{binary, "run", "-format", "json", "-config", "stdin:"}, Dir: directory, Env: xraySelectedTCPNativeEnvironment(), ExtraFiles: []*os.File{executable, config}, Stdin: config, Stdout: log, Stderr: log, SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}, nil
}
