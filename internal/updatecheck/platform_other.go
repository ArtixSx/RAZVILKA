//go:build !linux

package updatecheck

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

func reviewProductionDaemonPath() (func() error, error) {
	return nil, errors.New("unsupported-platform")
}

func checkRootOwnedPath(string) error      { return errors.New("unsupported-platform") }
func checkProductionPID(int, string) error { return errors.New("unsupported-platform") }
func helperAlive(int) bool                 { return false }
func checkUpdateSpace(string, int64) error { return errors.New("unsupported-platform") }
func launchInstallerHelper(context.Context, string, func(func() error) error) (int, error) {
	return 0, errors.New("unsupported-platform")
}
func runTransactionalInstaller(*exec.Cmd, time.Duration) error {
	return errors.New("unsupported-platform")
}

func configureBoundedCommand(command *exec.Cmd) { command.WaitDelay = 2 * time.Second }
func cleanupCommand(command *exec.Cmd) {
	if command.Process != nil {
		_ = command.Process.Kill()
	}
}
