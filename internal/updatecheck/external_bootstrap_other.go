//go:build !linux

package updatecheck

import (
	"context"
	"os"
)

func externalBootstrapFileFlags() int                    { return 0 }
func externalBootstrapProgramInfo() (os.FileInfo, error) { return nil, ErrExternalBootstrap }
func externalBootstrapProcesses(context.Context, Deployment) (fileProcess, fileProcess, string, error) {
	return fileProcess{}, fileProcess{}, "", ErrExternalBootstrap
}
func externalBootstrapEntryMatches(context.Context, string, string, string, fileProcess) error {
	return ErrExternalBootstrap
}
