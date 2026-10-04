//go:build !linux

package updatecheck

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"os"
)

func exchangePrivateDirectory(context.Context, string, restorejournal.Image, restorejournal.Image, func(context.Context) error, filePrivateAdmission) error {
	return ErrFileProtocol
}

func replacePrivateFile(context.Context, *os.Root, string, restorejournal.Image, restorejournal.Image, func(context.Context) error, filePrivateAdmission) error {
	return ErrFileProtocol
}

func probePrivateFilesystems(context.Context, string) error { return ErrFileProtocol }
