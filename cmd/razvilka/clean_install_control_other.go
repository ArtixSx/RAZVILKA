//go:build !linux

package main

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func initializeNativeCleanInstallControl(context.Context, *operationgate.Gate, string) error {
	return operationgate.ErrSelfUpdateStopJournal
}
