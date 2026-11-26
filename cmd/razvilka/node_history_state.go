package main

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

var errNodeHistoryState = errors.New("retained node history compatibility is unavailable")

// Roots are trusted startup/CLI deployment values, independent of a live
// config override. This never opens a Store or imports/clears retained data.
func checkNodeHistoryState(ctx context.Context, configRoot, stateRoot string, readerVersion int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if readerVersion < 1 || readerVersion > nodestore.ExactHistoryReadVersion {
		return errNodeHistoryState
	}
	for _, root := range []string{configRoot, stateRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) == filepath.VolumeName(root)+string(filepath.Separator) {
			return errNodeHistoryState
		}
	}
	required, err := updatecheck.RequiredRetainedNodeHistoryReadVersion(ctx, configRoot, stateRoot, nodestore.RequiredPrivateHistoryReadVersion)
	if err != nil || required < 1 || required > readerVersion {
		return errNodeHistoryState
	}
	return ctx.Err()
}
