//go:build linux && (amd64 || arm64)

package components

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Test-only cancellation at the first completed payload read, before EOF/hash
// acceptance. The production reader and its error/defer path remain original.
type runtimeClearCancelContext struct {
	context.Context
	observed bool
}

func (c *runtimeClearCancelContext) Err() error {
	if managedRuntimePayloadRetained.busy.Load() {
		for _, data := range managedRuntimePayloadRetained.scratch.members {
			for _, value := range data {
				if value != 0 {
					c.observed = true
					return context.Canceled
				}
			}
		}
	}
	return c.Context.Err()
}

func TestManagedRuntimePayloadClearOwnsEveryExit(t *testing.T) {
	for _, kind := range []string{"success", "canceled-after-read", "hash-refused"} {
		t.Run(kind, func(t *testing.T) {
			manager, manifest, receipt := runtimeImageFilesystemModel(t)
			if managedRuntimePayloadRetained.busy.Load() {
				t.Fatal("unexpected original scratch borrower")
			}
			ctx := context.Context(context.Background())
			cancelContext := &runtimeClearCancelContext{Context: ctx}
			if kind == "canceled-after-read" {
				ctx = cancelContext
			}
			if kind == "hash-refused" {
				path := filepath.Join(receipt.GenerationPath, filepath.FromSlash(manifest.Members[0].Destination))
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0600); err != nil {
					t.Fatal(err)
				}
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := file.WriteAt([]byte{0xff}, 0)
				if err := errors.Join(writeErr, file.Close(), os.Chmod(path, info.Mode().Perm())); err != nil {
					t.Fatal(err)
				}
			}
			got, err := manager.verifyManagedNFQWSRuntimeImage(ctx, receipt.GenerationPath, receipt.ManifestSHA256)
			if kind == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if hash, err := got.Digest(); err != nil || hash != receipt.ManifestSHA256 {
					t.Fatal("original manifest changed", err)
				}
			} else if !errors.Is(err, ErrManagedNFQWSBundle) || got.Schema != 0 {
				t.Fatal("failed read returned an accepted manifest", err)
			}
			if kind == "canceled-after-read" && (!cancelContext.observed || !errors.Is(err, context.Canceled)) {
				t.Fatal("partial original read cancellation not reached", err)
			}
			if managedRuntimePayloadRetained.busy.Load() {
				t.Fatal("returned while payload borrower remained held")
			}
			for _, data := range managedRuntimePayloadRetained.scratch.members {
				if !bytes.Equal(data[:cap(data)], make([]byte, cap(data))) {
					t.Fatal("payload capacity escaped original release")
				}
			}
			if !bytes.Equal(managedRuntimePayloadRetained.scratch.compare[:], make([]byte, 32<<10)) {
				t.Fatal("comparison bytes escaped original release")
			}
		})
	}
}
