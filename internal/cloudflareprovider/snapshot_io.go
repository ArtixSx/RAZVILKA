package cloudflareprovider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// The ordinary store keeps its original capacity. A coordinated transaction
// uses the smaller journal limit and rejects oversized images before mutation.
var ErrRestoreCapacity = errors.New("Cloudflare snapshots exceed the coordinated restore size limit")

func snapshotSizeError(limit int) error {
	if limit == storeLimit {
		return ErrStore
	}
	return ErrRestoreCapacity
}

func readSnapshotImage(ctx context.Context, root *ownedfs.Root, limit int) (restorejournal.Image, error) {
	if err := ctx.Err(); err != nil {
		return restorejournal.Image{}, err
	}
	info, err := root.Stat(storeFile)
	if errors.Is(err, os.ErrNotExist) {
		return restorejournal.Image{}, nil
	}
	if err != nil || !validWriterFile(info) {
		return restorejournal.Image{}, ErrStore
	}
	if info.Size() > int64(limit) {
		return restorejournal.Image{}, snapshotSizeError(limit)
	}
	f, err := openSnapshotFile(root)
	if err != nil {
		return restorejournal.Image{}, ErrStore
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !validWriterFile(actual) || !os.SameFile(info, actual) {
		return restorejournal.Image{}, ErrStore
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return restorejournal.Image{}, ErrStore
	}
	if len(data) > limit {
		return restorejournal.Image{}, snapshotSizeError(limit)
	}
	if err := ctx.Err(); err != nil {
		return restorejournal.Image{}, err
	}
	return restorejournal.Image{Exists: true, Data: data}, nil
}

func snapshotDocument(image restorejournal.Image, limit int) (privateDocument, error) {
	doc := privateDocument{Schema: Schema, Owner: "razvilka", Accounts: []storedAccount{}}
	if len(image.Data) > limit {
		return privateDocument{}, snapshotSizeError(limit)
	}
	if !image.Exists {
		if len(image.Data) != 0 {
			return privateDocument{}, ErrStore
		}
		return doc, nil
	}
	// Defaults are valid only for a missing file. Decoding {} or null into the
	// initialized empty-store model would silently accept a corrupt document.
	doc = privateDocument{}
	if json.Unmarshal(image.Data, &doc) != nil || validateDocument(doc) != nil {
		return privateDocument{}, ErrStore
	}
	return doc, nil
}

// Caller holds .import.lock. No fallback to a non-atomic write. A failure may
// follow rename/unlink; only an exact reread can establish the resulting state.
func writeSnapshotImage(root *ownedfs.Root, image restorejournal.Image) error {
	var err error
	if image.Exists {
		err = root.WriteAtomic(storeFile, image.Data, 0o600)
	} else {
		err = root.Remove(storeFile)
	}
	if err == nil && runtime.GOOS == "linux" {
		err = root.Sync()
	}
	if err != nil {
		return restorejournal.ErrRecovery
	}
	return nil
}
