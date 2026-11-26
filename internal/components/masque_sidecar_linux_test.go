//go:build linux

package components

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestMASQUESidecarExtractsOnlyPinnedMember(t *testing.T) {
	const member = "reviewed/sing-box"
	binary := []byte("fixture executable")
	var body bytes.Buffer
	zip := gzip.NewWriter(&body)
	archive := tar.NewWriter(zip)
	for i, name := range []string{"reviewed/extra", member} {
		data := []byte("not executable")
		if i > 0 {
			data = binary
		}
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(archive.Close(), zip.Close()); err != nil {
		t.Fatal(err)
	}
	archiveHash, binaryHash := sha256.Sum256(body.Bytes()), sha256.Sum256(binary)
	image := masqueSidecarArtifact{
		archiveBytes: int64(body.Len()), archiveSHA: hex.EncodeToString(archiveHash[:]),
		binaryBytes: int64(len(binary)), binarySHA: hex.EncodeToString(binaryHash[:]),
	}
	if got := new(bytes.Buffer); extractMASQUESidecar(bytes.NewReader(body.Bytes()), got, member, image) != nil || !bytes.Equal(got.Bytes(), binary) {
		t.Fatal("archive did not yield precisely the pinned executable")
	}
	corrupt := bytes.Clone(body.Bytes())
	corrupt[len(corrupt)-1] ^= 1
	for _, invalid := range [][]byte{corrupt, body.Bytes()[:body.Len()-2], append(bytes.Clone(body.Bytes()), byte(0))} {
		if err := extractMASQUESidecar(bytes.NewReader(invalid), io.Discard, member, image); !errors.Is(err, ErrMASQUESidecarIntegrity) {
			t.Fatalf("accepted an altered archive: %v", err)
		}
	}
}

func TestMASQUESidecarDoesNotPublishAfterCancellationOrConflict(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := ownedfs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	const binary = "fixture executable"
	download := func(dst io.Writer) error {
		_, err := io.WriteString(dst, binary)
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = publishMASQUESidecar(ctx, root, dir, int64(len(binary)), context.Context.Err, func(_ context.Context, publish func() error) error {
		cancel()
		return publish()
	}, download)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancelled publication: %v", err)
	}
	if paths, err := os.ReadDir(dir); err != nil || len(paths) != 0 {
		t.Fatalf("cancellation left artifacts: %v %v", paths, err)
	}
	target := filepath.Join(dir, "sing-box")
	err = publishMASQUESidecar(context.Background(), root, dir, int64(len(binary)), context.Context.Err, func(_ context.Context, publish func() error) error {
		if err := os.WriteFile(target, []byte("original"), 0500); err != nil {
			return err
		}
		return publish()
	}, download)
	data, readErr := os.ReadFile(target)
	if !errors.Is(err, ErrComponentAlreadyInstalled) || readErr != nil || string(data) != "original" {
		t.Fatalf("publication replaced another occupant: %v %v %q", err, readErr, data)
	}
	paths, err := os.ReadDir(dir)
	if err != nil || len(paths) != 1 || paths[0].Name() != "sing-box" {
		t.Fatalf("conflict left staged material: %v %v", paths, err)
	}
}

func TestMASQUESidecarPublicationHasOneOwnedNameBeforeDirectorySync(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stage := filepath.Join(dir, masqueSidecarStage)
	target := filepath.Join(dir, masqueSidecarTarget)
	if err := os.WriteFile(stage, []byte("verified fixture"), 0500); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(stage)
	if err != nil {
		t.Fatal(err)
	}
	if err := renameMASQUESidecar(int(file.Fd())); err != nil {
		t.Fatal(err)
	}
	// Observe the exact checkpoint at which a crash would skip directory
	// fsync. The normal reader must be able to settle the final publication.
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rename left a staging name: %v", err)
	}
	after, err := os.Lstat(target)
	if _, trusted := hevRetainedOwner(after, false); err != nil || !trusted || !os.SameFile(before, after) {
		t.Fatalf("rename changed the original executable or left multiple links: %v", err)
	}
	if err := checkInitialUSQUEPublication(context.Background(), target); err != nil {
		t.Fatalf("directory sync recovery could not settle the publication: %v", err)
	}
}
