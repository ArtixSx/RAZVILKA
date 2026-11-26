//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/installpath"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type cleanInstallDirectory struct {
	path    string
	root    *ownedfs.Root
	info    os.FileInfo
	private bool
}

type cleanInstallImage struct {
	path    string
	file    *os.File
	info    os.FileInfo
	digest  string
	limit   int64
	private bool
}

type cleanInstallObservation struct {
	directories []cleanInstallDirectory
	images      []cleanInstallImage
	running     *os.File
}

func cleanInstallProtected(info os.FileInfo, private bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	mask := os.FileMode(0022)
	if private {
		mask = 0077
	}
	return ok && s.Uid == 0 && info.Mode().Perm()&mask == 0
}

func (o *cleanInstallObservation) close() error {
	var err error
	for _, image := range o.images {
		err = errors.Join(err, image.file.Close())
	}
	if o.running != nil {
		err = errors.Join(err, o.running.Close())
	}
	for _, directory := range o.directories {
		err = errors.Join(err, directory.root.Close())
	}
	return err
}

func cleanInstallImageDigest(ctx context.Context, file *os.File, limit int64) (string, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return "", operationgate.ErrSelfUpdateStopJournal
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for offset := int64(0); offset < info.Size(); {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		want := int(min(int64(len(buffer)), info.Size()-offset))
		n, err := file.ReadAt(buffer[:want], offset)
		if n != want || err != nil {
			return "", operationgate.ErrSelfUpdateStopJournal
		}
		_, _ = hash.Write(buffer[:n])
		offset += int64(n)
	}
	var tail [1]byte
	if n, err := file.ReadAt(tail[:], info.Size()); n != 0 || !errors.Is(err, io.EOF) {
		return "", operationgate.ErrSelfUpdateStopJournal
	}
	closing, err := file.Stat()
	if err != nil || !os.SameFile(info, closing) || info.Size() != closing.Size() || !info.ModTime().Equal(closing.ModTime()) {
		return "", operationgate.ErrSelfUpdateStopJournal
	}
	return hex.EncodeToString(hash.Sum(nil)), ctx.Err()
}

func (o *cleanInstallObservation) current(ctx context.Context) error {
	namedBase, err := os.Stat("/opt")
	if err != nil || len(o.directories) != 6 || !os.SameFile(namedBase, o.directories[0].info) {
		return operationgate.ErrSelfUpdateStopJournal
	}
	for _, directory := range o.directories {
		named, err := os.Lstat(directory.path)
		held, heldErr := directory.root.RootInfo()
		if err != nil || heldErr != nil || !named.IsDir() || !os.SameFile(directory.info, held) ||
			!os.SameFile(held, named) || !cleanInstallProtected(named, directory.private) {
			return operationgate.ErrSelfUpdateStopJournal
		}
	}
	for _, image := range o.images {
		named, err := os.Lstat(image.path)
		held, heldErr := image.file.Stat()
		if err != nil || heldErr != nil || !named.Mode().IsRegular() || !os.SameFile(image.info, held) ||
			!os.SameFile(held, named) || named.Mode() != image.info.Mode() || !cleanInstallProtected(named, image.private) {
			return operationgate.ErrSelfUpdateStopJournal
		}
		digest, err := cleanInstallImageDigest(ctx, image.file, image.limit)
		if err != nil || digest != image.digest {
			return operationgate.ErrSelfUpdateStopJournal
		}
	}
	running, err := o.running.Stat()
	if err != nil || len(o.images) != 2 || !os.SameFile(running, o.images[0].info) {
		return operationgate.ErrSelfUpdateStopJournal
	}
	return ctx.Err()
}

func observeCleanInstall(ctx context.Context, expected string) (*cleanInstallObservation, error) {
	if os.Geteuid() != 0 || os.Getuid() != 0 {
		return nil, operationgate.ErrSelfUpdateStopJournal
	}
	// Only the explicitly named Entware /opt root may resolve through its
	// customary mount/link. Every descendant stays physical and protected.
	base, err := filepath.EvalSymlinks("/opt")
	if err != nil || base == "/" {
		return nil, operationgate.ErrSelfUpdateStopJournal
	}
	o := &cleanInstallObservation{}
	keep := false
	defer func() {
		if !keep {
			_ = o.close()
		}
	}()
	for i, relative := range []string{"", "bin", "etc", "etc/razvilka", "razvilka", "razvilka/state"} {
		path := filepath.Join(base, relative)
		root, err := ownedfs.Open(path)
		if err != nil {
			return nil, operationgate.ErrSelfUpdateStopJournal
		}
		info, err := root.RootInfo()
		private := i >= 4
		if err != nil || !info.IsDir() || !cleanInstallProtected(info, private) {
			_ = root.Close()
			return nil, operationgate.ErrSelfUpdateStopJournal
		}
		o.directories = append(o.directories, cleanInstallDirectory{path, root, info, private})
	}
	for i, input := range []struct {
		directory int
		name      string
		limit     int64
		private   bool
	}{{1, "razvilka", 128 << 20, false}, {3, "config.json", 4 << 20, true}} {
		directory := o.directories[input.directory]
		file, err := directory.root.OpenFile(input.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, operationgate.ErrSelfUpdateStopJournal
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || !cleanInstallProtected(info, input.private) || i == 0 && info.Mode().Perm()&0100 == 0 {
			_ = file.Close()
			return nil, operationgate.ErrSelfUpdateStopJournal
		}
		digest, err := cleanInstallImageDigest(ctx, file, input.limit)
		if err != nil || i == 0 && digest != expected {
			_ = file.Close()
			return nil, operationgate.ErrSelfUpdateStopJournal
		}
		o.images = append(o.images, cleanInstallImage{filepath.Join(directory.path, input.name), file, info, digest, input.limit, input.private})
	}
	o.running, err = os.Open("/proc/self/exe") // Actual kernel image, not argv metadata.
	if err != nil {
		return nil, operationgate.ErrSelfUpdateStopJournal
	}
	running, err := o.running.Stat()
	if err != nil || !os.SameFile(running, o.images[0].info) {
		return nil, operationgate.ErrSelfUpdateStopJournal
	}
	raw := make([]byte, o.images[1].info.Size())
	if _, err := o.images[1].file.ReadAt(raw, 0); err != nil {
		return nil, operationgate.ErrSelfUpdateStopJournal
	}
	if !cleanInstallConfigUnapplied(raw) {
		return nil, operationgate.ErrSelfUpdateStopJournal
	}
	keep = true
	return o, nil
}

func initializeNativeCleanInstallControl(ctx context.Context, gate *operationgate.Gate, expected string) error {
	if gate == nil || ctx == nil {
		return operationgate.ErrSelfUpdateStopJournal
	}
	return gate.WithExclusiveContext(ctx, func() (result error) {
		o, err := observeCleanInstall(ctx, expected)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, o.close()) }()
		if err := o.current(ctx); err != nil {
			return err
		}
		if err := initializeCleanInstallControlLedger(ctx, gate, installpath.State+"/self-update-stop"); err != nil {
			return err
		}
		control, err := gate.ReviewControlEpoch(ctx, installpath.State+"/self-update-stop")
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, control.Close()) }()
		return errors.Join(o.current(ctx), control.Current(ctx))
	})
}
