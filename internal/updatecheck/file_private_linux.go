//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"golang.org/x/sys/unix"
)

func exchangePrivateDirectory(ctx context.Context, path string, before, after restorejournal.Image, check func(context.Context) error, admission filePrivateAdmission) error {
	if check == nil || admission == nil {
		return ErrFileProtocol
	}
	tree, err := validateDirectoryImage(after)
	if err != nil {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	fd, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer fd.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	stage := ".self-update-private-" + hex.EncodeToString(nonce[:])
	name := filepath.Base(path)
	if after.Exists {
		if err := parent.Mkdir(stage, 0700); err != nil {
			return err
		}
		root, err := parent.OpenRoot(stage)
		if err != nil {
			return err
		}
		defer root.Close()
		for _, entry := range tree.Entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if entry.Directory {
				if err := root.Mkdir(entry.Name, 0700); err != nil {
					return err
				}
				continue
			}
			f, err := root.OpenFile(entry.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			if _, err = f.Write(entry.Data); err == nil {
				err = f.Chmod(os.FileMode(entry.Mode))
			}
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
		var directories []directoryEntry
		for _, entry := range tree.Entries {
			if entry.Directory {
				directories = append(directories, entry)
			}
		}
		sort.Slice(directories, func(i, j int) bool { return len(directories[i].Name) > len(directories[j].Name) })
		for _, entry := range directories {
			f, err := root.Open(entry.Name)
			if err != nil {
				return err
			}
			err = f.Chmod(os.FileMode(entry.Mode))
			if err == nil {
				err = f.Sync()
			}
			f.Close()
			if err != nil {
				return err
			}
		}
		f, err := root.Open(".")
		if err != nil {
			return err
		}
		err = f.Chmod(os.FileMode(tree.Mode))
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	if err := fd.Sync(); err != nil {
		return err
	}
	if err := check(ctx); err != nil {
		return err
	}
	actual, err := readDirectoryImage(ctx, path)
	if err != nil || actual.Exists != before.Exists || !bytes.Equal(actual.Data, before.Data) {
		return restorejournal.ErrConflict
	}
	if err := check(ctx); err != nil {
		return err
	}
	// Exchange retains the displaced complete directory as an owned private
	// LKG sibling. No recursive delete/prune occurs, including on uncertainty.
	err = admission(ctx, func() error {
		switch {
		case after.Exists && before.Exists:
			err = unix.Renameat2(int(fd.Fd()), stage, int(fd.Fd()), name, unix.RENAME_EXCHANGE)
		case after.Exists:
			err = unix.Renameat2(int(fd.Fd()), stage, int(fd.Fd()), name, unix.RENAME_NOREPLACE)
		case before.Exists:
			err = unix.Renameat2(int(fd.Fd()), name, int(fd.Fd()), stage, unix.RENAME_NOREPLACE)
		default:
			return nil
		}
		return err
	})
	if err != nil {
		return errors.Join(ErrFileProtocol, err)
	}
	return fd.Sync()
}

// The caller retains FileTarget's existing participant lease for the complete
// restore session. Payload staging/fsync and fresh CAS reads happen before the
// independent short Stop lock; only the rename/unlink happens inside it.
func replacePrivateFile(ctx context.Context, root *os.Root, name string, reader restorejournal.Target, before, after restorejournal.Image, check func(context.Context) error, admission filePrivateAdmission) error {
	if root == nil || reader == nil || check == nil || admission == nil || !filepath.IsLocal(name) || filepath.Base(name) != name || len(after.Data) > restorejournal.MaxImageBytes || !after.Exists && len(after.Data) != 0 {
		return ErrFileProtocol
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	stage := ".self-update-private-file-" + hex.EncodeToString(nonce[:])
	if after.Exists {
		file, err := root.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = file.Write(after.Data)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if err := syncPrivateFileRoot(root); err != nil {
		return err
	}
	actual, err := reader.Read(ctx)
	if err != nil {
		return err
	}
	if actual.Exists != before.Exists || !bytes.Equal(actual.Data, before.Data) {
		return restorejournal.ErrConflict
	}
	if err := check(ctx); err != nil {
		return err
	}
	if before.Exists == after.Exists && bytes.Equal(before.Data, after.Data) {
		return nil
	}
	if err := admission(ctx, func() error {
		if after.Exists {
			return root.Rename(stage, name)
		}
		return root.Remove(name)
	}); err != nil {
		return err
	}
	return syncPrivateFileRoot(root)
}

func syncPrivateFileRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// Check the real parents before stopping the old panel. The probe exchanges
// only newly created empty private directories, never an application target.
func probePrivateFilesystems(ctx context.Context, installation string) error {
	parents := map[string]bool{}
	for _, path := range fileMutablePrivateDirectories {
		parents[filepath.Dir(filepath.Join(installation, filepath.FromSlash(path)))] = true
	}
	for _, path := range filePrivateFiles {
		parents[filepath.Dir(filepath.Join(installation, filepath.FromSlash(path)))] = true
	}
	for path := range parents {
		if err := probePrivateFilesystem(ctx, path); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func probePrivateFilesystem(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parent, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer parent.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".self-update-fs-probe-" + hex.EncodeToString(nonce[:])
	if err := parent.Mkdir(name, 0700); err != nil {
		return err
	}
	probe, err := parent.OpenRoot(name)
	if err != nil {
		return err
	}
	defer probe.Close()
	defer func() {
		_ = probe.Remove("a")
		_ = probe.Remove("b")
		_ = parent.Remove(name)
		_ = syncPrivateFileRoot(parent)
	}()
	if err := probe.Mkdir("a", 0700); err != nil {
		return err
	}
	if err := probe.Mkdir("b", 0700); err != nil {
		return err
	}
	if err := syncPrivateFileRoot(probe); err != nil {
		return err
	}
	fd, err := probe.Open(".")
	if err != nil {
		return err
	}
	defer fd.Close()
	if err := unix.Renameat2(int(fd.Fd()), "a", int(fd.Fd()), "b", unix.RENAME_EXCHANGE); err != nil {
		return errors.Join(ErrFileProtocol, err)
	}
	if err := unix.Renameat2(int(fd.Fd()), "a", int(fd.Fd()), "b", unix.RENAME_NOREPLACE); !errors.Is(err, unix.EEXIST) {
		return errors.Join(ErrFileProtocol, err)
	}
	if err := probe.Remove("b"); err != nil {
		return err
	}
	if err := unix.Renameat2(int(fd.Fd()), "a", int(fd.Fd()), "b", unix.RENAME_NOREPLACE); err != nil {
		return errors.Join(ErrFileProtocol, err)
	}
	if err := fd.Sync(); err != nil {
		return err
	}
	return syncPrivateFileRoot(parent)
}
