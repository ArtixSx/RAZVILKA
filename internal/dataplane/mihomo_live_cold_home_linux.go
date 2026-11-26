//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// negative is the coordinator's SAME complete native process/kernel absence
// observer under its original exclusive offline lifetime. This helper only
// reads the fixed compiled temporary parent, never a serialized arbitrary path.
func observeMihomoColdHome(ctx context.Context, d ExecutionMihomoLiveDefinition, negative func(context.Context) (netidentity.Identity, error)) (out mihomoColdHomeArchive, resultErr error) {
	return observeMihomoOfflineHome(ctx, d, negative, false)
}

func observeMihomoSameBootHome(ctx context.Context, o *mihomoSameBootCleanup) (mihomoColdHomeArchive, error) {
	if o == nil || o.self != o || o.inputs == nil {
		return mihomoColdHomeArchive{}, ErrMihomoLiveRetirement
	}
	return observeMihomoOfflineHome(ctx, o.inputs.definition, o.absent, true)
}

func observeMihomoOfflineHome(ctx context.Context, d ExecutionMihomoLiveDefinition, negative func(context.Context) (netidentity.Identity, error), sameBoot bool) (out mihomoColdHomeArchive, resultErr error) {
	if ctx == nil || negative == nil || xraySelectedTCPFinite(ctx) != nil || d.validate() != nil || d.NativeHome == nil || d.NativeHome.Validate() != nil {
		return out, ErrMihomoLiveRetirement
	}
	ref := *d.NativeHome
	const prefix = ".razvilka-mihomo-live-"
	if ref.Parent != filepath.Clean(os.TempDir()) || !strings.HasPrefix(ref.Name, prefix) || !validMihomoColdHomeHex(strings.TrimPrefix(ref.Name, prefix)) {
		return out, ErrMihomoLiveRetirement
	}
	identity, err := negative(ctx)
	if err != nil || identity.Validate() != nil || !sameBoot && identity.BootID == d.NetworkIdentity.BootID || sameBoot && identity != d.NetworkIdentity {
		return out, errors.Join(ErrMihomoLiveRetirement, err)
	}
	before, err := os.Lstat(ref.Parent)
	if err != nil || !mihomoColdHomeParent(before) {
		return out, errors.Join(ErrMihomoLiveRetirement, err)
	}
	parent, err := os.OpenRoot(ref.Parent)
	if err != nil {
		return out, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, parent.Close())
		if resultErr != nil {
			clearMihomoColdHome(&out)
		}
	}()
	held, err := parent.Stat(".")
	if err != nil || !os.SameFile(before, held) || !mihomoColdHomeParent(held) {
		return out, errors.Join(ErrMihomoLiveRetirement, err)
	}
	ps := held.Sys().(*syscall.Stat_t)
	// Shared parent directory membership (e.g. /tmp) is unrelated to this
	// exact private scratch child. Never bind its mutable link count/times.
	parentIdentity := fmt.Sprintf("%d:%d:%d:%d:%d", ps.Dev, ps.Ino, ps.Uid, ps.Gid, uint32(held.Mode()))
	out = mihomoColdHomeArchive{Schema: 1, Reference: ref, ObservedParent: parentIdentity, OriginalParent: uint64(ps.Dev) == ref.ParentDevice && ps.Ino == ref.ParentInode}
	if sameBoot && !out.OriginalParent {
		return out, ErrMihomoLiveRetirement
	}
	bookend := func() error {
		named, e1 := os.Lstat(ref.Parent)
		actual, e2 := parent.Stat(".")
		if e1 != nil || e2 != nil || !mihomoColdHomeParent(named) || !mihomoColdHomeParent(actual) || !os.SameFile(held, named) || !os.SameFile(held, actual) || named.Mode() != held.Mode() {
			return errors.Join(ErrMihomoLiveRetirement, e1, e2)
		}
		if named.Sys().(*syscall.Stat_t).Gid != ps.Gid || actual.Sys().(*syscall.Stat_t).Gid != ps.Gid {
			return ErrMihomoLiveRetirement
		}
		return ctx.Err()
	}
	child, err := parent.Lstat(ref.Name)
	if errors.Is(err, os.ErrNotExist) {
		if sameBoot {
			return out, ErrMihomoLiveRetirement
		}
		out.State = "absent"
		closing, closeErr := negative(ctx)
		_, absentErr := parent.Lstat(ref.Name)
		if closeErr != nil || closing != identity || !errors.Is(absentErr, os.ErrNotExist) {
			return out, errors.Join(ErrMihomoLiveRetirement, closeErr, absentErr)
		}
		return out, errors.Join(bookend(), validateMihomoColdHomeArchive(d, out))
	}
	if err != nil || !out.OriginalParent || !networkPolicyPrivateDirectory(child) || !executionHistoryOwner(child, true) {
		return out, errors.Join(ErrMihomoLiveRetirement, err)
	}
	cs, ok := child.Sys().(*syscall.Stat_t)
	if !ok || uint64(cs.Dev) != ref.Device || cs.Ino != ref.Inode {
		return out, ErrMihomoLiveRetirement
	}
	home, err := parent.OpenRoot(ref.Name)
	if err != nil {
		return out, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, home.Close())
		if resultErr != nil {
			clearMihomoColdHome(&out)
		}
	}()
	homeCurrent := func() error {
		named, e1 := parent.Lstat(ref.Name)
		actual, e2 := home.Stat(".")
		if e1 != nil || e2 != nil || !mihomoColdHomeDirectorySame(child, named) || !mihomoColdHomeDirectorySame(child, actual) {
			return errors.Join(ErrMihomoLiveRetirement, e1, e2)
		}
		return bookend()
	}
	if err := homeCurrent(); err != nil {
		return out, err
	}
	out.State = "present"
	out.Files, out.Identities, out.Directories, err = readMihomoColdHomeTree(ctx, home)
	if err != nil {
		return out, err
	}
	out.Receipt = bytes.Clone(out.Files[components.MihomoLiveHomeReceiptName])
	if err := validateMihomoColdHomeArchive(d, out); err != nil {
		return out, err
	}
	closing, err := negative(ctx)
	if err != nil || closing != identity {
		return out, errors.Join(ErrMihomoLiveRetirement, err)
	}
	files, ids, dirs, err := readMihomoColdHomeTree(ctx, home)
	defer func() {
		for _, data := range files {
			clear(data)
		}
	}()
	if err != nil || !reflect.DeepEqual(files, out.Files) || !reflect.DeepEqual(ids, out.Identities) || !reflect.DeepEqual(dirs, out.Directories) {
		return out, errors.Join(ErrMihomoLiveRetirement, err)
	}
	return out, homeCurrent()
}

func mihomoColdHomeParent(info os.FileInfo) bool {
	if info == nil || !mihomoColdHomeParentMode(info.Mode()) {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}

func mihomoColdHomeDirectorySame(a, b os.FileInfo) bool {
	return a != nil && b != nil && networkPolicyPrivateDirectory(a) && networkPolicyPrivateDirectory(b) && executionHistoryOwner(a, true) && executionHistoryOwner(b, true) && mihomoColdHomeNodeIdentity(a) == mihomoColdHomeNodeIdentity(b)
}

func mihomoColdHomeNodeIdentity(info os.FileInfo) string {
	if info == nil {
		return ""
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s:%d:%d:%d:%d:%d", executionHistoryIdentity(info), info.Mode(), info.Size(), info.ModTime().UnixNano(), s.Ctim.Sec, s.Ctim.Nsec)
}

func clearMihomoColdHome(out *mihomoColdHomeArchive) {
	clear(out.Receipt)
	for _, data := range out.Files {
		clear(data)
	}
	*out = mihomoColdHomeArchive{}
}

func readMihomoColdHomeTree(ctx context.Context, home *os.Root) (files map[string][]byte, ids, dirs map[string]string, resultErr error) {
	files, ids, dirs = map[string][]byte{}, map[string]string{}, map[string]string{}
	defer func() {
		if resultErr != nil {
			for _, data := range files {
				clear(data)
			}
			files, ids, dirs = nil, nil, nil
		}
	}()
	total := 0
	var walk func(string, int) error
	walk = func(name string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		before, err := home.Lstat(name)
		if err != nil || !networkPolicyPrivateDirectory(before) || !executionHistoryOwner(before, true) || depth > 4 || len(dirs) >= 32 {
			return errors.Join(ErrMihomoLiveRetirement, err)
		}
		f, err := home.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		held, statErr := f.Stat()
		entries, readErr := f.ReadDir(129)
		closeErr := f.Close()
		if statErr != nil || !mihomoColdHomeDirectorySame(before, held) || readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 128 {
			return errors.Join(ErrMihomoLiveRetirement, statErr, readErr, closeErr)
		}
		dirs[name] = mihomoColdHomeNodeIdentity(before)
		for _, entry := range entries {
			path := filepath.Join(name, entry.Name())
			info, err := home.Lstat(path)
			if err != nil {
				return err
			}
			if info.IsDir() {
				if err := walk(path, depth+1); err != nil {
					return err
				}
				continue
			}
			if !mihomoColdFileValid(info) || info.Size() > int64(mihomoColdHomeLimit-total) || len(files) >= 128 {
				return ErrMihomoLiveRetirement
			}
			data, err := readMihomoColdFileAt(home, path, info)
			if err != nil {
				return err
			}
			total += len(data)
			files[path], ids[path] = data, mihomoColdHomeNodeIdentity(info)
		}
		after, err := home.Lstat(name)
		if err != nil || !mihomoColdHomeDirectorySame(before, after) {
			return errors.Join(ErrMihomoLiveRetirement, err)
		}
		return nil
	}
	resultErr = walk(".", 0)
	return
}
