package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// This is a separate mutable-state protocol, not part of the six-file ledger.
// All roots/names come from this fixed registry. Journals/supervision receipts
// are never restored as mutable state or removed to bypass a pending fence.
// Only fileMutablePrivateDirectories enter the mutable snapshot and restore.
// Warp/Cloudflare/runtime/LKG and private-restore native/feeds generations stay
// in their existing roots, including all current, legacy and unknown receipts.

func readDirectoryImage(ctx context.Context, path string) (restorejournal.Image, error) {
	var image restorejournal.Image
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return image, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return image, ErrFileProtocol
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return image, err
	}
	defer root.Close()
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		return image, ErrFileProtocol
	}
	tree := directoryImage{Mode: uint32(info.Mode().Perm())}
	total := 0
	var walk func(string) error
	walk = func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		directory, err := root.Open(name)
		if err != nil {
			return err
		}
		entries, err := directory.ReadDir(4097)
		directory.Close()
		if err != nil && err != io.EOF {
			return err
		}
		if len(entries) > 4096 {
			return ErrFileProtocol
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if len(tree.Entries) >= 4096 {
				return ErrFileProtocol
			}
			rel := filepath.Join(name, entry.Name())
			if !filepath.IsLocal(rel) || entry.Type()&os.ModeSymlink != 0 {
				return ErrFileProtocol
			}
			info, err := root.Lstat(rel)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return ErrFileProtocol
			}
			item := directoryEntry{Name: rel, Mode: uint32(info.Mode().Perm()), Directory: info.IsDir()}
			if info.IsDir() {
				tree.Entries = append(tree.Entries, item)
				if err := walk(rel); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() || info.Size() > restorejournal.MaxImageBytes {
				return ErrFileProtocol
			}
			f, err := root.Open(rel)
			if err != nil {
				return err
			}
			actual, err := f.Stat()
			if err != nil || !os.SameFile(info, actual) {
				f.Close()
				return ErrFileProtocol
			}
			item.Data, err = io.ReadAll(io.LimitReader(f, restorejournal.MaxImageBytes+1))
			f.Close()
			if err != nil {
				return err
			}
			total += len(item.Data)
			if total > restorejournal.MaxImageBytes {
				return ErrFileProtocol
			}
			tree.Entries = append(tree.Entries, item)
		}
		return nil
	}
	if err := walk("."); err != nil {
		return image, err
	}
	data, err := json.Marshal(tree)
	if err != nil || len(data) > restorejournal.MaxImageBytes {
		return image, ErrFileProtocol
	}
	return restorejournal.Image{Exists: true, Data: data}, nil
}

type fileDirectoryTarget struct {
	path      string
	check     func(context.Context) error
	admission filePrivateAdmission
}

type filePrivateAdmission func(context.Context, func() error) error

func (target *fileDirectoryTarget) Read(ctx context.Context) (restorejournal.Image, error) {
	return readDirectoryImage(ctx, target.path)
}
func (target *fileDirectoryTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if _, err := validateDirectoryImage(after); err != nil {
		return err
	}
	actual, err := target.Read(ctx)
	if err != nil || actual.Exists != before.Exists || !bytes.Equal(actual.Data, before.Data) {
		return restorejournal.ErrConflict
	}
	if err := target.check(ctx); err != nil {
		return err
	}
	return exchangePrivateDirectory(ctx, target.path, before, after, target.check, target.admission)
}

type fileGuardedTarget struct {
	restorejournal.Target
	check     func(context.Context) error
	root      *os.Root
	name      string
	admission filePrivateAdmission
}

func (target fileGuardedTarget) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	if err := target.check(ctx); err != nil {
		return err
	}
	return replacePrivateFile(ctx, target.root, target.name, target.Target, before, after, target.check, target.admission)
}

func (a *SelfUpdateFileAdapter) privateTargets(ctx context.Context, id string) (map[string]restorejournal.Target, func(), error) {
	_, review, err := a.load(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	check := func(c context.Context) error {
		if err := a.AuthorityAction(c, id, review.Revision, "replace-to-rollback"); err != nil {
			return err
		}
		if err := a.fileQuiescenceExcept(c, id, "restore-private-state"); err != nil {
			return err
		}
		return a.filePanelAbsent(c)
	}
	targets := map[string]restorejournal.Target{}
	var closeFiles []func() error
	close := func() {
		for _, f := range closeFiles {
			_ = f()
		}
	}
	for name, path := range fileMutablePrivateDirectories {
		admission := func(c context.Context, begin func() error) error {
			return a.EffectAdmission(c, id, "replace-to-rollback", "rollback-private-"+name, begin)
		}
		targets[name] = &fileDirectoryTarget{path: filepath.Join(a.installation, filepath.FromSlash(path)), check: check, admission: admission}
	}
	for name, path := range filePrivateFiles {
		full := filepath.Join(a.installation, filepath.FromSlash(path))
		root, err := os.OpenRoot(filepath.Dir(full))
		if err != nil {
			close()
			return nil, nil, err
		}
		closeFiles = append(closeFiles, root.Close)
		file, err := restorejournal.OpenFileTarget(full)
		if err != nil {
			close()
			return nil, nil, err
		}
		closeFiles = append(closeFiles, file.Close)
		admission := func(c context.Context, begin func() error) error {
			return a.EffectAdmission(c, id, "replace-to-rollback", "rollback-private-"+name, begin)
		}
		targets[name] = fileGuardedTarget{Target: file, check: check, root: root, name: filepath.Base(full), admission: admission}
	}
	return targets, close, nil
}

func (a *SelfUpdateFileAdapter) preparePrivateSnapshot(ctx context.Context, id string) error {
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Stat("private-snapshot.json"); !errors.Is(err, os.ErrNotExist) {
		return ErrFileProtocol
	}
	snapshot := privateFileSnapshot{Schema: 2, ID: id, Images: map[string]restorejournal.Image{}}
	total := 0
	for name, path := range fileMutablePrivateDirectories {
		image, err := readDirectoryImage(ctx, filepath.Join(a.installation, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		snapshot.Images[name] = image
		total += len(image.Data)
	}
	for name, path := range filePrivateFiles {
		image, err := restorejournal.ReadFileImage(ctx, filepath.Join(a.installation, filepath.FromSlash(path)))
		if err != nil {
			return err
		}
		snapshot.Images[name] = image
		total += len(image.Data)
	}
	if total > restorejournal.MaxPlanBytes/2 {
		return ErrFileProtocol
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if err := root.WriteAtomic("private-snapshot.json", data, 0600); err != nil {
		return err
	}
	if err := root.WriteAtomic("private-snapshot.sha256", []byte(digestBytes(data)), 0600); err != nil {
		return err
	}
	return syncSelfUpdateDirectory(root)
}

func (a *SelfUpdateFileAdapter) privateSnapshot(ctx context.Context, id string) (privateFileSnapshot, error) {
	var snapshot privateFileSnapshot
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return snapshot, err
	}
	defer root.Close()
	data, err := root.ReadLimited("private-snapshot.json", 6<<20)
	if err != nil {
		return snapshot, err
	}
	hash, err := root.ReadLimited("private-snapshot.sha256", 64)
	if err != nil || string(hash) != digestBytes(data) || decodeFileProtocol(data, &snapshot) != nil || snapshot.ID != id {
		return snapshot, ErrFileProtocol
	}
	return snapshot, validatePrivateSnapshot(snapshot)
}

func (a *SelfUpdateFileAdapter) verifyPrivateSnapshot(ctx context.Context, id string) error {
	_, err := a.privateSnapshot(ctx, id)
	return err
}

func (a *SelfUpdateFileAdapter) restorePrivateSnapshot(ctx context.Context, id string) error {
	snapshot, err := a.privateSnapshot(ctx, id)
	if err != nil {
		return err
	}
	// Legacy whole-domain snapshots remain readable retained evidence, but
	// cannot authorize rewinding independent native/runtime/LKG histories.
	if snapshot.Schema != 2 {
		return ErrFileProtocol
	}
	_, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return err
	}
	if err := a.AuthorityAction(ctx, id, review.Revision, "replace-to-rollback"); err != nil {
		return err
	}
	targets, close, err := a.privateTargets(ctx, id)
	if err != nil {
		return err
	}
	defer close()
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.MkdirAll("private-restore", 0700); err != nil {
		return err
	}
	if err := syncSelfUpdateDirectory(root); err != nil {
		return err
	}
	var names []string
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	scope := digestBytes([]byte("self-update-private-v1\n" + a.installation + "\n" + id + "\n" + strings.Join(names, "\n")))
	journal, err := restorejournal.Open(filepath.Join(a.directory, id, "private-restore"), scope, targets)
	if err != nil {
		return err
	}
	defer journal.Close()
	// The separate journal resumes only known CAS file/tree replacement; no
	// script, command, runtime startup or whole-directory shell deletion.
	if outcome, err := journal.Recover(ctx); err != nil || outcome == restorejournal.Blocked {
		return errors.Join(ErrFileProtocol, err)
	}
	if err := a.AuthorityAction(ctx, id, review.Revision, "replace-to-rollback"); err != nil {
		return err
	}
	outcome, err := journal.Execute(ctx, snapshot.Images)
	if err != nil || (outcome != restorejournal.Applied && outcome != restorejournal.Clean) {
		return errors.Join(ErrFileProtocol, err)
	}
	return a.verifyPrivateRestore(ctx, id)
}

// Explicit data-only repair, after CORE matching admission. This resumes known
// restore CAS records and never replays an unknown external command or starts
// a panel. An absent restore plan cannot be turned into a new repair plan.
func (a *SelfUpdateFileAdapter) RepairPrivate(ctx context.Context, id string) error {
	_, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return err
	}
	if err := a.AuthorityAction(ctx, id, review.Revision, "replace-to-rollback"); err != nil {
		return err
	}
	if err := a.fileQuiescence(ctx, id); err != nil {
		return err
	}
	root, err := a.commandRoot(id)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := root.ReadLimited("private-restore/restore.private.json", 12<<20)
	if err != nil {
		return err
	}
	if err := inspectRetainedRestoreNodes(data, func([]byte) error { return nil }); err != nil {
		return err
	}
	return a.restorePrivateSnapshot(ctx, id)
}

func (a *SelfUpdateFileAdapter) verifyPrivateRestore(ctx context.Context, id string) error {
	snapshot, err := a.privateSnapshot(ctx, id)
	if err != nil {
		return err
	}
	if snapshot.Schema != 2 {
		return ErrFileProtocol
	}
	for name, path := range fileMutablePrivateDirectories {
		actual, err := readDirectoryImage(ctx, filepath.Join(a.installation, filepath.FromSlash(path)))
		expected := snapshot.Images[name]
		if err != nil || actual.Exists != expected.Exists || !bytes.Equal(actual.Data, expected.Data) {
			return ErrFileProtocol
		}
	}
	for name, path := range filePrivateFiles {
		actual, err := restorejournal.ReadFileImage(ctx, filepath.Join(a.installation, filepath.FromSlash(path)))
		expected := snapshot.Images[name]
		if err != nil || actual.Exists != expected.Exists || !bytes.Equal(actual.Data, expected.Data) {
			return ErrFileProtocol
		}
	}
	return ctx.Err()
}
