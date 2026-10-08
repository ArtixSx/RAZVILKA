package updatecheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

type priorStateObservation struct {
	path string
	info os.FileInfo
}

// The optional cut seam is private to model/native fault tests. A public
// caller can supply neither source roots, a manifest, nor a claimed checksum.
func capturePairedPriorState(ctx context.Context, installation string, binding pairedPriorBinding, receipt selfupdatejournal.Receipt, owned func(string) error, check func(context.Context) error, admit func(func() error) error, cut func(string) error) (string, error) {
	if ctx == nil || owned == nil || check == nil || admit == nil || !validPairedPriorBinding(binding) || !filepath.IsAbs(installation) || validatePairedPriorCoverage() != nil {
		return "", ErrPairedPriorArchive
	}
	if _, finite := ctx.Deadline(); !finite {
		return "", ErrPairedPriorArchive
	}
	boundary := func(stage string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if cut != nil {
			return cut(stage)
		}
		return nil
	}
	if check(ctx) != nil || owned(installation) != nil {
		return "", ErrPairedPriorArchive
	}
	source, err := ownedfs.Open(installation)
	if err != nil {
		return "", ErrPairedPriorArchive
	}
	defer source.Close()
	fs, err := os.OpenRoot(installation)
	if err != nil {
		return "", ErrPairedPriorArchive
	}
	defer fs.Close()
	unchanged := func() error {
		held, err := source.RootInfo()
		raw, rawErr := fs.Stat(".")
		current, e := os.Lstat(installation)
		if err != nil || rawErr != nil || e != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(held, raw) || !os.SameFile(held, current) || owned(installation) != nil {
			return ErrPairedPriorArchive
		}
		return check(ctx)
	}
	if err := unchanged(); err != nil {
		return "", err
	}
	basePath := filepath.Join(installation, filepath.FromSlash(pairedPriorArchiveDirectory))
	parent, err := ownedfs.Open(filepath.Dir(basePath))
	if err != nil || owned(filepath.Dir(basePath)) != nil {
		if parent != nil {
			parent.Close()
		}
		return "", ErrPairedPriorArchive
	}
	defer parent.Close()
	if err := parent.MkdirAll(filepath.Base(basePath), 0700); err != nil {
		return "", ErrPairedPriorArchive
	}
	if err := syncSelfUpdateDirectory(parent); err != nil {
		return "", ErrPairedPriorArchive
	}
	base, err := ownedfs.Open(basePath)
	if err != nil || owned(basePath) != nil {
		if base != nil {
			base.Close()
		}
		return "", ErrPairedPriorArchive
	}
	defer base.Close()
	if info, err := base.RootInfo(); err != nil || !privatePriorArchiveInfo(info, true) {
		return "", ErrPairedPriorArchive
	}
	baseFS, err := os.OpenRoot(basePath)
	if err != nil {
		return "", ErrPairedPriorArchive
	}
	defer baseFS.Close()
	baseHeld, baseErr := base.RootInfo()
	baseRaw, baseRawErr := baseFS.Stat(".")
	if baseErr != nil || baseRawErr != nil || !os.SameFile(baseHeld, baseRaw) {
		return "", ErrPairedPriorArchive
	}
	created := baseFS.Mkdir(binding.ID, 0700)
	if created != nil && !errors.Is(created, os.ErrExist) {
		return "", ErrPairedPriorArchive
	}
	if err := syncSelfUpdateDirectory(base); err != nil {
		return "", ErrPairedPriorArchive
	}
	archivePath := filepath.Join(basePath, binding.ID)
	archive, err := ownedfs.Open(archivePath)
	if err != nil || owned(archivePath) != nil {
		if archive != nil {
			archive.Close()
		}
		return "", ErrPairedPriorArchive
	}
	defer archive.Close()
	archiveFS, err := os.OpenRoot(archivePath)
	if err != nil {
		return "", ErrPairedPriorArchive
	}
	defer archiveFS.Close()
	if info, err := archive.RootInfo(); err != nil || !privatePriorArchiveInfo(info, true) {
		return "", ErrPairedPriorArchive
	}
	archiveCurrent := func() error {
		held, err := archive.RootInfo()
		current, e := os.Lstat(archivePath)
		baseHeld, baseErr := base.RootInfo()
		baseCurrent, baseCurrentErr := os.Lstat(basePath)
		if err != nil || e != nil || baseErr != nil || baseCurrentErr != nil || !privatePriorArchiveInfo(current, true) || !privatePriorArchiveInfo(baseCurrent, true) || !os.SameFile(held, current) || !os.SameFile(baseHeld, baseCurrent) || owned(archivePath) != nil {
			return ErrPairedPriorArchive
		}
		return nil
	}
	if created != nil {
		// A partial/foreign directory is preserved, never overwritten, pruned,
		// or silently promoted. A fully committed copy can only be reused while
		// the same actual prior source is still present under its original owner.
		doc, data, err := readPairedPriorArchive(ctx, archive, archiveFS, binding)
		if err != nil || priorArchiveMatchesReceipt(doc, receipt) != nil || archiveCurrent() != nil {
			return "", ErrPairedPriorArchive
		}
		fresh, _, err := scanPairedPriorState(ctx, source, fs, nil, binding, owned, boundary)
		if err != nil || !reflect.DeepEqual(doc, fresh) || unchanged() != nil {
			return "", ErrPairedPriorArchive
		}
		return digestBytes(data), nil
	}
	doc, observations, err := scanPairedPriorState(ctx, source, fs, archive, binding, owned, boundary)
	if err != nil || validatePairedPriorArchive(doc) != nil || priorArchiveMatchesReceipt(doc, receipt) != nil {
		return "", errors.Join(ErrPairedPriorArchive, ctx.Err())
	}
	if boundary("after:copy") != nil || syncSelfUpdateDirectory(archive) != nil || verifyPriorArchivePayloads(ctx, archive, archiveFS, doc, 0) != nil {
		return "", errors.Join(ErrPairedPriorArchive, ctx.Err())
	}
	data, err := json.Marshal(doc)
	if err != nil || len(data) > restorejournal.MaxImageBytes {
		return "", ErrPairedPriorArchive
	}
	prepared := func() error {
		if err := boundary("before:publish"); err != nil {
			return err
		}
		fresh, seen, err := scanPairedPriorState(ctx, source, fs, nil, binding, owned, boundary)
		if err != nil || !reflect.DeepEqual(doc, fresh) || !samePriorObservations(observations, seen) || unchanged() != nil || archiveCurrent() != nil {
			return ErrPairedPriorArchive
		}
		// ownedfs verifies its staged manifest separately. The complete closed
		// directory is checked before staging and again after publication.
		return verifyPriorArchivePayloads(ctx, archive, archiveFS, doc, -1)
	}
	if err := boundary("before:manifest"); err != nil {
		return "", err
	}
	_, err = archive.WriteAtomicWithRenameAdmission("manifest.json", data, 0600, admit, prepared)
	if err != nil {
		return "", err
	}
	if boundary("after:publish") != nil || syncSelfUpdateDirectory(archive) != nil || archiveCurrent() != nil {
		return "", errors.Join(ErrPairedPriorArchive, ctx.Err())
	}
	read, actual, err := readPairedPriorArchive(ctx, archive, archiveFS, binding)
	if err != nil || !reflect.DeepEqual(doc, read) || digestBytes(actual) != digestBytes(data) {
		return "", ErrPairedPriorArchive
	}
	fresh, seen, err := scanPairedPriorState(ctx, source, fs, nil, binding, owned, boundary)
	if err != nil || !reflect.DeepEqual(doc, fresh) || !samePriorObservations(observations, seen) || unchanged() != nil || boundary("after:verify") != nil {
		return "", errors.Join(ErrPairedPriorArchive, ctx.Err())
	}
	return digestBytes(actual), nil
}

func scanPairedPriorState(ctx context.Context, source *ownedfs.Root, fs *os.Root, output *ownedfs.Root, binding pairedPriorBinding, owned func(string) error, boundary func(string) error) (pairedPriorArchive, []priorStateObservation, error) {
	doc := pairedPriorArchive{Kind: pairedPriorArchiveKind, Schema: pairedPriorArchiveSchema, Platform: runtime.GOOS, Binding: binding}
	var observed []priorStateObservation
	var total int64
	for i, spec := range pairedPriorRoots {
		root := pairedPriorRoot{Path: spec.path, Directory: spec.directory}
		path := filepath.FromSlash(spec.path)
		if source.Check(path) != nil || owned(filepath.Join(fs.Name(), path)) != nil {
			return doc, observed, ErrPairedPriorArchive
		}
		info, err := fs.Lstat(path)
		if errors.Is(err, os.ErrNotExist) && !spec.required {
			doc.Roots = append(doc.Roots, root)
			observed = append(observed, priorStateObservation{path: path})
			continue
		}
		if err != nil || !safePriorSourceInfo(info) || info.IsDir() != spec.directory || !spec.directory && !info.Mode().IsRegular() {
			return doc, observed, ErrPairedPriorArchive
		}
		root.Exists, root.Mode = true, uint32(info.Mode().Perm())
		observed = append(observed, priorStateObservation{path, info})
		copyFile := func(relative, name string, before os.FileInfo) error {
			blob := fmt.Sprintf("payload-%08d", len(doc.Payloads))
			if len(doc.Payloads) >= 20000 || boundary("before:"+blob) != nil {
				return ErrPairedPriorArchive
			}
			size, hash, err := copyPriorArchiveFile(ctx, fs, relative, before, output, blob)
			if err != nil {
				return err
			}
			total += size
			if total > maximumPairedArchiveBytes || boundary("after:"+blob) != nil {
				return ErrPairedPriorArchive
			}
			doc.Payloads = append(doc.Payloads, pairedPriorPayload{i, name, blob, size, hash})
			return nil
		}
		if !spec.directory {
			if err := copyFile(path, "", info); err != nil {
				return doc, observed, err
			}
		} else {
			var walk func(string, os.FileInfo) error
			walk = func(name string, before os.FileInfo) error {
				if ctx.Err() != nil || source.Check(name) != nil {
					return ErrPairedPriorArchive
				}
				directory, err := openPriorArchiveReadOnly(fs, name)
				if err != nil {
					return ErrPairedPriorArchive
				}
				opened, statErr := directory.Stat()
				entries, readErr := directory.ReadDir(4097)
				closeErr := directory.Close()
				if statErr != nil || readErr != nil && readErr != io.EOF || closeErr != nil || !samePriorInfo(before, opened) || !safePriorSourceInfo(opened) || len(entries) > 4096 {
					return ErrPairedPriorArchive
				}
				sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
				for _, entry := range entries {
					rel := filepath.Join(name, entry.Name())
					info, err := fs.Lstat(rel)
					if err != nil || source.Check(rel) != nil || owned(filepath.Join(fs.Name(), rel)) != nil || !safePriorSourceInfo(info) || len(root.Entries) >= 4096 {
						return ErrPairedPriorArchive
					}
					child, err := filepath.Rel(path, rel)
					if err != nil || !filepath.IsLocal(child) {
						return ErrPairedPriorArchive
					}
					root.Entries = append(root.Entries, directoryEntry{Name: child, Mode: uint32(info.Mode().Perm()), Directory: info.IsDir()})
					observed = append(observed, priorStateObservation{rel, info})
					if info.IsDir() {
						if err := walk(rel, info); err != nil {
							return err
						}
					} else if err := copyFile(rel, child, info); err != nil {
						return err
					}
				}
				fresh, err := fs.Lstat(name)
				if err != nil || !samePriorInfo(before, fresh) || !safePriorSourceInfo(fresh) {
					return ErrPairedPriorArchive
				}
				return nil
			}
			if err := walk(path, info); err != nil {
				return doc, observed, err
			}
		}
		doc.Roots = append(doc.Roots, root)
	}
	return doc, observed, ctx.Err()
}

func samePriorInfo(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func samePriorObservations(before, after []priorStateObservation) bool {
	if len(before) != len(after) {
		return false
	}
	for i, old := range before {
		fresh := after[i]
		if old.path != fresh.path || (old.info == nil) != (fresh.info == nil) || old.info != nil && !samePriorInfo(old.info, fresh.info) {
			return false
		}
	}
	return true
}

func copyPriorArchiveFile(ctx context.Context, source *os.Root, name string, before os.FileInfo, output *ownedfs.Root, blob string) (int64, string, error) {
	if before.Size() > maximumPairedArchiveFileBytes || !before.Mode().IsRegular() || !safePriorSourceInfo(before) {
		return 0, "", ErrPairedPriorArchive
	}
	in, err := openPriorArchiveReadOnly(source, name)
	if err != nil {
		return 0, "", ErrPairedPriorArchive
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil || !samePriorInfo(before, opened) || !safePriorSourceInfo(opened) {
		return 0, "", ErrPairedPriorArchive
	}
	var out *os.File
	if output != nil {
		out, err = output.OpenFile(blob, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return 0, "", ErrPairedPriorArchive
		}
		defer out.Close()
		if err := out.Chmod(0600); err != nil {
			return 0, "", ErrPairedPriorArchive
		}
	}
	h := sha256.New()
	var writer io.Writer = h
	if out != nil {
		writer = io.MultiWriter(out, h)
	}
	n, err := copyPriorArchiveBytes(ctx, writer, in)
	after, statErr := in.Stat()
	current, currentErr := source.Lstat(name)
	if err != nil || statErr != nil || currentErr != nil || n != before.Size() || !samePriorInfo(before, after) || !samePriorInfo(before, current) || !safePriorSourceInfo(after) || !safePriorSourceInfo(current) {
		return 0, "", errors.Join(ErrPairedPriorArchive, ctx.Err())
	}
	if out != nil && (out.Sync() != nil || out.Close() != nil) {
		return 0, "", ErrPairedPriorArchive
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func copyPriorArchiveBytes(ctx context.Context, out io.Writer, in io.Reader) (int64, error) {
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := in.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > maximumPairedArchiveFileBytes {
				return total, ErrPairedPriorArchive
			}
			written, writeErr := out.Write(buffer[:n])
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, ctx.Err()
		}
		if err != nil {
			return total, err
		}
	}
}

func privatePriorArchiveInfo(info os.FileInfo, directory bool) bool {
	return info != nil && info.IsDir() == directory && (directory || info.Mode().IsRegular()) && info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && (runtime.GOOS == "windows" || !directory && info.Mode().Perm() == 0600 || directory && info.Mode().Perm() == 0700) && checkPriorArchiveOwner(info) == nil
}

func safePriorSourceInfo(info os.FileInfo) bool {
	return info != nil && (info.IsDir() || info.Mode().IsRegular()) && info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && (runtime.GOOS == "windows" || info.Mode().Perm()&0022 == 0) && checkPriorArchiveOwner(info) == nil
}

func readPairedPriorArchive(ctx context.Context, root *ownedfs.Root, fs *os.Root, binding pairedPriorBinding) (pairedPriorArchive, []byte, error) {
	var doc pairedPriorArchive
	info, err := root.Stat("manifest.json")
	if err != nil || !privatePriorArchiveInfo(info, false) {
		return doc, nil, ErrPairedPriorArchive
	}
	data, err := readPriorArchiveManifest(ctx, fs, info)
	if err != nil || decodeFileProtocol(data, &doc) != nil || validatePairedPriorArchive(doc) != nil || doc.Binding != binding || verifyPriorArchivePayloads(ctx, root, fs, doc, 1) != nil {
		return doc, nil, ErrPairedPriorArchive
	}
	return doc, data, ctx.Err()
}

func readPriorArchiveManifest(ctx context.Context, fs *os.Root, before os.FileInfo) ([]byte, error) {
	if before.Size() > restorejournal.MaxImageBytes {
		return nil, ErrPairedPriorArchive
	}
	file, err := openPriorArchiveReadOnly(fs, "manifest.json")
	if err != nil {
		return nil, ErrPairedPriorArchive
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !samePriorInfo(before, opened) || !privatePriorArchiveInfo(opened, false) {
		return nil, ErrPairedPriorArchive
	}
	var data bytes.Buffer
	n, copyErr := copyPriorArchiveBytes(ctx, &data, io.LimitReader(file, restorejournal.MaxImageBytes+1))
	after, afterErr := file.Stat()
	current, currentErr := fs.Lstat("manifest.json")
	if copyErr != nil || afterErr != nil || currentErr != nil || n != before.Size() || !samePriorInfo(before, after) || !samePriorInfo(before, current) || !privatePriorArchiveInfo(after, false) || !privatePriorArchiveInfo(current, false) {
		return nil, errors.Join(ErrPairedPriorArchive, ctx.Err())
	}
	return data.Bytes(), ctx.Err()
}

func verifyPriorArchivePayloads(ctx context.Context, root *ownedfs.Root, fs *os.Root, doc pairedPriorArchive, metadataCount int) error {
	if validatePairedPriorArchive(doc) != nil {
		return ErrPairedPriorArchive
	}
	info, err := root.RootInfo()
	raw, rawErr := fs.Stat(".")
	if err != nil || rawErr != nil || !os.SameFile(info, raw) || !privatePriorArchiveInfo(raw, true) {
		return ErrPairedPriorArchive
	}
	if metadataCount >= 0 {
		directory, err := fs.Open(".")
		if err != nil {
			return ErrPairedPriorArchive
		}
		entries, readErr := directory.ReadDir(20002)
		closeErr := directory.Close()
		if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) != len(doc.Payloads)+metadataCount {
			return ErrPairedPriorArchive
		}
	}
	for _, payload := range doc.Payloads {
		info, err := root.Stat(payload.Blob)
		if err != nil || !privatePriorArchiveInfo(info, false) || info.Size() != payload.Size {
			return ErrPairedPriorArchive
		}
		size, digest, err := copyPriorArchiveFile(ctx, fs, payload.Blob, info, nil, "")
		if err != nil || size != payload.Size || digest != payload.SHA256 {
			return ErrPairedPriorArchive
		}
	}
	return ctx.Err()
}
