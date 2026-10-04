package components

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func bundleGunzip(ctx context.Context, input []byte, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw := bytes.NewReader(input)
	gz, err := gzip.NewReader(raw)
	if err != nil {
		return nil, errors.Join(ErrManagedNFQWSBundle, err)
	}
	gz.Multistream(false)
	data, readErr := io.ReadAll(io.LimitReader(gz, limit+1))
	closeErr := gz.Close()
	if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil || int64(len(data)) > limit || raw.Len() != 0 {
		return nil, errors.Join(ErrManagedNFQWSBundle, err)
	}
	return data, nil
}

// Parse an entire bounded stream, including gzip CRC/trailing data, before
// writing any selected member. All paths/types/duplicates are checked even
// for discarded hooks. Discarding a regular hook never makes it executable.
func bundleTar(ctx context.Context, compressed []byte, limit int64, selected map[string]bool) (map[string][]byte, error) {
	data, err := bundleGunzip(ctx, compressed, limit)
	if err != nil {
		return nil, err
	}
	raw := bytes.NewReader(data)
	reader := tar.NewReader(raw)
	seen, found := map[string]bool{}, map[string][]byte{}
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Join(ErrManagedNFQWSBundle, err)
		}
		count++
		// The upstream tar includes one explicit root directory entry. It is
		// metadata only and is never materialized as a selected member.
		if (h.Name == "." || h.Name == "./") && h.Typeflag == tar.TypeDir && h.Size == 0 && h.Linkname == "" && len(h.PAXRecords) == 0 && !seen["."] {
			seen["."] = true
			continue
		}
		name, e := bundleArchivePath(h.Name)
		if e != nil || seen[name] || count > 256 || h.Size < 0 || h.Size > limit || len(h.PAXRecords) != 0 || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA && h.Typeflag != tar.TypeDir) || h.Linkname != "" {
			return nil, ErrManagedNFQWSBundle
		}
		seen[name] = true
		if selected[name] {
			if h.Typeflag == tar.TypeDir || h.Size > 8<<20 {
				return nil, ErrManagedNFQWSBundle
			}
			b, err := io.ReadAll(io.LimitReader(reader, h.Size+1))
			if err != nil || int64(len(b)) != h.Size {
				return nil, ErrManagedNFQWSBundle
			}
			found[name] = b
		}
	}
	// USTAR end padding may contain only zero bytes, never another payload.
	for _, b := range data[len(data)-raw.Len():] {
		if b != 0 {
			return nil, ErrManagedNFQWSBundle
		}
	}
	for name := range selected {
		if _, ok := found[name]; !ok {
			return nil, ErrManagedNFQWSBundle
		}
	}
	return found, nil
}

func extractManagedNFQWS(ctx context.Context, m ManagedNFQWSManifest, input []byte) (map[string][]byte, error) {
	if _, err := m.bytes(); err != nil {
		return nil, err
	}
	if int64(len(input)) != m.ParentAssetSize || digest(input) != m.ParentSHA256 {
		return nil, ErrManagedNFQWSBundle
	}
	outer, err := bundleTar(ctx, input, 12<<20, map[string]bool{"control.tar.gz": true, "data.tar.gz": true, "debian-binary": true})
	if err != nil || string(outer["debian-binary"]) != "2.0\n" || len(outer) != 3 {
		return nil, fmt.Errorf("outer IPK: %w", errors.Join(ErrManagedNFQWSBundle, err))
	}
	if _, err := bundleTar(ctx, outer["control.tar.gz"], 1<<20, nil); err != nil {
		return nil, fmt.Errorf("control tar: %w", err)
	}
	selected := map[string]bool{}
	for _, member := range m.Members {
		name, _ := bundleArchivePath(member.Path)
		selected[name] = true
	}
	payload, err := bundleTar(ctx, outer["data.tar.gz"], 12<<20, selected)
	if err != nil {
		return nil, fmt.Errorf("data tar: %w", err)
	}
	result := map[string][]byte{}
	for _, member := range m.Members {
		name, _ := bundleArchivePath(member.Path)
		data := payload[name]
		if int64(len(data)) != member.Size || digest(data) != member.SHA256 {
			return nil, ErrManagedNFQWSBundle
		}
		if member.Gzip {
			data, err = bundleGunzip(ctx, data, member.RawSize)
			if err != nil {
				return nil, err
			}
		}
		if int64(len(data)) != member.RawSize || digest(data) != member.RawSHA256 {
			return nil, ErrManagedNFQWSBundle
		}
		result[member.Destination] = data
	}
	return result, nil
}

func bundleWrite(root *ownedfs.Root, name string, data []byte, mode os.FileMode) error {
	f, err := root.OpenFile(filepath.FromSlash(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	err = errors.Join(writeErr, f.Chmod(mode), f.Sync(), f.Close())
	return err
}

func stageManagedNFQWS(ctx context.Context, path string, m ManagedNFQWSManifest, payload map[string][]byte) error {
	root, err := ownedfs.Open(path)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, directory := range []string{"bin", "lua", "blobs"} {
		if err := root.MkdirAll(directory, 0700); err != nil {
			return err
		}
	}
	for i, member := range m.Members {
		if err := ctx.Err(); err != nil {
			return err
		}
		mode := os.FileMode(0444)
		if i == 0 {
			mode = 0555
		}
		if err := bundleWrite(root, member.Destination, payload[member.Destination], mode); err != nil {
			return err
		}
	}
	data, err := m.bytes()
	if err != nil {
		return err
	}
	if err := bundleWrite(root, "manifest.json", data, 0444); err != nil {
		return err
	}
	notices, err := json.Marshal(m.Notices)
	if err != nil {
		return err
	}
	if err := bundleWrite(root, "source-notices.json", notices, 0444); err != nil {
		return err
	}
	for _, directory := range []string{"bin", "lua", "blobs", "."} {
		// OpenRoot keeps this final chmod/fsync anchored to the staged tree.
		r, err := os.OpenRoot(path)
		if err != nil {
			return err
		}
		f, err := r.Open(directory)
		r.Close()
		if err != nil {
			return err
		}
		// Keep the unpublished stage root private. Publication seals its root
		// mode under the same short authority as the actual directory rename.
		var modeErr error
		if directory != "." {
			modeErr = chmodBundleDirectory(f)
		}
		err = errors.Join(modeErr, syncBundleFile(f), f.Close())
		if err != nil {
			return err
		}
	}
	return nil
}

type managedNFQWSImageState uint8

const (
	managedNFQWSPublishedImage managedNFQWSImageState = iota
	managedNFQWSPrivateStage
	managedNFQWSStartedStage
)

func (m *Manager) verifyManagedNFQWS(ctx context.Context, path string, expected string) (ManagedNFQWSManifest, error) {
	return m.verifyManagedNFQWSImage(ctx, path, expected, managedNFQWSPublishedImage)
}

// A sealed stage is a known image only for this exact upgrade-started journal.
// The chmod -> rename crash cut can leave either0700 or0555; neither permits
// bypassing full hashes/tree/owner verification or frozen effect admission.
func (m *Manager) verifyStartedManagedNFQWSStage(ctx context.Context, doc updateJournal, releases string) (ManagedNFQWSManifest, error) {
	if validateManagedNFQWSJournal(doc) != nil || doc.Phase != UpdateStarted || filepath.Dir(doc.ManagedNFQWS.After.GenerationPath) != releases {
		return ManagedNFQWSManifest{}, ErrManagedNFQWSBundle
	}
	return m.verifyManagedNFQWSImage(ctx, filepath.Join(releases, doc.ManagedNFQWS.Stage), doc.ManagedNFQWS.After.ManifestSHA256, managedNFQWSStartedStage)
}

func (manager *Manager) verifyManagedNFQWSImage(ctx context.Context, path string, expected string, state managedNFQWSImageState) (ManagedNFQWSManifest, error) {
	var m ManagedNFQWSManifest
	if state > managedNFQWSStartedStage {
		return m, ErrManagedNFQWSBundle
	}
	if err := manager.publicManagedNFQWSPath(filepath.Dir(path), false); err != nil {
		return m, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || manager.trustedManagedNFQWSNode(info) != nil {
		return m, ErrManagedNFQWSBundle
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return m, err
	}
	defer root.Close()
	data, err := root.ReadLimited("manifest.json", 64<<10)
	if err != nil || digest(data) != expected || json.Unmarshal(data, &m) != nil {
		return m, ErrManagedNFQWSBundle
	}
	canonical, err := m.bytes()
	if err != nil || !bytes.Equal(data, canonical) {
		return m, ErrManagedNFQWSBundle
	}
	notices, _ := json.Marshal(m.Notices)
	files := map[string][]byte{"manifest.json": canonical, "source-notices.json": notices}
	for _, member := range m.Members {
		if err := ctx.Err(); err != nil {
			return m, err
		}
		data, err := root.ReadLimited(filepath.FromSlash(member.Destination), member.RawSize)
		if err != nil || int64(len(data)) != member.RawSize || digest(data) != member.RawSHA256 {
			return m, ErrManagedNFQWSBundle
		}
		files[member.Destination] = data
	}
	for name, expectedData := range files {
		data, err := root.ReadLimited(filepath.FromSlash(name), 1<<20)
		info, infoErr := root.Stat(filepath.FromSlash(name))
		mode := os.FileMode(0444)
		if name == "bin/rzv-nfqws2" {
			mode = 0555
		}
		if err != nil || infoErr != nil || !bytes.Equal(data, expectedData) || manager.trustedManagedNFQWSNode(info) != nil || !updateModeMatches(info.Mode().Perm(), mode) {
			return m, ErrManagedNFQWSBundle
		}
	}
	// Reject extra files, symlinks, or writable directories in the generation.
	r, err := os.OpenRoot(path)
	if err != nil {
		return m, err
	}
	defer r.Close()
	count := 0
	for _, directory := range []string{".", "bin", "lua", "blobs"} {
		f, err := r.Open(directory)
		if err != nil {
			return m, err
		}
		info, statErr := f.Stat()
		entries, readErr := f.ReadDir(16)
		f.Close()
		modeOK := statErr == nil && updateModeMatches(info.Mode().Perm(), 0555)
		if statErr == nil && directory == "." {
			switch state {
			case managedNFQWSPrivateStage:
				modeOK = updateModeMatches(info.Mode().Perm(), 0700)
			case managedNFQWSStartedStage:
				modeOK = modeOK || updateModeMatches(info.Mode().Perm(), 0700)
			}
		}
		if statErr != nil || !info.IsDir() || manager.trustedManagedNFQWSNode(info) != nil || !modeOK || (readErr != nil && readErr != io.EOF) {
			return m, ErrManagedNFQWSBundle
		}
		for _, entry := range entries {
			name := entry.Name()
			if directory != "." {
				name = directory + "/" + name
			}
			if directory == "." && (name == "bin" || name == "lua" || name == "blobs") && entry.IsDir() {
				continue
			}
			if _, ok := files[name]; !ok || !entry.Type().IsRegular() {
				return m, ErrManagedNFQWSBundle
			}
			count++
		}
	}
	if count != len(files) {
		return m, ErrManagedNFQWSBundle
	}
	return m, ctx.Err()
}
