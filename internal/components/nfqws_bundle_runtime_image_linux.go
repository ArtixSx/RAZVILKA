//go:build linux && (amd64 || arm64)

package components

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

type managedRuntimeImageNode struct {
	name    string
	file    *os.File
	info    os.FileInfo
	entries []string // Directories only; names and exact entry kinds.
	content []byte   // This call's first read only, cleared before returning.
}

// This bounded, callback-free image observation keeps original descriptors
// until the whole graph closes. BOTH complete payload reads remain: the first
// uses an exact bounded allocation; the second compares fixed 32KiB chunks
// against those bytes, independent of timestamp granularity. No observed bytes
// survive this call; every later Check hashes and compares all six members anew.
// Original source/kernel/Start bookends and installer/recovery readers remain.
func (m *Manager) verifyManagedNFQWSRuntimeImage(ctx context.Context, path, expected string) (manifest ManagedNFQWSManifest, resultErr error) {
	if m == nil || ctx == nil || !bundleHash(expected, 64) {
		return manifest, ErrManagedNFQWSBundle
	}
	if err := ctx.Err(); err != nil {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err)
	}
	if err := m.publicManagedNFQWSPath(filepath.Dir(path), false); err != nil {
		return manifest, err
	}
	anchor, err := os.Lstat(path)
	if err != nil || !anchor.IsDir() || m.trustedManagedNFQWSNode(anchor) != nil || !updateModeMatches(anchor.Mode().Perm(), 0555) {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return manifest, err
	}
	var nodes []*managedRuntimeImageNode
	defer func() {
		for _, node := range nodes {
			clear(node.content)
			resultErr = errors.Join(resultErr, node.file.Close())
		}
		resultErr = errors.Join(resultErr, root.Close())
		if resultErr != nil {
			manifest = ManagedNFQWSManifest{}
			resultErr = errors.Join(ErrManagedNFQWSBundle, resultErr)
		}
	}()
	open := func(name string, directory bool, limit int64) (*managedRuntimeImageNode, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		before, err := root.Lstat(name)
		if err != nil {
			return nil, err
		}
		file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		held, e1 := file.Stat()
		named, e2 := root.Lstat(name)
		mode := os.FileMode(0444)
		if directory || name == "bin/rzv-nfqws2" {
			mode = 0555
		}
		if e1 != nil || e2 != nil || !managedRuntimeImageSameNode(before, held) || !managedRuntimeImageSameNode(held, named) || held.IsDir() != directory || !directory && (!held.Mode().IsRegular() || held.Size() < 1 || held.Size() > limit) || m.trustedManagedNFQWSNode(held) != nil || !updateModeMatches(held.Mode().Perm(), mode) {
			return nil, errors.Join(ErrManagedNFQWSBundle, e1, e2, file.Close())
		}
		node := &managedRuntimeImageNode{name: name, file: file, info: held}
		nodes = append(nodes, node)
		return node, nil
	}
	// Exact schema1 tree, not a discovered loader recipe or arbitrary member.
	directories := map[string][]string{
		".":     {"d:bin", "d:blobs", "d:lua", "f:manifest.json", "f:source-notices.json"},
		"bin":   {"f:rzv-nfqws2"},
		"lua":   {"f:zapret-antidpi.lua", "f:zapret-auto.lua", "f:zapret-lib.lua"},
		"blobs": {"f:quic_initial.bin", "f:tls_clienthello.bin"},
	}
	for _, name := range []string{".", "bin", "lua", "blobs"} {
		node, err := open(name, true, 0)
		if err != nil {
			return manifest, err
		}
		if name == "." && !managedRuntimeImageSameNode(anchor, node.info) {
			return manifest, ErrManagedNFQWSBundle
		}
		node.entries, err = managedRuntimeImageEntries(node.file)
		if err != nil || !slices.Equal(node.entries, directories[name]) {
			return manifest, errors.Join(ErrManagedNFQWSBundle, err)
		}
	}
	manifestNode, err := open("manifest.json", false, 64<<10)
	if err != nil {
		return manifest, err
	}
	wire, err := io.ReadAll(io.LimitReader(manifestNode.file, (64<<10)+1))
	manifestNode.content = wire
	if err != nil || len(wire) > 64<<10 || digest(wire) != expected || json.Unmarshal(wire, &manifest) != nil {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err)
	}
	canonical, err := manifest.bytes()
	if err != nil || !bytes.Equal(wire, canonical) {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err)
	}
	noticeNode, err := open("source-notices.json", false, 1<<20)
	if err != nil {
		return manifest, err
	}
	notices, err := io.ReadAll(io.LimitReader(noticeNode.file, (1<<20)+1))
	noticeNode.content = notices
	expectedNotices, marshalErr := json.Marshal(manifest.Notices)
	if err != nil || marshalErr != nil || len(notices) > 1<<20 || !bytes.Equal(notices, expectedNotices) {
		return manifest, errors.Join(ErrManagedNFQWSBundle, err, marshalErr)
	}
	// Open the entire immutable member closure before any member payload read.
	var members []*managedRuntimeImageNode
	for _, member := range manifest.Members {
		node, err := open(filepath.FromSlash(member.Destination), false, 1<<20)
		if err != nil || node.info.Size() != member.RawSize {
			return manifest, errors.Join(ErrManagedNFQWSBundle, err)
		}
		members = append(members, node)
	}
	for i, node := range members {
		member := manifest.Members[i]
		data := make([]byte, member.RawSize+1)
		count, err := io.ReadFull(managedRuntimeImageContextReader{ctx, io.LimitReader(node.file, member.RawSize+1)}, data)
		node.content = data[:count]
		noteManagedNFQWSPayloadRead(m, int64(count))
		if !errors.Is(err, io.ErrUnexpectedEOF) || int64(count) != member.RawSize || digest(node.content) != member.RawSHA256 || ctx.Err() != nil {
			return manifest, errors.Join(ErrManagedNFQWSBundle, err, ctx.Err())
		}
	}
	// Preserve the second full byte comparison for manifest, notices and ALL
	// six payloads. Metadata closing is additional, never a substitute for it.
	buffer := make([]byte, 32<<10)
	defer clear(buffer)
	for _, node := range nodes {
		if node.info.IsDir() {
			continue
		}
		count, err := managedRuntimeImageCompare(ctx, node.file, node.content, buffer)
		if node.name != "manifest.json" && node.name != "source-notices.json" {
			noteManagedNFQWSPayloadRead(m, count)
		}
		if err != nil {
			return manifest, err
		}
	}
	if err := m.managedRuntimeImageClosing(ctx, root, path, anchor, nodes); err != nil {
		return manifest, err
	}
	return manifest, ctx.Err()
}

func managedRuntimeImageCompare(ctx context.Context, file *os.File, expected, buffer []byte) (int64, error) {
	if ctx == nil || file == nil || len(expected) == 0 || len(expected) > 1<<20 || len(buffer) != 32<<10 {
		return 0, ErrManagedNFQWSBundle
	}
	var total int64
	for offset := 0; offset < len(expected); {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		size := min(len(buffer), len(expected)-offset)
		count, err := file.ReadAt(buffer[:size], int64(offset))
		total += int64(count)
		if err != nil || count != size || !bytes.Equal(buffer[:count], expected[offset:offset+size]) {
			return total, errors.Join(ErrManagedNFQWSBundle, err)
		}
		offset += size
	}
	// The old second ReadLimited also refused trailing bytes. This read is
	// mandatory even if the named metadata will subsequently be checked again.
	count, err := file.ReadAt(buffer[:1], int64(len(expected)))
	total += int64(count)
	if count != 0 || !errors.Is(err, io.EOF) {
		return total, errors.Join(ErrManagedNFQWSBundle, err)
	}
	return total, ctx.Err()
}

// No callback, effect or reusable observation escapes this closing data guard.
func (m *Manager) managedRuntimeImageClosing(ctx context.Context, root *os.Root, path string, anchor os.FileInfo, nodes []*managedRuntimeImageNode) error {
	if m == nil || ctx == nil || root == nil || anchor == nil || len(nodes) != 12 {
		return ErrManagedNFQWSBundle
	}
	for _, node := range nodes {
		held, e1 := node.file.Stat()
		named, e2 := root.Lstat(node.name)
		if e1 != nil || e2 != nil || !managedRuntimeImageSameNode(node.info, held) || !managedRuntimeImageSameNode(held, named) || m.trustedManagedNFQWSNode(held) != nil {
			return errors.Join(ErrManagedNFQWSBundle, e1, e2)
		}
		if node.info.IsDir() {
			fresh, err := root.OpenFile(node.name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			freshInfo, e1 := fresh.Stat()
			entries, e2 := managedRuntimeImageEntries(fresh)
			closeErr := fresh.Close()
			if e1 != nil || e2 != nil || closeErr != nil || !managedRuntimeImageSameNode(node.info, freshInfo) || !slices.Equal(node.entries, entries) {
				return errors.Join(ErrManagedNFQWSBundle, e1, e2, closeErr)
			}
		}
	}
	closing, err := os.Lstat(path)
	if err != nil || !managedRuntimeImageSameNode(anchor, closing) {
		return errors.Join(ErrManagedNFQWSBundle, err)
	}
	if err := m.publicManagedNFQWSPath(filepath.Dir(path), false); err != nil {
		return err
	}
	return ctx.Err()
}

func managedRuntimeImageSameNode(a, b os.FileInfo) bool {
	if a == nil || b == nil || !os.SameFile(a, b) || a.Mode() != b.Mode() || a.Size() != b.Size() || !a.ModTime().Equal(b.ModTime()) {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Ctim == y.Ctim && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink
}

func managedRuntimeImageEntries(file *os.File) ([]string, error) {
	entries, err := file.ReadDir(16)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) >= 16 {
		return nil, errors.Join(ErrManagedNFQWSBundle, err)
	}
	var names []string
	for _, entry := range entries {
		kind := "f:"
		if entry.IsDir() {
			kind = "d:"
		} else if !entry.Type().IsRegular() {
			return nil, ErrManagedNFQWSBundle
		}
		names = append(names, kind+entry.Name())
	}
	slices.Sort(names)
	return names, nil
}

type managedRuntimeImageContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r managedRuntimeImageContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
