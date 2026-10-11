package dataplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type wgInactivityRootNode struct {
	path   string
	file   *os.File
	info   os.FileInfo
	names  []string // Non-nil only for the observed engine subtree.
	digest [32]byte
}
type wgInactivityRootObservation struct {
	nodes  []wgInactivityRootNode
	absent string
}

// Capture each actual directory incarnation for THIS finite read session.
// Missing runtime directories are recorded only as file comparison, not as
// runtime absence; the full existing kernel/process observer still executes.
func observeWGInactivityRoots(ctx context.Context, managerRoot, stateRoot string) (out wgInactivityRootObservation, result error) {
	rel, err := filepath.Rel(managerRoot, stateRoot)
	if err != nil || rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return out, ErrWGOperationOwner
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) > 16 {
		return out, ErrWGOperationOwner
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, out.close())
		}
	}()
	path := managerRoot
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			path = filepath.Join(path, parts[i])
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			out.absent = path
			break
		}
		if err != nil || !networkPolicyPrivateDirectory(before) {
			return out, ErrWGOperationOwner
		}
		file, err := openWGInactivityObservationFile(path)
		if err != nil {
			return out, err
		}
		info, err := file.Stat()
		if err != nil || !os.SameFile(before, info) {
			return out, errors.Join(ErrWGOperationOwner, file.Close())
		}
		out.nodes = append(out.nodes, wgInactivityRootNode{path: path, file: file, info: info})
	}
	if out.absent == "" {
		var bytes int64
		if err := out.captureTree(ctx, len(out.nodes)-1, 0, &bytes); err != nil {
			return out, err
		}
	}
	return out, out.current(ctx)
}

// Bound the complete original engine subtree, including generation receipts.
// Retained file descriptors prevent same-bytes/inode reuse from adopting a new
// occupant. Digests are comparison only; they never issue runtime ownership.
func (o *wgInactivityRootObservation) captureTree(ctx context.Context, index, depth int, total *int64) error {
	if depth > 16 || len(o.nodes) > 384 || ctx.Err() != nil {
		return errors.Join(ErrWGOperationOwner, ctx.Err())
	}
	entries, err := wgInactivityDirectoryEntries(o.nodes[index].path)
	if err != nil {
		return err
	}
	o.nodes[index].names = make([]string, 0, len(entries))
	for _, entry := range entries {
		if len(o.nodes) >= 384 || ctx.Err() != nil {
			return errors.Join(ErrWGOperationOwner, ctx.Err())
		}
		parent := o.nodes[index].path
		path := filepath.Join(parent, entry.Name())
		o.nodes[index].names = append(o.nodes[index].names, entry.Name())
		before, err := os.Lstat(path)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() && !before.Mode().IsRegular() || before.IsDir() && !networkPolicyPrivateDirectory(before) || before.Mode().IsRegular() && (before.Mode().Perm()&0022 != 0 || before.Size() < 0 || before.Size() > 16<<20) {
			return errors.Join(ErrWGOperationOwner, err)
		}
		file, err := openWGInactivityObservationFile(path)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil || !os.SameFile(before, info) {
			return errors.Join(ErrWGOperationOwner, err, file.Close())
		}
		next := len(o.nodes)
		o.nodes = append(o.nodes, wgInactivityRootNode{path: path, file: file, info: info})
		if info.IsDir() {
			if err := o.captureTree(ctx, next, depth+1, total); err != nil {
				return err
			}
		} else {
			*total += info.Size()
			if *total > 64<<20 {
				return ErrWGOperationOwner
			}
			digest, err := wgInactivityFileDigest(ctx, file, info)
			if err != nil {
				return err
			}
			o.nodes[next].digest = digest
		}
	}
	return nil
}

func wgInactivityFileDigest(ctx context.Context, file *os.File, original os.FileInfo) ([32]byte, error) {
	var result [32]byte
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// SectionReader never changes shared descriptor offsets across concurrent
	// admitted read RPCs or pure bookends.
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(file, 0, original.Size()+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || n != original.Size() || !wgInactivitySameFile(original, after) || ctx.Err() != nil {
		return result, errors.Join(ErrWGOperationOwner, err, statErr, ctx.Err())
	}
	copy(result[:], h.Sum(nil))
	return result, nil
}

func wgInactivitySameFile(original, actual os.FileInfo) bool {
	return original != nil && actual != nil && os.SameFile(original, actual) && original.Mode() == actual.Mode() && original.Size() == actual.Size() && original.ModTime().Equal(actual.ModTime())
}

func (o wgInactivityRootObservation) current(ctx context.Context) error {
	if len(o.nodes) == 0 {
		return ErrWGOperationOwner
	}
	for _, node := range o.nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := os.Lstat(node.path)
		if err != nil || !os.SameFile(node.info, info) || node.info.IsDir() && !networkPolicyPrivateDirectory(info) || !node.info.IsDir() && !wgInactivitySameFile(node.info, info) {
			return ErrWGOperationOwner
		}
		retained, err := node.file.Stat()
		if err != nil || !os.SameFile(node.info, retained) {
			return ErrWGOperationOwner
		}
		if node.names != nil {
			entries, err := wgInactivityDirectoryEntries(node.path)
			if err != nil {
				return err
			}
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			if !slices.Equal(node.names, names) {
				return ErrWGOperationOwner
			}
		} else if !node.info.IsDir() {
			digest, err := wgInactivityFileDigest(ctx, node.file, node.info)
			if err != nil || digest != node.digest {
				return errors.Join(ErrWGOperationOwner, err)
			}
		}
	}
	if o.absent != "" {
		if _, err := os.Lstat(o.absent); !errors.Is(err, os.ErrNotExist) {
			return ErrWGOperationOwner
		}
	}
	return nil
}

func wgInactivityDirectoryEntries(path string) (entries []os.DirEntry, result error) {
	file, err := openWGInactivityObservationFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	entries, err = file.ReadDir(385)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 384 {
		return nil, ErrWGOperationOwner
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return entries, nil
}

func (o wgInactivityRootObservation) close() error {
	var result error
	for _, node := range o.nodes {
		result = errors.Join(result, node.file.Close())
	}
	return result
}
