//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func ownedArchiveRoot(managerRoot, relative string, expected os.FileInfo) (*ownedfs.Root, error) {
	if expected == nil {
		return nil, ErrExecutionJournal
	}
	root, err := ownedfs.Open(filepath.Join(managerRoot, relative))
	if err != nil {
		return nil, err
	}
	held, err := root.RootInfo()
	if err != nil || !networkPolicyPrivateDirectory(held) || !executionHistoryOwner(held, true) || !os.SameFile(expected, held) {
		return nil, errors.Join(ErrExecutionJournal, err, root.Close())
	}
	return root, nil
}

func (c *mihomoTransitArchiveCursor) original() error {
	if c == nil || c.self != c || c.owner == nil || c.owner.self != c.owner || c.owner.transitHistory != c || c.owner.scope == nil || c.owner.scope.mihomoLive != c.owner || c.owner.records == nil || c.owner.records.scope != c.owner.scope || c.closeErr != nil {
		if c != nil {
			return errors.Join(ErrExecutionJournal, c.closeErr)
		}
		return ErrExecutionJournal
	}
	return nil
}

// Creating this original private transaction is subordinate to reader8
// admission and the whole-history peak budget checked by the caller.
func (c *mihomoTransitArchiveCursor) create(ctx context.Context) error {
	if err := c.original(); err != nil {
		return err
	}
	if ctx == nil || c.fileClosed || c.rootClosed {
		return ErrExecutionJournal
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrExecutionJournal, err)
	}
	d := c.owner.records
	if c.file != nil {
		return c.current(ctx)
	}
	if err := d.current(ctx, true); err != nil {
		return err
	}
	if c.relative == "" {
		parent, err := d.root.Stat("transactions")
		if err != nil || !networkPolicyPrivateDirectory(parent) || !executionHistoryOwner(parent, true) {
			return errors.Join(ErrExecutionJournal, err)
		}
		c.parentAnchor = parent
		relative, err := d.root.MkdirTemp("transactions", "dp-check-")
		if err != nil {
			return err
		}
		c.relative = relative // Never repeat a successful mkdir or adopt another directory.
		anchor, err := d.root.Stat(relative)
		if err != nil || !networkPolicyPrivateDirectory(anchor) || !executionHistoryOwner(anchor, true) {
			return errors.Join(ErrExecutionJournal, err)
		}
		c.anchor = anchor
	}
	if c.root == nil {
		root, err := ownedArchiveRoot(c.owner.scope.managerRoot, c.relative, c.anchor)
		if err != nil {
			return err
		}
		c.root = root
	}
	c.archive.PlanID = filepath.Base(c.relative)
	if err := c.archive.MihomoTransitHistoryArchive.validate(c.archive); err != nil {
		return err
	}
	image, err := json.Marshal(c.archive)
	c.image = image
	if err != nil || len(c.image) > mihomoTransitArchiveImageLimit {
		return errors.Join(ErrExecutionJournal, err)
	}
	file, err := c.root.OpenFile("execution.json", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0600)
	var statErr error
	if file != nil {
		c.file = file // Original creation ACK retained even when later Stat fails.
		c.info, statErr = file.Stat()
	}
	return errors.Join(err, statErr, c.current(ctx))
}

func (c *mihomoTransitArchiveCursor) current(ctx context.Context) error {
	if err := c.original(); err != nil {
		return err
	}
	if ctx == nil || c.file == nil || c.root == nil || c.fileClosed || c.rootClosed || c.info == nil || c.written < 0 || c.written > len(c.image) {
		return ErrExecutionJournal
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrExecutionJournal, err)
	}
	d := c.owner.records
	transactions, parentErr := d.root.Stat("transactions")
	manager, e1 := os.Lstat(c.owner.scope.managerRoot)
	parent, e2 := d.root.Stat(c.relative)
	heldRoot, e3 := c.root.RootInfo()
	before, e4 := c.file.Stat()
	named, e5 := c.root.Stat("execution.json")
	if errors.Join(e1, e2, e3, e4, e5, parentErr) != nil || !mihomoTransitArchiveDirectorySame(c.parentAnchor, transactions) || !mihomoTransitArchiveDirectorySame(d.anchor, manager) || !mihomoTransitArchiveDirectorySame(c.anchor, parent) || !mihomoTransitArchiveDirectorySame(c.anchor, heldRoot) || !mihomoColdFileSame(c.info, before) || !mihomoColdFileSame(before, named) || before.Size() != int64(c.written) {
		return errors.Join(ErrExecutionJournal, e1, e2, e3, e4, e5, parentErr)
	}
	raw := make([]byte, c.written+1)
	n, err := c.file.ReadAt(raw, 0)
	after, statErr := c.file.Stat()
	closing, namedErr := c.root.Stat("execution.json")
	if n != c.written || !errors.Is(err, io.EOF) || !bytes.Equal(raw[:n], c.image[:c.written]) || statErr != nil || namedErr != nil || !mihomoColdFileSame(before, after) || !mihomoColdFileSame(after, closing) {
		return ErrExecutionJournal
	}
	return ctx.Err()
}

// After the authored descriptors have acknowledged Close, reopening permits
// only a bounded comparison against their frozen original inode and bytes.
// This cannot issue a writer, a probe owner or any native cleanup authority.
func (c *mihomoTransitArchiveCursor) archiveCurrent(ctx context.Context) (result error) {
	if err := c.original(); err != nil {
		return err
	}
	if !c.fileClosed {
		return c.current(ctx)
	}
	if ctx == nil || c.info == nil || c.written != len(c.image) || !c.durable || !c.originACK {
		return ErrExecutionJournal
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root := c.owner.records.root
	manager, e1 := os.Lstat(c.owner.scope.managerRoot)
	transactions, e2 := root.Stat("transactions")
	child, e3 := root.Stat(c.relative)
	name := filepath.Join(c.relative, "execution.json")
	before, e4 := root.Stat(name)
	if errors.Join(e1, e2, e3, e4) != nil || !mihomoTransitArchiveDirectorySame(c.owner.records.anchor, manager) || !mihomoTransitArchiveDirectorySame(c.parentAnchor, transactions) || !mihomoTransitArchiveDirectorySame(c.anchor, child) || !mihomoColdFileSame(c.info, before) {
		return ErrExecutionJournal
	}
	f, err := executionHistoryOpen(root, name)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	held, err := f.Stat()
	if err != nil || !mihomoColdFileSame(before, held) {
		return errors.Join(ErrExecutionJournal, err)
	}
	raw := make([]byte, len(c.image)+1)
	n, readErr := f.ReadAt(raw, 0)
	after, statErr := f.Stat()
	named, namedErr := root.Stat(name)
	closingChild, childErr := root.Stat(c.relative)
	closingParent, parentErr := root.Stat("transactions")
	if n != len(c.image) || !errors.Is(readErr, io.EOF) || !bytes.Equal(raw[:n], c.image) || errors.Join(statErr, namedErr, childErr, parentErr) != nil || !mihomoColdFileSame(held, after) || !mihomoColdFileSame(after, named) || !mihomoTransitArchiveDirectorySame(c.anchor, closingChild) || !mihomoTransitArchiveDirectorySame(c.parentAnchor, closingParent) {
		return ErrExecutionJournal
	}
	return ctx.Err()
}

func (c *mihomoTransitArchiveCursor) publish(ctx context.Context) error {
	if err := c.current(ctx); err != nil {
		return err
	}
	if c.written < len(c.image) {
		n, err := c.file.WriteAt(c.image[c.written:], int64(c.written))
		c.written += n
		info, statErr := c.file.Stat()
		if statErr == nil {
			c.info = info
		}
		if err != nil || statErr != nil || c.written != len(c.image) {
			return errors.Join(ErrExecutionJournal, err, statErr)
		}
	}
	if err := errors.Join(c.current(ctx), c.file.Sync()); err != nil {
		return err
	}
	// Child entry plus the new transaction directory both require durable ACK.
	if err := c.root.Sync(); err != nil {
		return err
	}
	parent, err := openJournalDirectory(filepath.Join(c.owner.scope.managerRoot, "transactions"))
	if err != nil {
		return err
	}
	parentInfo, statErr := parent.RootInfo()
	expected, expectedErr := c.owner.records.root.Stat("transactions")
	if statErr != nil || expectedErr != nil || !mihomoTransitArchiveDirectorySame(c.parentAnchor, parentInfo) || !mihomoTransitArchiveDirectorySame(parentInfo, expected) {
		return errors.Join(ErrExecutionJournal, statErr, expectedErr, parent.Close())
	}
	err = errors.Join(parent.Sync(), parent.Close(), c.current(ctx))
	if err == nil {
		c.durable = true
	}
	return err
}

func mihomoTransitArchiveDirectorySame(a, b os.FileInfo) bool {
	if a == nil || b == nil || !networkPolicyPrivateDirectory(a) || !networkPolicyPrivateDirectory(b) || !executionHistoryOwner(a, true) || !executionHistoryOwner(b, true) || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Uid == y.Uid && x.Gid == y.Gid
}

func (c *mihomoTransitArchiveCursor) closeArchive(ctx context.Context) error {
	if err := c.original(); err != nil {
		return err
	}
	if !c.durable || !c.originACK {
		return ErrExecutionJournal
	}
	if !c.fileClosed {
		if err := c.current(ctx); err != nil {
			return err
		}
		c.fileClosed = true
		c.closeErr = errors.Join(c.closeErr, c.file.Close())
	}
	if c.closeErr == nil && !c.rootClosed {
		named, err := c.root.Stat("execution.json")
		if err != nil || !mihomoColdFileSame(c.info, named) {
			return errors.Join(ErrExecutionJournal, err)
		}
		c.rootClosed = true
		c.closeErr = errors.Join(c.closeErr, c.root.Close())
	}
	return c.closeErr
}

// The archive adds one transaction while BOTH live Before images still exist.
// No projected After shrink is subtracted from this peak bound.
func (r *mihomoLiveResource) transitArchivePeakBudget(ctx context.Context, additional int) error {
	if r == nil || r.records == nil || r.records.root == nil || additional <= 0 || additional > mihomoTransitArchiveImageLimit {
		return ErrExecutionJournal
	}
	root := r.records.root
	entries, err := root.ReadDirAt("transactions", 1024)
	if err != nil || len(entries)+1 >= 1024 {
		return errors.Join(ErrExecutionJournal, err)
	}
	names := []string{"latest-execution.json"}
	for _, entry := range entries {
		if !entry.IsDir() || !validExecutionPlanID(entry.Name()) {
			return ErrExecutionJournal
		}
		names = append(names, filepath.Join("transactions", entry.Name(), "execution.json"))
	}
	total := int64(additional)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := root.Stat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !mihomoColdFileValid(info) || info.Size() > mihomoTransitArchiveImageLimit {
			return errors.Join(ErrExecutionJournal, err)
		}
		total += info.Size()
		if total > 32<<20 {
			return ErrExecutionJournal
		}
	}
	return ctx.Err()
}
