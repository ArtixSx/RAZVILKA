package dataplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
	"os"
	"sync"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// A documentary borrow of the SAME original owner's global writer FD. This
// neither owns Close nor issues a standby/successor. Only an original writer
// cursor may seal the observed rename-over transition before using history.
type domainTCPGlobalHistory struct {
	mu       sync.Mutex
	self     *domainTCPGlobalHistory
	owner    *domainTCPStandbyOwner
	keeper   *domainTCPGlobalKeeper // Exact original documentary producer, never a synthetic standby.
	process  *XrayDomainTCPExecutionResource
	records  *xraySelectedTCPExecutionRecords
	file     *os.File
	root     *ownedfs.Root
	rootPath string
	rootInfo os.FileInfo
	original os.FileInfo
	sealed   os.FileInfo
	digest   [32]byte
}

func borrowDomainTCPGlobalHistory(ctx context.Context, owner *domainTCPStandbyOwner, record Execution) (*domainTCPGlobalHistory, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, errors.Join(ErrExecutionJournal, ctx.Err())
	}
	if xraySelectedTCPFinite(ctx) != nil || owner == nil || owner.self != owner || owner.process == nil || owner.process.scope == nil || owner.process.records == nil || owner.process.records.root == nil {
		return nil, ErrExecutionJournal
	}
	rootPath := owner.process.scope.managerRoot
	if err := owner.globalRecordCurrent(rootPath, record); err != nil {
		return nil, err
	}
	owner.latestMu.Lock()
	file, published := owner.latest, owner.latestInfo
	owner.latestMu.Unlock()
	if file == nil {
		return nil, ErrExecutionJournal
	}
	info, err := file.Stat()
	if err != nil || !domainTCPGlobalOriginalInfo(info) || published == nil || !domainTCPGlobalInfoSame(published, info) {
		return nil, errors.Join(ErrExecutionJournal, err)
	}
	root := owner.process.records.root
	anchor, err := root.RootInfo()
	if err != nil || !networkPolicyPrivateDirectory(anchor) {
		return nil, errors.Join(ErrExecutionJournal, err)
	}
	b := &domainTCPGlobalHistory{owner: owner, process: owner.process, records: owner.process.records, file: file, root: root, rootPath: rootPath, rootInfo: anchor, original: info}
	b.self = b
	b.digest, err = domainTCPGlobalHash(ctx, b.file, info.Size())
	if combined := errors.Join(err, b.currentOriginal(ctx), owner.globalRecordCurrent(rootPath, record)); combined != nil {
		return nil, errors.Join(ErrExecutionJournal, combined)
	}
	return b, nil
}

func (b *domainTCPGlobalHistory) currentRoot() error {
	if b == nil || b.self != b || b.root == nil || b.records == nil || b.records.root != b.root {
		return ErrExecutionJournal
	}
	if b.keeper != nil {
		if b.owner != nil || b.process != nil || b.keeper.historyBinding(b) != nil {
			return ErrExecutionJournal
		}
	} else if b.owner == nil || b.owner.self != b.owner || b.owner.process != b.process || b.process == nil || b.process.records != b.records {
		return ErrExecutionJournal
	}
	held, e1 := b.root.RootInfo()
	named, e2 := os.Lstat(b.rootPath)
	if e1 != nil || e2 != nil || !domainTCPGlobalRootSame(b.rootInfo, held) || !domainTCPGlobalRootSame(held, named) {
		return errors.Join(ErrExecutionJournal, e1, e2)
	}
	same := true
	if b.owner != nil {
		b.owner.latestMu.Lock()
		same = b.owner.latest == b.file
		b.owner.latestMu.Unlock()
	}
	if !same {
		return ErrExecutionJournal
	}
	return nil
}

func (b *domainTCPGlobalHistory) currentFile(ctx context.Context, expected os.FileInfo) error {
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrExecutionJournal, ctx.Err())
	}
	if b == nil || b.self != b || b.file == nil || xraySelectedTCPFinite(ctx) != nil {
		return ErrExecutionJournal
	}
	before, err := b.file.Stat()
	if err != nil || !domainTCPGlobalInfoSame(expected, before) {
		return errors.Join(ErrExecutionJournal, err)
	}
	digest, err := domainTCPGlobalHash(ctx, b.file, expected.Size())
	after, e2 := b.file.Stat()
	if err != nil || e2 != nil || digest != b.digest || !domainTCPGlobalInfoSame(expected, after) {
		return errors.Join(ErrExecutionJournal, err, e2)
	}
	return ctx.Err()
}

func (b *domainTCPGlobalHistory) currentOriginal(ctx context.Context) error {
	if b == nil || b.self != b {
		return ErrExecutionJournal
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sealed != nil {
		return ErrExecutionJournal
	}
	named, e1 := b.root.Stat("latest-execution.json")
	if e1 != nil || !domainTCPGlobalInfoSame(b.original, named) {
		return errors.Join(ErrExecutionJournal, e1)
	}
	if err := errors.Join(b.currentRoot(), b.currentFile(ctx, b.original)); err != nil {
		return err
	}
	closing, e2 := b.root.Stat("latest-execution.json")
	if e2 != nil || !domainTCPGlobalInfoSame(b.original, closing) {
		return errors.Join(ErrExecutionJournal, e2)
	}
	return b.currentRoot()
}

// Called only after an actual successor writer retained its newly published
// global FD. The cursor separately checks that FD/data/namespace/whole pool.
// The old inode must now have exactly ZERO links; this is never a general
// receipt validator exemption. Its post-rename metadata is then frozen.
func (b *domainTCPGlobalHistory) sealOriginalRename(ctx context.Context, produced *os.File) error {
	if b == nil || b.self != b {
		return ErrExecutionJournal
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sealed != nil || produced == nil || produced == b.file {
		return ErrExecutionJournal
	}
	if err := b.currentRoot(); err != nil {
		return err
	}
	newInfo, e1 := produced.Stat()
	named, e2 := b.root.Stat("latest-execution.json")
	oldInfo, e3 := b.file.Stat()
	if e1 != nil || e2 != nil || e3 != nil || !domainTCPGlobalOriginalInfo(newInfo) || !os.SameFile(newInfo, named) || os.SameFile(b.original, newInfo) || !domainTCPGlobalRenamedInfo(b.original, oldInfo) {
		return errors.Join(ErrExecutionJournal, e1, e2, e3)
	}
	if err := b.currentFile(ctx, oldInfo); err != nil {
		return err
	}
	if err := b.currentRoot(); err != nil {
		return err
	}
	closing, e1 := produced.Stat()
	named, e2 = b.root.Stat("latest-execution.json")
	if e1 != nil || e2 != nil || !domainTCPGlobalInfoSame(newInfo, closing) || !domainTCPGlobalInfoSame(closing, named) {
		return errors.Join(ErrExecutionJournal, e1, e2)
	}
	if err := b.currentRoot(); err != nil {
		return err
	}
	b.sealed = oldInfo
	return nil
}

func (b *domainTCPGlobalHistory) currentHistorical(ctx context.Context) error {
	if b == nil || b.self != b {
		return ErrExecutionJournal
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sealed == nil {
		return ErrExecutionJournal
	}
	return errors.Join(b.currentRoot(), b.currentFile(ctx, b.sealed), b.currentRoot())
}

func domainTCPGlobalHash(ctx context.Context, file *os.File, size int64) ([32]byte, error) {
	var zero [32]byte
	if file == nil || xraySelectedTCPFinite(ctx) != nil || size < 1 || size > 16<<20 {
		return zero, ErrExecutionJournal
	}
	var h hash.Hash = sha256.New()
	buffer := make([]byte, 32<<10)
	defer clear(buffer)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		chunk := buffer[:min(int64(len(buffer)), size-offset)]
		n, err := file.ReadAt(chunk, offset)
		if err != nil || n != len(chunk) {
			return zero, errors.Join(ErrExecutionJournal, err)
		}
		_, _ = h.Write(chunk)
		offset += int64(n)
	}
	var extra [1]byte
	if n, err := file.ReadAt(extra[:], size); n != 0 || !errors.Is(err, io.EOF) {
		return zero, errors.Join(ErrExecutionJournal, err)
	}
	copy(zero[:], h.Sum(nil))
	return zero, nil
}
