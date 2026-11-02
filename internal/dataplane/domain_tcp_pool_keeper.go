package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Original documentary custody after an UNSTARTED generation is retired.
// No process, DNS source, baseline or forward admission can be issued by it.
// Its actual transaction/global FDs remain available to the NEXT original
// writer; a disk record or a newly opened matching file cannot create one.
type domainTCPGlobalKeeper struct {
	self         *domainTCPGlobalKeeper
	closeMu      sync.Mutex
	pool         *domainTCPStandbyPool
	cursor       *domainTCPGlobalSuccessor
	records      *xraySelectedTCPExecutionRecords
	image        []byte
	digest       [32]byte
	ready        atomic.Bool
	closed       atomic.Bool
	closeErr     error // closeMu; an actual close error is sticky.
	retirement   *domainTCPStandbyRetirement
	continuation *dnscontrol.SyntheticDNSLedgerContinuation
}

// Read-only recognition of the SAME completed metadata holder. A restart,
// saved marker, or equal-byte replacement cannot create this exception.
func (m *Manager) checkKnownDomainKeeperRecord(record Execution) error {
	if m == nil || record.DomainDNSCoexistence == nil || record.State != "temporary-complete" || validateExecutionResources(record, true) != nil {
		return ErrPolicyAdditionUnknown
	}
	m.retainedXrayMu.Lock()
	pool := m.domainPool
	m.retainedXrayMu.Unlock()
	if pool == nil || pool.self != pool || pool.manager != m {
		return ErrPolicyAdditionUnknown
	}
	pool.mu.Lock()
	k := pool.keeper
	c := pool.successor
	pool.mu.Unlock()
	if k == nil || k.cursor != c || c == nil || k.original() != nil || !k.ready.Load() {
		return ErrPolicyAdditionUnknown
	}
	data, err := json.Marshal(record)
	if err != nil || !bytes.Equal(data, k.image) {
		return errors.Join(ErrExecutionJournal, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := k.current(ctx); err != nil {
		return err
	}
	if err := c.comparePrior(ctx, true); err != nil {
		return err
	}
	return k.current(ctx)
}

func (k *domainTCPGlobalKeeper) original() error {
	if k == nil || k.self != k || k.pool == nil || k.pool.self != k.pool || k.cursor == nil || k.cursor.self != k.cursor || k.cursor.pool != k.pool || k.records == nil || k.cursor.records != k.records || k.records.scope != k.cursor.scope || len(k.image) == 0 || len(k.image) > 4<<20 {
		return ErrPolicyAdditionUnknown
	}
	initial := k.cursor.terminal != nil && k.cursor.terminal.keeper == k
	retired := k.retirement != nil && k.retirement.self == k.retirement && k.retirement.keeper == k && k.retirement.owner != nil && k.retirement.owner.process != nil && k.retirement.owner.process.scope == k.cursor.scope && k.retirement.owner.process.records == k.records && k.continuation != nil
	if initial == retired {
		return ErrPolicyAdditionUnknown
	}
	return nil
}

func (k *domainTCPGlobalKeeper) current(ctx context.Context) error {
	if err := k.original(); err != nil {
		return err
	}
	k.closeMu.Lock()
	defer k.closeMu.Unlock()
	if !k.ready.Load() || k.closed.Load() || k.closeErr != nil {
		return errors.Join(ErrPolicyAdditionUnknown, k.closeErr)
	}
	if k.retirement != nil {
		if err := k.retirement.retiredPoolCurrent(ctx); err != nil {
			return err
		}
	}
	if err := k.compareFiles(ctx); err != nil {
		return err
	}
	if k.retirement != nil {
		return k.retirement.retiredPoolCurrent(ctx)
	}
	return ctx.Err()
}

func (k *domainTCPGlobalKeeper) compareFiles(ctx context.Context) error {
	if k.original() != nil || xraySelectedTCPFinite(ctx) != nil || k.records.standbyAlias.Load() {
		return ErrPolicyAdditionUnknown
	}
	if err := k.records.current(ctx, true); err != nil {
		return err
	}
	k.records.mu.Lock()
	images := bytes.Equal(k.records.images[0], k.image) && bytes.Equal(k.records.images[1], k.image)
	k.records.mu.Unlock()
	if !images {
		return ErrExecutionJournal
	}
	k.cursor.scope.mu.Lock()
	current, err := json.Marshal(k.cursor.scope.execution)
	k.cursor.scope.mu.Unlock()
	if err != nil || !bytes.Equal(current, k.image) || sha256.Sum256(current) != k.digest {
		return errors.Join(ErrExecutionJournal, err)
	}
	return k.records.current(ctx, true)
}

func borrowDomainTCPKeeperHistory(ctx context.Context, k *domainTCPGlobalKeeper) (*domainTCPGlobalHistory, error) {
	if k == nil || k.current(ctx) != nil {
		return nil, ErrPolicyAdditionUnknown
	}
	d := k.records
	d.mu.Lock()
	file, info := d.files[1], d.infos[1]
	d.mu.Unlock()
	if file == nil || info == nil || !domainTCPGlobalOriginalInfo(info) {
		return nil, ErrExecutionJournal
	}
	anchor, err := d.root.RootInfo()
	if err != nil {
		return nil, err
	}
	b := &domainTCPGlobalHistory{keeper: k, records: d, file: file, root: d.root, rootPath: k.cursor.scope.managerRoot, rootInfo: anchor, original: info, digest: k.digest}
	b.self = b
	if err := errors.Join(b.currentOriginal(ctx), k.current(ctx)); err != nil {
		return nil, err
	}
	return b, nil
}

// Used only by the typed global-history checker; no named file is reopened.
func (k *domainTCPGlobalKeeper) historyBinding(b *domainTCPGlobalHistory) error {
	if k.original() != nil || !k.ready.Load() || k.closed.Load() || b == nil || b.keeper != k || b.records != k.records || b.root != k.records.root {
		return ErrExecutionJournal
	}
	k.pool.mu.Lock()
	same := k.pool.keeper == k
	k.pool.mu.Unlock()
	if !same {
		return ErrExecutionJournal
	}
	k.records.mu.Lock()
	same = !k.records.closed && k.records.files[1] == b.file
	k.records.mu.Unlock()
	if !same {
		return ErrExecutionJournal
	}
	return nil
}

// After an actual next global replacement, compare the old transaction via
// its SAME FD and name, and the unlinked global ONLY via the typed original
// rename proof. Generic receipt validators are never relaxed for nlink zero.
func (k *domainTCPGlobalKeeper) historicalCurrent(ctx context.Context, b *domainTCPGlobalHistory) error {
	if k.original() != nil || b == nil || b.keeper != k {
		return ErrExecutionJournal
	}
	if err := b.currentHistorical(ctx); err != nil {
		return err
	}
	if k.retirement != nil {
		if err := k.retirement.retiredPoolCurrent(ctx); err != nil {
			return err
		}
	}
	d := k.records
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.closeErr != nil || d.files[0] == nil || d.infos[0] == nil || !bytes.Equal(d.images[0], k.image) {
		return errors.Join(ErrExecutionJournal, d.closeErr)
	}
	held, e1 := d.files[0].Stat()
	named, e2 := d.transactionRoot.Stat("execution.json")
	if e1 != nil || e2 != nil || !domainTCPGlobalInfoSame(d.infos[0], held) || !domainTCPGlobalInfoSame(held, named) {
		return errors.Join(ErrExecutionJournal, e1, e2)
	}
	hash, err := domainTCPGlobalHash(ctx, d.files[0], held.Size())
	closing, e1 := d.files[0].Stat()
	last, e2 := d.transactionRoot.Stat("execution.json")
	if err != nil || e1 != nil || e2 != nil || hash != k.digest || !domainTCPGlobalInfoSame(held, closing) || !domainTCPGlobalInfoSame(closing, last) {
		return errors.Join(ErrExecutionJournal, err, e1, e2)
	}
	return ctx.Err()
}

func (k *domainTCPGlobalKeeper) closeForSuccessor(ctx context.Context, c *domainTCPGlobalSuccessor) error {
	if k.original() != nil || c == nil || c.self != c || c.previousKeeper != k || c.previous == nil || c.previous.keeper != k || c.original() != nil {
		return ErrPolicyAdditionUnknown
	}
	k.closeMu.Lock()
	defer k.closeMu.Unlock()
	if k.closed.Load() {
		return nil
	} // SAME actual Close ACK, never a reopened FD.
	if k.closeErr != nil {
		return k.closeErr
	}
	if err := c.records.current(ctx, true); err != nil {
		return err
	}
	if err := k.historicalCurrent(ctx, c.previous); err != nil {
		return err
	}
	if !k.closed.Load() {
		if err := k.records.close(); err != nil {
			k.closeErr = errors.Join(ErrPolicyAdditionUnknown, err)
			return k.closeErr
		}
		if k.retirement != nil {
			if err := k.retirement.closePoolReceipts(); err != nil {
				k.closeErr = errors.Join(ErrPolicyAdditionUnknown, err)
				return k.closeErr
			}
		}
		k.closed.Store(true)
		k.ready.Store(false)
		k.pool.mu.Lock()
		if k.pool.keeper == k {
			k.pool.keeper = nil
		}
		k.pool.mu.Unlock()
	}
	return ctx.Err()
}
