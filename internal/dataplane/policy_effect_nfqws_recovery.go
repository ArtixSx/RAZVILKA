package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
)

// One original execution owns at most one retained COMMON writer. No decoded
// receipt, public flag, copied binding or restarted process can create it.
// mu spans Apply or rollback; shutdown takes ONLY mu, never an execution lock.
type nfqwsPolicyRecovery struct {
	self            *nfqwsPolicyRecovery
	mu              sync.Mutex
	execution       *nfqws2ActiveExecution
	session         *policyEffectSession
	index           int
	entered         bool
	retained        bool
	settled         bool
	closed          bool
	fenced          bool
	needsSync       bool
	pending         *os.File
	pendingRaw      []byte
	publication     uint64
	scope           atomic.Pointer[nfqwsRecoveryScope]
	shutdownStop    func() bool
	intentBefore    *nfqwsIntentBefore
	renameAttempted bool
}

type nfqwsIntentBefore struct {
	publication uint64
	checksum    string
	file        *os.File
	info        os.FileInfo
	raw         []byte
}

type nfqwsPolicyRecoveryKey struct{}

type nfqwsRecoveryScope struct {
	self    *nfqwsRecoveryScope
	owner   *nfqwsPolicyRecovery
	closed  atomic.Bool
	readers sync.RWMutex
}

func (c *nfqwsPolicyRecovery) scopeCurrent(ctx context.Context) bool {
	scope, ok := ctx.Value(nfqwsPolicyRecoveryKey{}).(*nfqwsRecoveryScope)
	return ok && scope != nil && scope.self == scope && scope.owner == c && !scope.closed.Load() && c.scope.Load() == scope
}

func (c *nfqwsPolicyRecovery) intent(index int) {
	c.index, c.entered = index, false
	c.renameAttempted = false
	b := c.session.borrow
	b.mu.Lock()
	c.intentBefore = &nfqwsIntentBefore{publication: c.publication, checksum: c.session.doc.Checksum, file: b.published, info: b.publishedInfo, raw: append([]byte(nil), b.publishedBytes...)}
	b.mu.Unlock()
}

func (c *nfqwsPolicyRecovery) finishApply() {
	// This is a private control-flow witness, not inference from kernel state.
	// Even an unsuccessful intent publication retains custody but cannot settle
	// unless the actual authored inode/image is subsequently proven exact.
	c.retained = c.self == c && c.session != nil && c.index >= 0 && c.index < len(c.session.doc.Steps) && !c.entered && c.session.doc.Steps[c.index].State == "intent"
	if c.retained && !c.fenced && !c.renameAttempted && c.intentBefore != nil && c.publication == c.intentBefore.publication {
		if c.restoreUnpublishedIntent() == nil {
			c.retained = false // Existing known-prefix Remove remains available.
		} else {
			c.fenced = true // A changed original cannot be reopened/adopted.
		}
	}
	if !c.retained && c.pending != nil {
		c.pending.Close()
		c.pending = nil
	}
}

// No rename was attempted and no new publication was returned. Prove the
// exact prior authored image with bounded retained-FD reads before restoring
// only private memory. This has no callback, command, publication or revived
// forward context; a canceled Apply may still release an unchanged writer.
func (c *nfqwsPolicyRecovery) restoreUnpublishedIntent() error {
	b, before := c.session.borrow, c.intentBefore
	b.mu.Lock()
	defer b.mu.Unlock()
	if before == nil || before.file == nil || before.info == nil || len(before.raw) == 0 || len(before.raw) > policyAdditionMaxBytes || b.published != before.file || !bytes.Equal(b.publishedBytes, before.raw) || b.currentOwner() != nil {
		return ErrPolicyAdditionReceipt
	}
	info, err := before.file.Stat()
	named, namedErr := c.session.root.Stat(policyAdditionFile)
	if err != nil || namedErr != nil || !os.SameFile(before.info, info) || !os.SameFile(info, named) || info.Size() != int64(len(before.raw)) {
		return errors.Join(ErrPolicyAdditionReceipt, err, namedErr)
	}
	raw := make([]byte, len(before.raw))
	defer clear(raw)
	n, readErr := before.file.ReadAt(raw, 0)
	closing, closeErr := c.session.root.Stat(policyAdditionFile)
	if readErr != nil || n != len(raw) || !bytes.Equal(raw, before.raw) || closeErr != nil || !os.SameFile(info, closing) || b.currentOwner() != nil {
		return errors.Join(ErrPolicyAdditionReceipt, readErr, closeErr)
	}
	c.session.doc.Steps[c.index].State, c.session.doc.Checksum = "planned", before.checksum
	return nil
}

func (c *nfqwsPolicyRecovery) close() {
	if scope := c.scope.Load(); scope != nil {
		scope.closed.Store(true)
		scope.readers.Lock()
		defer scope.readers.Unlock()
	}
	if c.closed {
		return
	}
	c.closed = true
	if c.shutdownStop != nil {
		c.shutdownStop()
		c.shutdownStop = nil
	}
	if c.pending != nil {
		c.pending.Close()
		c.pending = nil
	}
	if c.retained && c.session != nil {
		c.session.borrow.close()
		c.session.close()
	}
}

func (c *nfqwsPolicyRecovery) save(ctx context.Context, s *policyEffectSession) error {
	if ctx == nil || c == nil || c.self != c || c.closed || c.fenced || c.session != s || s.borrow == nil || c.pending != nil {
		return ErrPolicyAdditionUnknown
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkWGCommonBeforePublication(ctx, s.policyAdditionSession); err != nil {
		return err
	}
	if err := s.borrow.currentOwner(); err != nil {
		return err
	}
	s.doc.Checksum = policyAdditionChecksum(s.doc)
	raw, err := json.Marshal(s.doc)
	if err != nil || len(raw) > policyAdditionMaxBytes {
		return ErrPolicyAdditionReceipt
	}
	if err := s.fault("nfq-original-before-write", c.index); err != nil {
		return err
	}
	file, attempted, err := s.root.WriteAtomicRetainedAttempted(policyAdditionFile, raw, 0600)
	c.renameAttempted = c.renameAttempted || attempted
	if err != nil {
		// The primitive cannot return custody after an ambiguous rename error.
		// Neither reopening the path nor an identical readback repairs that loss.
		c.fenced = c.fenced || attempted
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	// Take ownership BEFORE fault, cancellation, directory sync or old-FD close.
	c.pending, c.pendingRaw, c.needsSync = file, raw, true
	c.publication++
	if err := s.fault("nfq-original-publication", c.index); err != nil {
		return err
	}
	if err := c.finishPublication(ctx); err != nil {
		return err
	}
	// Preserve existing cross-participant publication checks. Their normal NFQ
	// path is a no-op; an unexpected foreign owner must not bypass its fence.
	return errors.Join(captureXraySelectedTCPPolicyPublication(ctx, s.borrow), captureWGCommonPublication(ctx, s.policyAdditionSession, s.borrow.published))
}

// All callers hold c.mu. Installing the actual newly authored FD transfers
// ownership before closing the old one, so even a close error cannot drop it.
func (c *nfqwsPolicyRecovery) installPending() error {
	if c.pending == nil {
		return nil
	}
	b := c.session.borrow
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.currentOwner(); err != nil {
		return err
	}
	file := c.pending
	before, err := file.Stat()
	named, namedErr := c.session.root.Stat(policyAdditionFile)
	if err != nil || namedErr != nil || !validNetworkPolicyReceiptFile(before) || !os.SameFile(before, named) || before.Size() != int64(len(c.pendingRaw)) {
		return errors.Join(ErrPolicyAdditionReceipt, err, namedErr)
	}
	raw := make([]byte, len(c.pendingRaw))
	defer clear(raw)
	n, readErr := file.ReadAt(raw, 0)
	closing, closeErr := c.session.root.Stat(policyAdditionFile)
	if readErr != nil || n != len(raw) || !bytes.Equal(raw, c.pendingRaw) || closeErr != nil || !os.SameFile(before, closing) || b.currentOwner() != nil {
		return errors.Join(ErrPolicyAdditionReceipt, readErr, closeErr)
	}
	old := b.published
	b.published, b.publishedInfo, b.publishedBytes = file, before, c.pendingRaw
	c.pending, c.pendingRaw = nil, nil
	if old != nil {
		return old.Close()
	}
	return nil
}

func (c *nfqwsPolicyRecovery) documentCurrent(ctx context.Context) error {
	if c == nil || c.self != c || c.closed || c.fenced || c.session == nil || c.session.nfqRecovery != c || ctx == nil || ctx.Err() != nil {
		return errors.Join(ErrPolicyAdditionUnknown, networkPolicyChecksContextError(ctx))
	}
	s := c.session
	borrowed := context.WithValue(ctx, policyEffectReceiptBorrowKey{}, s.borrow)
	o, present, err := observeBorrowedPolicyEffects(borrowed, s.plan, s.path)
	if err != nil || !present || o.absent {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	defer o.close()
	expected, err := json.Marshal(s.doc)
	if err != nil || !bytes.Equal(o.canonical, expected) {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	return o.current(borrowed)
}

func (c *nfqwsPolicyRecovery) finishPublication(ctx context.Context) error {
	if c == nil || c.self != c || c.closed || c.fenced || ctx == nil || ctx.Err() != nil {
		return errors.Join(ErrPolicyAdditionUnknown, networkPolicyChecksContextError(ctx))
	}
	if err := c.installPending(); err != nil {
		return err
	}
	if err := c.documentCurrent(ctx); err != nil {
		return err
	}
	if c.needsSync {
		if err := c.session.fault("nfq-original-before-sync", c.index); err != nil {
			return err
		}
		if runtime.GOOS == "linux" {
			if err := c.session.root.Sync(); err != nil {
				return errors.Join(ErrPolicyAdditionReceipt, err)
			}
		}
		if err := c.session.fault("nfq-original-after-sync", c.index); err != nil {
			return err
		}
	}
	if err := c.documentCurrent(ctx); err != nil {
		return err
	}
	c.needsSync = false
	return nil
}

// Used only by the original NFQ cleanup context while its sole writer is held.
// It provides the same parser/status and both original-file bookends, no grant.
func inspectNFQWSRecoveryReceipt(ctx context.Context, plan PolicyEffectPlan, path string) (PolicyAdditionStatus, bool, error) {
	var zero PolicyAdditionStatus
	raw := ctx.Value(nfqwsPolicyRecoveryKey{})
	if raw == nil {
		return zero, false, nil
	}
	scope, ok := raw.(*nfqwsRecoveryScope)
	if !ok || scope == nil || scope.self != scope || scope.owner == nil {
		return zero, true, ErrPolicyAdditionUnknown
	}
	scope.readers.RLock()
	defer scope.readers.RUnlock()
	if scope.closed.Load() {
		return zero, true, ErrPolicyAdditionUnknown
	}
	c := scope.owner
	if c.self != c || !c.scopeCurrent(ctx) || c.closed || !c.retained || c.execution == nil || c.execution.partialRecovery != c || c.session == nil || c.session.path != path || !reflect.DeepEqual(c.session.plan, plan) || ctx.Value(policyEffectReceiptBorrowKey{}) != c.session.borrow || ctx.Value(nfqws2ActiveExecutionKey{}) != c.execution {
		return zero, true, ErrPolicyAdditionUnknown
	}
	// Read only the borrow's immutable publication/parser view, never s.doc:
	// actual COMMON publication may be in progress on the writer goroutine.
	o, present, err := observeBorrowedPolicyEffects(ctx, plan, path)
	if err != nil || !present {
		return zero, true, errors.Join(ErrPolicyAdditionUnknown, err)
	}
	defer o.close()
	return o.status, true, o.current(ctx)
}
