package dataplane

import (
	"context"
	"errors"
	"sync"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privaterestore"
	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

var ErrMihomoSameBootRetainedRetry = errors.New("original same-boot cleanup retains a retryable acknowledgment")

// Issued only by the original stop-sidecar failure branch, before any policy
// or forwarding phase. A generic unknown/effect error cannot mint this state.
type mihomoSameBootSidecarWaitFailure struct {
	cursor  *mihomoSameBootRetirementCursor
	sidecar *mihomoSameBootSidecar
	cause   error
}

func (p *mihomoSameBootSidecarWaitFailure) Error() string {
	return "original sidecar terminal acknowledgment remains unknown"
}
func (p *mihomoSameBootSidecarWaitFailure) Unwrap() error { return p.cause }

func (c *mihomoSameBootRetirementCursor) sidecarWaitPhase() bool {
	return c != nil && c.self == c && !c.closed && !c.sidecarDone && !c.policyDone && !c.forwardingDone && c.runtimeAfter == nil && c.finalTree == nil && c.home == nil && c.owner != nil && c.owner.self == c.owner && !c.owner.effectsClosed && !c.owner.effectUnknown && c.owner.sidecar != nil
}

func (c *mihomoSameBootRetirementCursor) sidecarFailureAfterAttempt(err error) error {
	if err == nil || !c.sidecarWaitPhase() {
		return err
	}
	s := c.owner.sidecar
	if s.self != s || !s.validated || !s.attempted || s.terminal || s.closed || s.closeErr != nil {
		return err
	}
	return &mihomoSameBootSidecarWaitFailure{cursor: c, sidecar: s, cause: err}
}

func (p *mihomoSameBootSidecarWaitFailure) matches(c *mihomoSameBootRetirementCursor) bool {
	return p != nil && p.cursor == c && c.sidecarWaitPhase() && c.unknown == p && c.owner.sidecar == p.sidecar && p.sidecar.self == p.sidecar && p.sidecar.validated && p.sidecar.attempted && !p.sidecar.terminal && !p.sidecar.closed && p.sidecar.closeErr == nil
}

// MihomoSameBootRetirement exists only in its synchronous five-lease callback.
// It is a cleanup cursor, not a warm runtime owner or saved permission. Calls
// serialize through the SAME Manager operation and exact original context.
type MihomoSameBootRetirement struct {
	mu              sync.Mutex
	self            *MihomoSameBootRetirement
	ctx             context.Context
	cursor          *mihomoSameBootRetirementCursor
	open, attempted bool
	lastErr         error
	retryArchive    string
	retrySidecar    bool
	retryTerminal   int
}

func (m *Manager) WithMihomoSameBootRetirement(ctx context.Context, id, digest string, set *privaterestore.OfflineServiceControlSet, control *operationgate.ControlEpochReview, cleanup *operationgate.ExclusiveCleanupReview, controlRoot string, history *updatecheck.ExecutionHistoryAdmission, use func(context.Context, *MihomoSameBootRetirement) error) (resultErr error) {
	if use == nil {
		return ErrMihomoLiveRetirement
	}
	c, err := m.prepareMihomoSameBootRetirement(ctx, id, digest, set, control, cleanup, controlRoot, history)
	if err != nil {
		return err
	}
	h := &MihomoSameBootRetirement{ctx: ctx, cursor: c, open: true}
	h.self = h
	defer func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.open = false
		resultErr = errors.Join(resultErr, h.lastErr, c.close())
	}()
	return use(ctx, h)
}

func (h *MihomoSameBootRetirement) Run(ctx context.Context) (Execution, error) {
	if h == nil || h.self != h {
		return Execution{}, ErrMihomoLiveRetirement
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.open || ctx != h.ctx || h.attempted {
		return Execution{}, ErrMihomoLiveRetirement
	}
	h.attempted = true
	return h.runLocked()
}

// Retry repeats a classified SAME authored archive durability ACK, or waits
// for the already-signaled SAME original pidfd to become terminal. It never
// reopens a pathname, looks up a PID or retries an uncertain native command.
// A new context cannot extend the five callbacks or cleanup admission.
func (h *MihomoSameBootRetirement) Retry(ctx context.Context) (Execution, error) {
	if h == nil || h.self != h {
		return Execution{}, ErrMihomoLiveRetirement
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.open || ctx != h.ctx || !h.attempted || h.retryArchive == "" && !h.retrySidecar && h.retryTerminal == 0 || !errors.Is(h.lastErr, ErrMihomoSameBootRetainedRetry) {
		return Execution{}, errors.Join(h.lastErr, ErrMihomoLiveRetirement)
	}
	c := h.cursor
	if h.retrySidecar {
		pending, ok := c.unknown.(*mihomoSameBootSidecarWaitFailure)
		if !ok || !pending.matches(c) {
			return h.failRetryLocked(ErrMihomoLiveRetirement)
		}
		if c.owner == nil || c.owner.inputs == nil || c.owner.inputs.definition.Observation == nil || c.owner.sidecar == nil || c.owner.sidecar.pid <= 1 || c.owner.sidecar.receipt != c.owner.inputs.definition.Observation.SidecarReceiptSHA256 {
			return h.failRetryLocked(ErrMihomoLiveRetirement)
		}
		if err := c.originalInputsCurrent(); err != nil {
			return h.failRetryLocked(err)
		}
		if err := waitMihomoSameBootSidecarExit(ctx, c.owner.sidecar, c.owner.static); err != nil {
			return h.failRetryLocked(err)
		}
		if err := errors.Join(c.originalInputsCurrent(), c.owner.current(ctx)); err != nil {
			return h.failRetryLocked(err)
		}
		if !pending.matches(c) {
			return h.failRetryLocked(ErrMihomoLiveRetirement)
		}
		// New actual terminal and full absence knowledge, from the SAME pidfd
		// and original source. No saved unknown/finalizing execution is edited.
		c.owner.sidecar.terminal, c.sidecarDone = true, true
		c.unknown = nil
		return h.runLocked()
	}
	if err := c.beforeSidecar(); err != nil {
		return h.failRetryLocked(err)
	}
	if h.retryTerminal != 0 {
		n := h.retryTerminal - 1
		if n < 0 || n > 1 || !c.owner.effectsClosed || !c.terminalPending[n] || c.terminalCloseErr != nil {
			return h.failRetryLocked(ErrMihomoLiveRetirement)
		}
		return h.runLocked()
	}
	if c.archive == nil || c.archive.records[h.retryArchive] == nil {
		return h.failRetryLocked(ErrMihomoLiveRetirement)
	}
	if err := c.archive.current(); err != nil {
		return h.failRetryLocked(err)
	}
	return h.runLocked()
}

// An observed source/identity/Close loss revokes this retry opportunity even
// if a later pathname/readback looks current again. Never erase that cause.
func (h *MihomoSameBootRetirement) failRetryLocked(err error) (Execution, error) {
	h.lastErr = errors.Join(h.lastErr, err)
	h.retryArchive, h.retrySidecar, h.retryTerminal = "", false, 0
	return Execution{}, h.lastErr
}

func (h *MihomoSameBootRetirement) runLocked() (Execution, error) {
	c := h.cursor
	c.retryArchive = ""
	c.retryTerminal = 0
	result, err := c.run()
	h.retryArchive = c.retryArchive
	h.retryTerminal = c.retryTerminal
	h.retrySidecar = false
	if pending, ok := err.(*mihomoSameBootSidecarWaitFailure); ok && pending.matches(c) {
		h.retrySidecar = c.originalInputsCurrent() == nil
	}
	if err != nil && (h.retryArchive != "" || h.retrySidecar || h.retryTerminal != 0) {
		err = errors.Join(err, ErrMihomoSameBootRetainedRetry)
	}
	h.lastErr = err
	return result, err
}

func (c *mihomoSameBootRetirementCursor) publishArchive(name string, value any, current func() error) error {
	err := c.archive.publish(name, value, current)
	if err == nil && c.retryArchive == name {
		c.retryArchive = ""
	}
	ack, ownedACK := err.(*mihomoSameBootArchiveACKError)
	if ownedACK && ack != nil && ack.archive == c.archive && ack.name == name && c.archive.closeErr == nil && c.owner != nil && c.owner.self == c.owner && !c.owner.effectUnknown && c.unknown == nil && c.archive.records[name] != nil && c.archive.current() == nil && current() == nil {
		// Only an actually authored retained FD with complete current source
		// bookends is retryable; pre-publication, foreign or unknown errors are not.
		c.retryArchive = name
	}
	return err
}
