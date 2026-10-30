package privaterestore

import (
	"context"
	"errors"
	"os"
	"sort"
	"sync"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/nativeenrollment"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerfeed"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrRuntimeStarted = errors.New("private offline restore is unavailable after runtime handover")

// Keep the recovery fence and typed causes while exposing only closed stages.
// Target errors may contain private paths or images and must not be logged.
type openRecoveryFailure struct {
	stage string
	cause error
}

func (e *openRecoveryFailure) Error() string {
	return restorejournal.ErrRecovery.Error() + " (" + e.stage + ")"
}
func (e *openRecoveryFailure) Unwrap() []error {
	return []error{restorejournal.ErrRecovery, e.cause}
}
func openingRecoveryError(cause error, closeFailed bool) error {
	stage := "journal-recover-required"
	switch {
	case errors.Is(cause, restorejournal.ErrInvalid):
		stage = "journal-recover-invalid"
	case errors.Is(cause, context.DeadlineExceeded):
		stage = "journal-recover-deadline"
	case errors.Is(cause, context.Canceled):
		stage = "journal-recover-canceled"
	case errors.Is(cause, restorejournal.ErrUnavailable):
		stage = "journal-recover-unavailable"
	case errors.Is(cause, restorejournal.ErrBusy):
		stage = "journal-recover-busy"
	case errors.Is(cause, restorejournal.ErrAborted):
		stage = "journal-recover-aborted"
	case closeFailed:
		stage = "target-close-required"
	}
	return &openRecoveryFailure{stage: stage, cause: cause}
}

type managedTarget interface {
	restorejournal.Target
	Close() error
}
type slot struct {
	id      string
	owner   *Coordinator
	factory func() (managedTarget, error)
	target  managedTarget
}

func (s *slot) open(ctx context.Context) (managedTarget, error) {
	if ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if s.target == nil {
		if s.owner.runtimeStarted {
			return nil, restorejournal.ErrInvalid // Online calls must bind Store sessions.
		}
		t, err := s.factory()
		if err != nil {
			return nil, err
		}
		s.target = t
		s.owner.acquired = append(s.owner.acquired, s)
	}
	return s.target, nil
}
func (s *slot) Read(ctx context.Context) (restorejournal.Image, error) {
	t, err := s.open(ctx)
	if err != nil {
		return restorejournal.Image{}, err
	}
	return t.Read(ctx)
}
func (s *slot) CompareAndSwap(ctx context.Context, before, after restorejournal.Image) error {
	t, err := s.open(ctx)
	if err != nil {
		return err
	}
	if s.owner.beforeWrite != nil {
		if err := s.owner.beforeWrite(s.id); err != nil {
			return err
		}
	}
	if err := t.CompareAndSwap(ctx, before, after); err != nil {
		return err
	}
	if s.owner.afterWrite != nil {
		s.owner.afterWrite(s.id)
	}
	return nil
}

// Coordinator holds the journal OS lease for its whole lifetime. Competing new
// servers with the same journal root fail BEFORE loading or creating any Store.
// Store-file leases are acquired lazily for trusted recorded targets only, kept
// across the entire transaction and released in reverse acquisition order.
type Coordinator struct {
	mu                              sync.Mutex
	layout                          Layout
	journal                         *restorejournal.Journal
	slots                           map[string]*slot
	acquired                        []*slot
	closed, blocked, runtimeStarted bool
	// Package-private crash/failure seams around REAL typed target writes.
	beforeWrite    func(string) error
	afterWrite     func(string)
	beforeHandover func() error
}

func (*Coordinator) String() string   { return "[private draft recovery coordinator]" }
func (*Coordinator) GoString() string { return "[private draft recovery coordinator]" }

// Open recovers before any application Store/worker/API starts. A clean journal
// never opens optional provider/draft files or creates their directories. A bad
// journal/target is preserved and blocks startup. No empty-default repair.
func Open(ctx context.Context, layout Layout) (*Coordinator, restorejournal.Outcome, error) {
	return openCoordinator(ctx, layout, true)
}

// OpenForOfflineNFQWS2Stop acquires the same real lifetime lease as Open, but
// requires an idle journal. An already pending explicit Stop must not replay
// an unrelated private restore before it checks its frozen configuration.
// No target is opened, read, restored or normalized by this entry point.
func OpenForOfflineNFQWS2Stop(ctx context.Context, layout Layout) (*Coordinator, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, restorejournal.ErrInvalid
	}
	c, _, err := openCoordinator(ctx, layout, false)
	return c, err
}

func openCoordinator(ctx context.Context, layout Layout, recoverTargets bool) (*Coordinator, restorejournal.Outcome, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, restorejournal.Blocked, restorejournal.ErrAborted
	}
	layout, scope, err := normalizeLayout(layout)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	if err := os.MkdirAll(layout.JournalRoot, 0o700); err != nil {
		return nil, restorejournal.Blocked, restorejournal.ErrUnavailable
	}
	c := &Coordinator{layout: layout, slots: map[string]*slot{}}
	add := func(id string, factory func() (managedTarget, error)) {
		c.slots[id] = &slot{id: id, owner: c, factory: factory}
	}
	add("config", func() (managedTarget, error) { return config.OpenRestoreTarget(layout.Config) })
	add("custom_services", func() (managedTarget, error) { return customservices.OpenRestoreTarget(layout.CustomServices) })
	add("devices", func() (managedTarget, error) { return devices.OpenRestoreTarget(layout.Devices) })
	add("provider_cloudflare", func() (managedTarget, error) { return cloudflareprovider.OpenRestoreTarget(layout.ProviderRoot) })
	if layout.NodeRoot != "" {
		add("nodes", func() (managedTarget, error) { return nodestore.OpenRestoreTarget(layout.NodeRoot) })
	}
	if layout.WarpRoot != "" {
		add("native_warp", func() (managedTarget, error) { return nativeenrollment.Open(layout.WarpRoot) })
	}
	if layout.FeedRoot != "" {
		add("subscriptions", func() (managedTarget, error) { return providerfeed.OpenRestoreTarget(layout.FeedRoot) })
	}
	for _, spec := range engineconfig.Specs() {
		for _, file := range spec.Files {
			add(draftID(spec.ID, file.ID), func() (managedTarget, error) {
				return engineconfig.OpenRestoreTarget(layout.StageRoot, spec.ID, file.ID)
			})
		}
	}
	targets := map[string]restorejournal.Target{}
	for id, s := range c.slots {
		targets[id] = s
	}
	c.journal, err = restorejournal.Open(layout.JournalRoot, scope, targets)
	if err != nil {
		return nil, restorejournal.Blocked, err
	}
	out := restorejournal.Clean
	if recoverTargets {
		out, err = c.journal.Recover(ctx)
	} else {
		err = c.journal.RequireIdle(ctx)
	}
	closeErr := c.releaseTargets()
	if err != nil || closeErr != nil || out == restorejournal.Blocked {
		_ = c.journal.Close()
		// Recover deliberately returns a recovery fence when its context has
		// expired, including an empty journal. Preserve that diagnostic fact;
		// a subsequent normal retry still reopens and validates the journal.
		return nil, restorejournal.Blocked, openingRecoveryError(errors.Join(err, ctx.Err()), closeErr != nil)
	}
	return c, out, nil
}

func (c *Coordinator) releaseTargets() error {
	var result error
	for i := len(c.acquired) - 1; i >= 0; i-- {
		s := c.acquired[i]
		if err := s.target.Close(); err != nil {
			result = restorejournal.ErrRecovery
		}
		s.target = nil
	}
	c.acquired = nil
	return result
}

// StartRuntime irreversibly seals the offline interface. Keep the Coordinator
// alive until shutdown; it remains the deployment's journal/instance guard.
// RestoreOnline additionally requires Store sessions + API/worker exclusion.
func (c *Coordinator) StartRuntime() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.blocked {
		return restorejournal.ErrRecovery
	}
	c.runtimeStarted = true
	return nil
}

func (c *Coordinator) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	err := c.releaseTargets()
	if closeErr := c.journal.Close(); closeErr != nil {
		err = closeErr
	}
	return err
}

// acquireAll is used by planning to obtain the whole set in deterministic order
// before reading/building images. Failure causes no target writes.
func (c *Coordinator) acquireAll(ctx context.Context, ids []string) error {
	sort.Strings(ids)
	for _, id := range ids {
		s := c.slots[id]
		if s == nil {
			return restorejournal.ErrInvalid
		}
		if _, err := s.open(ctx); err != nil {
			return err
		}
	}
	return nil
}
