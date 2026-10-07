// Package startuptools retains the protected, fixed xtables deployment used
// by trusted startup. A descriptor is tool identity, never effect admission.
package startuptools

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrUnknown = errors.New("trusted startup tool binding unavailable or changed")

const (
	operationTimeout = 2 * time.Second
	maxImageBytes    = 16 << 20
	maxReviewBytes   = 64 << 20
	maxImages        = 384
	maxEdges         = 2048
	maxOutputBytes   = 1 << 20
)

type failure struct {
	stage string
	cause error
}

func (e *failure) Error() string { return "trusted startup tools: " + e.stage }
func (e *failure) Unwrap() error { return e.cause }
func at(stage string, err error) error {
	return &failure{stage: stage, cause: errors.Join(ErrUnknown, err)}
}

// Lease has no caller-supplied paths, runner, hashes, filesystem or profile.
// Its factory context is its lifetime; use a service lifetime context, not a
// short acquisition-only context. Acquisition and each read are internally
// capped. Close cancels and joins reads/effects before releasing descriptors.
type Lease struct {
	provider  *netidentity.Provider
	identity  netidentity.Identity
	profile   profile
	review    *heldReview
	digest    string
	lifetime  context.Context
	cancel    context.CancelFunc
	gate      chan struct{}
	closeDone chan struct{}
	closeErr  error
	closed    atomic.Bool
	retainMu  sync.Mutex
	retained  sync.WaitGroup
}

// AcquireUbuntuLegacy selects only the reviewed Ubuntu AMD64 1.8.11 legacy
// main image. It does not discover a version/backend or choose from PATH.
func AcquireUbuntuLegacy(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquire(ctx, provider, ubuntuProfile())
}

// AcquireReviewedStockNC1812 selects only the reviewed ARM64 stock deployment.
// The supplied production provider must freshly issue its exact stock identity.
func AcquireReviewedStockNC1812(ctx context.Context, provider *netidentity.Provider) (*Lease, error) {
	return acquire(ctx, provider, stockProfile())
}

func (l *Lease) lock(ctx context.Context) error {
	if l == nil || ctx == nil || ctx.Err() != nil || l.gate == nil || l.lifetime == nil || l.closed.Load() || l.lifetime.Err() != nil {
		return at("LIFETIME", nil)
	}
	select {
	case <-ctx.Done():
		return at("CONTEXT", ctx.Err())
	case <-l.lifetime.Done():
		return at("LIFETIME", l.lifetime.Err())
	case <-l.gate:
	}
	if l.closed.Load() || l.lifetime.Err() != nil || ctx.Err() != nil {
		l.unlock()
		return at("LIFETIME", nil)
	}
	return nil
}
func (l *Lease) unlock() { l.gate <- struct{}{} }

func boundedReadContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, at("READ_DEADLINE", nil)
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 {
		return nil, nil, at("READ_DEADLINE", nil)
	}
	// A bounded whole capture may outlive this leaf command. Always impose
	// our own two-second cap while preserving a shorter original deadline.
	c, cancel := context.WithTimeout(ctx, operationTimeout)
	return c, cancel, nil
}

// InventoryTools returns the fixed collector binding while retaining the same
// opaque lease. Copying this descriptor cannot extend lifetime or replace Check.
func (l *Lease) InventoryTools() (dataplane.BackendInventoryTools, error) {
	if l == nil || l.lifetime == nil {
		return dataplane.BackendInventoryTools{}, at("LIFETIME", nil)
	}
	c, cancel := context.WithTimeout(l.lifetime, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return dataplane.BackendInventoryTools{}, err
	}
	defer l.unlock()
	if l.review == nil || l.digest == "" || l.provider == nil || l.identity.Validate() != nil {
		return dataplane.BackendInventoryTools{}, at("UNISSUED", nil)
	}
	return dataplane.BackendInventoryTools{Runner: l, IPTables: l.profile.aliases[0], IP6Tables: l.profile.aliases[1], ReviewSHA256: l.digest, Check: l.Check}, nil
}

// Check independently verifies the held review and actual network identity.
// This callback never consults caller metadata as its issuer or performs writes.
func (l *Lease) Check(ctx context.Context, expected netidentity.Identity) error {
	if ctx == nil || expected.Validate() != nil {
		return at("CHECK_SCOPE", nil)
	}
	c, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	if err := l.lock(c); err != nil {
		return err
	}
	defer l.unlock()
	stop := context.AfterFunc(l.lifetime, cancel)
	defer stop()
	return l.current(c, expected, true)
}

// Run implements the existing runner shape only for the same fixed read ABI.
// In particular it cannot be used as an unguarded policy effect runner.
func (l *Lease) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return l.RunBounded(ctx, name, maxOutputBytes, args...)
}

func readArguments(args []string) bool {
	if len(args) != 3 || args[0] != "-t" || args[2] != "-S" {
		return false
	}
	// Same canonical name bound as the complete registered-table collector.
	// Unknown table names must remain observable; the command shape is fixed.
	name := args[1]
	if len(name) == 0 || len(name) > 31 || name[0] == '-' {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// Close linearizes with every callback and subprocess and releases all files.
// Repeated Close is harmless; no subsequent callback can issue evidence.
func (l *Lease) Close() error {
	if l == nil {
		return nil
	}
	if !l.closed.CompareAndSwap(false, true) {
		if l.closeDone != nil {
			<-l.closeDone
		}
		return l.closeErr
	}
	if l.closeDone != nil {
		defer close(l.closeDone)
	}
	if l.cancel != nil {
		l.cancel()
	}
	// Join retain's closed check and Add before Wait. External admission may
	// reenter Check, so it retains lifetime without holding the command gate.
	l.retainMu.Lock()
	l.retainMu.Unlock()
	l.retained.Wait()
	if l.gate == nil {
		return nil
	}
	<-l.gate
	defer l.unlock()
	if l.review == nil {
		return nil
	}
	l.closeErr = l.review.close()
	l.review = nil
	return l.closeErr
}

func (l *Lease) retain(ctx context.Context) error {
	if l == nil || ctx == nil {
		return at("LIFETIME", nil)
	}
	l.retainMu.Lock()
	defer l.retainMu.Unlock()
	if ctx.Err() != nil || l.lifetime == nil || l.lifetime.Err() != nil || l.closed.Load() || l.gate == nil {
		return at("LIFETIME", nil)
	}
	l.retained.Add(1)
	return nil
}
