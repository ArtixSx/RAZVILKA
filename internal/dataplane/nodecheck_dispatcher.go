package dataplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
)

// ExactNodeDispatcher shares one non-blocking quota across runtime-specific
// views. Configure its checkers before construction; use only its views after
// construction. Calling the underlying checkers directly bypasses the quota.
type ExactNodeDispatcher struct {
	gate     chan struct{}
	checkers map[string]*ExactNodeChecker
	order    []*ExactNodeChecker
}

// NewExactNodeDispatcher rejects ambiguous ownership and overlapping runtime
// resources. The total quota is 1..MaxExactNodeSlots, never the sum of engines.
func NewExactNodeDispatcher(slots int, checkers ...*ExactNodeChecker) (*ExactNodeDispatcher, error) {
	if slots < 1 || slots > MaxExactNodeSlots || len(checkers) < 1 || len(checkers) > 2 {
		return nil, ErrExactNodeUnavailable
	}
	d := &ExactNodeDispatcher{gate: make(chan struct{}, slots), checkers: map[string]*ExactNodeChecker{}}
	for _, c := range checkers {
		if c == nil || c.Capacity() == 0 || !filepath.IsAbs(c.StateRoot) || filepath.Clean(c.StateRoot) == filepath.VolumeName(c.StateRoot)+string(filepath.Separator) || c.Port < 1024 || c.Port+MaxExactNodeSlots-1 > 65535 || d.checkers[c.EngineID()] != nil {
			return nil, ErrExactNodeUnavailable
		}
		for _, other := range d.order {
			if exactRootsOverlap(c.StateRoot, other.StateRoot) || c.Port < other.Port+MaxExactNodeSlots && other.Port < c.Port+MaxExactNodeSlots {
				return nil, ErrExactNodeUnavailable
			}
		}
		d.checkers[c.EngineID()] = c
		d.order = append(d.order, c)
	}
	return d, nil
}

func exactRootsOverlap(a, b string) bool {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, err := filepath.Rel(filepath.Clean(pair[0]), filepath.Clean(pair[1]))
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (d *ExactNodeDispatcher) Capacity() int {
	if d == nil {
		return 0
	}
	return cap(d.gate)
}

// ForEngine returns a fixed executor view suitable for App.NodeChecker. There
// is no fallback to another engine if a profile/runtime is unsupported.
func (d *ExactNodeDispatcher) ForEngine(engine string) (*DispatchedNodeChecker, error) {
	if d == nil || d.checkers[engine] == nil {
		return nil, ErrExactNodeUnsupported
	}
	return &DispatchedNodeChecker{dispatcher: d, checker: d.checkers[engine]}, nil
}

// Recover excludes all dispatched checks/screens while recovering every
// engine. One runtime's failure does not skip cleanup of the other runtime.
func (d *ExactNodeDispatcher) Recover(ctx context.Context) error {
	if d == nil || d.gate == nil {
		return ErrExactNodeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	acquired := 0
	defer func() {
		for range acquired {
			<-d.gate
		}
	}()
	for range cap(d.gate) {
		select {
		case d.gate <- struct{}{}:
			acquired++
		default:
			return ErrExactNodeBusy
		}
	}
	var errs []error
	for _, c := range d.order {
		errs = append(errs, c.Recover(ctx))
	}
	return errors.Join(errs...)
}

// DispatchedNodeChecker implements NodeChecker, NodeCheckCapacity and
// TransportScreener. Screens share the quota too, bounding DNS/TCP work.
type DispatchedNodeChecker struct {
	dispatcher *ExactNodeDispatcher
	checker    *ExactNodeChecker
}

func (c *DispatchedNodeChecker) EngineID() string {
	if c == nil || c.checker == nil {
		return ""
	}
	return c.checker.EngineID()
}
func (c *DispatchedNodeChecker) Capacity() int {
	if c == nil || c.dispatcher == nil || c.checker == nil {
		return 0
	}
	return min(c.dispatcher.Capacity(), c.checker.Capacity())
}
func (c *DispatchedNodeChecker) Recover(ctx context.Context) error {
	if c == nil {
		return ErrExactNodeUnavailable
	}
	return c.dispatcher.Recover(ctx)
}

func (c *DispatchedNodeChecker) acquire(ctx context.Context, request NodeCheckRequest) error {
	if c == nil || c.dispatcher == nil || c.checker == nil {
		return ErrExactNodeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Capability rejection must precede the shared quota and any DNS work.
	if err := c.checker.validRequest(ctx, request); err != nil {
		return err
	}
	select {
	case c.dispatcher.gate <- struct{}{}:
		return nil
	default:
		return ErrExactNodeBusy
	}
}

func (c *DispatchedNodeChecker) Check(ctx context.Context, request NodeCheckRequest) (NodeCheckResult, error) {
	if err := c.acquire(ctx, request); err != nil {
		return NodeCheckResult{}, err
	}
	defer func() { <-c.dispatcher.gate }()
	return c.checker.Check(ctx, request)
}

func (c *DispatchedNodeChecker) ScreenTransport(ctx context.Context, request NodeCheckRequest) (NodeCheckResult, bool, error) {
	if err := c.acquire(ctx, request); err != nil {
		return NodeCheckResult{}, false, err
	}
	defer func() { <-c.dispatcher.gate }()
	return c.checker.ScreenTransport(ctx, request)
}
