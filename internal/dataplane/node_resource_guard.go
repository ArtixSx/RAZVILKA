package dataplane

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"sync"

	"github.com/ArtixSx/razvilka/internal/evidence"
)

var ErrNodeResourceDenied = errors.New("node resource observation refused")

type nodeResourceGuardKey struct{}
type nodeResourceGuard struct {
	check func(context.Context, string, netip.Addr) error
	mu    sync.Mutex
	err   error
}

// WithNodeResourceGuard adds only a denial boundary. It grants no source,
// process, client or route permission. App candidates must install it from
// their actual Store; standalone explicit diagnostics retain their own scope.
// The first refusal is sticky, including through a probe's generic error path.
func WithNodeResourceGuard(ctx context.Context, check func(context.Context, string, netip.Addr) error) context.Context {
	return context.WithValue(ctx, nodeResourceGuardKey{}, &nodeResourceGuard{check: check})
}

func checkNodeResource(ctx context.Context, host string, address netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	g, _ := ctx.Value(nodeResourceGuardKey{}).(*nodeResourceGuard)
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.err != nil {
		return g.err
	}
	if g.check == nil {
		g.err = ErrNodeResourceDenied
	} else if err := g.check(ctx, host, address); err != nil {
		g.err = errors.Join(ErrNodeResourceDenied, err)
	}
	return g.err
}

// nodeResourceRefusal returns the sticky refusal of ctx's guard, if any. Unlike
// checkNodeResource it neither runs the check nor stops at the end of ctx, so
// a refusal made before a deadline still wins over a timeout explanation.
func nodeResourceRefusal(ctx context.Context) error {
	g, _ := ctx.Value(nodeResourceGuardKey{}).(*nodeResourceGuard)
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

func checkNodeResourceURL(ctx context.Context, rawURL string, address netip.Addr) error {
	target, err := url.Parse(rawURL)
	if err != nil || target.Hostname() == "" {
		return ErrNodeResourceDenied
	}
	return checkNodeResource(ctx, target.Hostname(), address)
}

// RefuseNodeResourceResult removes usable evidence after an App bookend fails,
// including when a test or separately supplied checker did not inspect targets.
func RefuseNodeResourceResult(result *NodeCheckResult) {
	result.Available, result.Verdict, result.EgressIP = false, evidence.VerdictInconclusive, ""
	result.Stage, result.ErrorCode = "resource_scope", "node-resource-refused"
	result.Message = "Ресурс исключён, не включён в активный список или условия проверки изменились. Результат не используется."
	result.Evidence.Verdict, result.Evidence.Outcome, result.Evidence.EgressIP = evidence.VerdictInconclusive, evidence.OutcomeUnknown, ""
	result.Evidence.ErrorCode = result.ErrorCode
}
