package physicalscope

import "context"

// CurrentRetained compares this SAME already-issued primary witness using a
// fresh finite caller context. It does not read the old selection owner, issue
// consent, renew forward permission or admit any listener/effect/cleanup.
// The caller must separately hold its actual current App/control operation.
// Original physical capture/provider/fence bracket both complete RTM_GETADDR
// dumps. Close joins these reads on the original Review; no new Review opens.
func (p *PrimaryIPv4Review) CurrentRetained(ctx context.Context) error {
	if p == nil || p.state == nil || p.state.self != p {
		return at("primary.retained.original", nil)
	}
	c, cancel, err := operationContext(ctx)
	if err != nil {
		return boundary("primary.retained.context", err)
	}
	defer cancel()
	v := p.state
	r := v.original
	if r == nil || r.state == nil || r.state.self != r || !v.observer.ready() {
		return at("primary.retained.dependencies", nil)
	}
	s := r.state
	s.mu.Lock()
	current := s.issuer == v.observer && !s.closed && !s.physicalInvalid && s.fence != nil && !v.invalid && v.issued
	s.mu.Unlock()
	if !current {
		return at("primary.retained.unavailable", nil)
	}
	if err := v.observer.VerifyRetainedIncarnation(c, r); err != nil {
		return boundary("primary.retained.physical.before", err)
	}
	if err := p.current(c, true); err != nil {
		return err
	}
	if err := v.observer.VerifyRetainedIncarnation(c, r); err != nil {
		return boundary("primary.retained.physical.after", err)
	}
	return c.Err()
}
