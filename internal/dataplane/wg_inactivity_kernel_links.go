package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

// Optional only for older structured-CLI sources; the concrete production
// startup inactivity source always implements this original kernel reader.
type wgInactivityKernelLinkSource interface {
	ReadWGKernelLinks(context.Context, netidentity.Identity) ([]physicalscope.WGKernelLink, error)
}

func (r *WGInactivityRead) kernelLinksAvailable() bool {
	if r == nil {
		return false
	}
	_, ok := r.tools.Runner.(wgInactivityKernelLinkSource)
	return ok
}

// Called only inside the original still-open WithCurrent session. Retain the
// read through kernel completion; Close and session exit cancel and join it.
func (r *WGInactivityRead) readKernelLinks(ctx context.Context) ([]physicalscope.WGKernelLink, error) {
	if r == nil || r.self != r || !wgInactivityFinite(ctx) {
		return nil, ErrWGOperationOwner
	}
	s, _ := ctx.Value(wgInactivitySessionKey{}).(*wgInactivityReadSession)
	if s == nil || s.self != s || s.source != r {
		return nil, ErrWGOperationOwner
	}
	s.mu.Lock()
	if !s.open || s.ctx == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, ErrWGOperationOwner
	}
	s.reads.Add(1)
	s.mu.Unlock()
	defer s.reads.Done()
	deadline, _ := ctx.Deadline()
	c, cancel := context.WithDeadline(s.ctx, deadline)
	stop := context.AfterFunc(ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := errors.Join(r.current(c, s.cleanup), s.roots.current(c)); err != nil {
		return nil, err
	}
	source, ok := r.tools.Runner.(wgInactivityKernelLinkSource)
	if !ok {
		return nil, ErrWGOperationOwner
	}
	links, err := source.ReadWGKernelLinks(c, r.tools.Identity)
	closing := errors.Join(r.current(c, s.cleanup), s.roots.current(c), c.Err())
	if err != nil || closing != nil {
		return nil, errors.Join(err, closing)
	}
	return append([]physicalscope.WGKernelLink(nil), links...), nil
}

func wgKernelLinksExclude(links []physicalscope.WGKernelLink, interfaces []string) error {
	if err := wgKernelLinkFactsComplete(links); err != nil {
		return err
	}
	for _, link := range links {
		for _, name := range interfaces {
			if link.Name == name {
				return errWGInactiveUnknown
			}
		}
	}
	return nil
}

// Validate detached inventory shape only. This grants neither absence nor
// identity proof: callers must still check their exact interface/peer facts.
func wgKernelLinkFactsComplete(links []physicalscope.WGKernelLink) error {
	if len(links) == 0 || len(links) > 4096 {
		return errWGInactiveUnknown
	}
	names, indices := map[string]bool{}, map[int]bool{}
	for _, link := range links {
		if link.Name == "" || link.Index <= 0 || names[link.Name] || indices[link.Index] {
			return errWGInactiveUnknown
		}
		names[link.Name], indices[link.Index] = true, true
	}
	return nil
}
