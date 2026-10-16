package physicalscope

import (
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// WGKernelLink is detached kernel observation only. Neither a link name nor
// its kind is process, peer, receipt, scope or mutation authority.
type WGKernelLink struct {
	Name  string
	Index int
	Kind  string
}

// ReadWGKernelLinks observes the complete RTM link dump under the caller's
// original namespace Provider. It needs no Home/device selection and performs
// no discovery, command, module load or mutation request. The owning WG source
// must retain its own control/tool/file guards across this observation.
func ReadWGKernelLinks(ctx context.Context, provider *netidentity.Provider, expected netidentity.Identity) ([]WGKernelLink, error) {
	if provider == nil {
		return nil, ErrUnknown
	}
	return readWGKernelLinks(ctx, expected, provider.WithCurrent, platformWGKernelLinks)
}

func readWGKernelLinks(ctx context.Context, expected netidentity.Identity, current func(context.Context, func(context.Context, netidentity.Identity) error) error, capture func(context.Context) ([]message, error)) ([]WGKernelLink, error) {
	if ctx == nil || ctx.Err() != nil || expected.Validate() != nil || current == nil || capture == nil {
		return nil, ErrUnknown
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, ErrUnknown
	}
	c, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var result []WGKernelLink
	uses := 0
	err := current(c, func(held context.Context, actual netidentity.Identity) error {
		uses++
		if uses != 1 || actual != expected || held.Err() != nil {
			return ErrUnknown
		}
		leaf, stop := context.WithTimeout(held, 2*time.Second)
		defer stop()
		frames, err := capture(leaf)
		if err != nil {
			return err
		}
		result, err = wgKernelLinks(frames)
		return errors.Join(err, leaf.Err())
	})
	if err != nil || uses != 1 || c.Err() != nil {
		return nil, errors.Join(ErrUnknown, err, c.Err())
	}
	return result, nil
}

func wgKernelLinks(frames []message) ([]WGKernelLink, error) {
	if len(frames) == 0 || len(frames) > 4096 {
		return nil, ErrUnknown
	}
	names, indices := map[string]bool{}, map[int]bool{}
	result := make([]WGKernelLink, 0, len(frames))
	for _, frame := range frames {
		if frame.kind != 16 || frame.flags != 2 {
			return nil, ErrUnknown
		}
		link, err := decodeLink(frame)
		if err != nil || names[link.Interface] || indices[link.IfIndex] {
			return nil, errors.Join(ErrUnknown, err)
		}
		names[link.Interface], indices[link.IfIndex] = true, true
		result = append(result, WGKernelLink{Name: link.Interface, Index: link.IfIndex, Kind: link.kind})
	}
	return result, nil
}
