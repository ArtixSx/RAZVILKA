package startuptools

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// SyntheticBaselineIPSetReader issues only an actual read-only kernel source,
// not a command extension or caller-provided membership observation.
func (l *Lease) SyntheticBaselineIPSetReader() (*dataplane.SyntheticBaselineIPSetReader, error) {
	if l == nil || l.lifetime == nil {
		return nil, at("IPSET_SOURCE", nil)
	}
	ctx, cancel := context.WithTimeout(l.lifetime, operationTimeout)
	defer cancel()
	if err := l.Check(ctx, l.identity); err != nil {
		return nil, err
	}
	return dataplane.NewSyntheticBaselineIPSetReader(l.provider, l.identity, func(ctx context.Context, use func(context.Context) error) error {
		if use == nil {
			return at("IPSET_SOURCE", nil)
		}
		if err := l.retain(ctx); err != nil {
			return err
		}
		defer l.retained.Done()
		held, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(l.lifetime, cancel)
		defer stop()
		if err := l.Check(held, l.identity); err != nil {
			return err
		}
		err := use(held)
		// The native provider bracket has ended before this closing source check.
		return errors.Join(err, l.Check(held, l.identity), held.Err())
	})
}
