// Package tunnelcheck separates reachability of an isolated tunnel from proof
// that live LAN policy selects that tunnel. It never changes routes or profiles.
package tunnelcheck

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNoService = errors.New("candidate has no service probe")
	ErrHandshake = errors.New("candidate handshake not confirmed")
	ErrService   = errors.New("candidate service not confirmed")
	ErrBootstrap = errors.New("candidate provider identity not confirmed")
)

type Service struct{ Name, URL string }

// WireGuard sends authorized traffic before observing the handshake. This
// supports peers with PersistentKeepalive=0 without mutating their configuration.
// The supplied probe MUST be bound to the temporary candidate's source/path.
// ProviderTrace is for WARP only; a generic WG/AWG server has no such dependency.
// No success here is proof of a LAN client's path or a permission to Apply.
func WireGuard(ctx context.Context, services []Service, timeout time.Duration, providerTrace bool,
	probe func(context.Context, string) error, handshake func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(services) == 0 || probe == nil || handshake == nil {
		return ErrNoService
	}
	if timeout <= 0 {
		return errors.New("candidate probe timeout must be positive")
	}
	for _, s := range services {
		if s.URL == "" {
			return ErrNoService
		}
	}
	run := func(url string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		err := probe(c, url)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.Err() != nil {
			return c.Err()
		}
		return err
	}
	first := services[0].URL
	if providerTrace {
		first = "https://www.cloudflare.com/cdn-cgi/trace"
	}
	probeErr := run(first)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Even a failed HTTPS request may have established WG. Do not mislabel a
	// denied website as a missing handshake, or accept a handshake as service PASS.
	if err := handshake(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.Join(ErrHandshake, err, probeErr)
	}
	if probeErr != nil {
		if providerTrace {
			return errors.Join(ErrBootstrap, probeErr)
		}
		return fmt.Errorf("%w (%s): %w", ErrService, services[0].Name, probeErr)
	}
	seen := map[string]bool{}
	if !providerTrace {
		seen[first] = true
	}
	for _, s := range services {
		if seen[s.URL] {
			continue
		}
		if err := run(s.URL); err != nil {
			return fmt.Errorf("%w (%s): %w", ErrService, s.Name, err)
		}
		seen[s.URL] = true
	}
	return ctx.Err()
}
