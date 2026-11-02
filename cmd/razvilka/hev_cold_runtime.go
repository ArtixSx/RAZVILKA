package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// No executable/version observation here: this private registry is only for
// cold observation/owned cleanup. Actual Start retains installed-owner checks.
func newColdDataplaneManager(ctx context.Context, stateRoot string, configs *engineconfig.Manager, configuration string, owner *components.Manager) (*dataplane.Manager, error) {
	return newColdDataplaneManagerAt(ctx, stateRoot, configs, configuration, owner, false)
}
func newColdRemovalDataplaneManager(ctx context.Context, stateRoot string, configs *engineconfig.Manager, configuration string, owner *components.Manager) (*dataplane.Manager, error) {
	return newColdDataplaneManagerAt(ctx, stateRoot, configs, configuration, owner, true)
}
func newColdDataplaneManagerAt(ctx context.Context, stateRoot string, configs *engineconfig.Manager, configuration string, owner *components.Manager, removal bool) (*dataplane.Manager, error) {
	if ctx == nil || owner == nil || !filepath.IsAbs(stateRoot) || !filepath.IsAbs(configuration) {
		return nil, dataplane.ErrReviewChanged
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, err := config.LoadExisting(configuration)
	backend := ""
	if err != nil {
		if !removal || !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		backend, err = retainedRemovalProxySidecar(ctx, stateRoot, owner)
		if err != nil {
			return nil, err
		}
	} else {
		backend = config.EffectiveProxySidecar(store.Get().ProxySidecar)
	}
	if err := config.ValidateProxySidecar(backend); err != nil {
		return nil, err
	}
	return newDataplaneManagerWithNodes(stateRoot, configs, nil, nil, proxySidecarStartup{backend: backend, components: owner, recovery: true})
}

// Configuration-less uninstall may retain its actual previous sidecar identity,
// never infer it from a binary filename or a missing process scan. Every later
// cleanup still checks original PID/kernel/policy ownership independently.
func retainedRemovalProxySidecar(ctx context.Context, stateRoot string, owner *components.Manager) (string, error) {
	choice := ""
	for _, id := range []string{"usque", "sing-box", "xray"} {
		runtime := filepath.Join(stateRoot, id, "runtime")
		kind, err := dataplane.RetainedProxySidecarKind(ctx, id, stateRoot)
		if err != nil {
			return "", err
		}
		if kind == "" {
			for _, path := range []string{filepath.Join(runtime, "engine.pid"), filepath.Join(runtime, "sidecar.pid"), filepath.Join(runtime, "engine.json"), filepath.Join(stateRoot, id, "policy.json"), filepath.Join(stateRoot, id, "forwarding.json"), filepath.Join(stateRoot, id, "transport.json")} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					return "", dataplane.ErrProxyPolicyUnknown
				}
			}
			continue
		}
		if choice != "" && choice != kind {
			return "", dataplane.ErrProxyPolicyUnknown
		}
		choice = kind
	}
	if choice == "" {
		choice = "sing-box"
	}
	return choice, ctx.Err()
}
