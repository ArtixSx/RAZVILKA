package dataplane

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// BindRuntimeInactivitySources is called once by the trusted startup assembly
// with its actual complete collector and provider. The assembly must keep the
// original admitted tool lease alive throughout every later observation.
// Construction authenticates the source; it does not prove runtime absence.
func (m *Manager) BindRuntimeInactivitySources(ctx context.Context, provider *netidentity.Provider, inventory *BackendInventory, settingsPath string) error {
	return m.bindRuntimeInactivitySources(ctx, provider, inventory, settingsPath, NewNFQWSRuntimeInactiveSource)
}

// Private complete-source construction seam; production only uses the original
// concrete constructor above, never a caller supplied source or observation.
func (m *Manager) bindRuntimeInactivitySources(ctx context.Context, provider *netidentity.Provider, inventory *BackendInventory, settingsPath string, construct func(context.Context, *NFQWS2Adapter, *BackendInventory) (*NFQWSRuntimeInactiveSource, error)) error {
	if m == nil || !nfqws2InactiveFinite(ctx) || provider == nil || inventory == nil || inventory.reader.Provider != provider ||
		!filepath.IsAbs(settingsPath) || filepath.Clean(settingsPath) != settingsPath || settingsPath == filepath.VolumeName(settingsPath)+string(filepath.Separator) {
		stage := "binding-inputs"
		switch {
		case m == nil:
		case !nfqws2InactiveFinite(ctx):
			stage = "binding-context"
		case provider == nil || inventory == nil || inventory.reader.Provider != provider:
		default:
			stage = "binding-settings"
		}
		return runtimeInactivityBindingAt(stage, ctx)
	}
	m.registryMu.Lock()
	defer m.registryMu.Unlock()
	nfq, ok := m.Adapters["nfqws2"].(*NFQWS2Adapter)
	dns, dnsOK := m.Adapters[scopedDNSAdapterID].(*ScopedDNSAdapter)
	if !ok || !dnsOK || nfq == nil || dns == nil || nfq.StateRoot != filepath.Join(m.StateRoot, "runtime", "nfqws2") || dns.StateRoot != filepath.Join(m.StateRoot, scopedDNSAdapterID) ||
		dns.InactivityIdentity != nil || dns.InactivityKernelCheck != nil || dns.inactivitySources != nil || m.runtimeSources != nil || dns.DNS != nil && dns.DNS.Path != settingsPath || dns.InactivitySettingsPath != "" && dns.InactivitySettingsPath != settingsPath {
		stage := "binding-participants"
		switch {
		case !ok || !dnsOK || nfq == nil || dns == nil:
		case nfq.StateRoot != filepath.Join(m.StateRoot, "runtime", "nfqws2") || dns.StateRoot != filepath.Join(m.StateRoot, scopedDNSAdapterID):
			stage = "binding-roots"
		case dns.InactivityIdentity != nil || dns.InactivityKernelCheck != nil || dns.inactivitySources != nil || m.runtimeSources != nil:
			stage = "binding-already-bound"
		default:
			stage = "binding-dns-settings"
		}
		return runtimeInactivityBindingAt(stage, ctx)
	}
	source, err := construct(ctx, nfq, inventory)
	if err != nil {
		return errors.Join(ErrRuntimeInactivity, err, ctx.Err())
	}
	if err := source.Bind(nfq); err != nil {
		return errors.Join(ErrRuntimeInactivity, err, ctx.Err())
	}
	dns.InactivitySettingsPath = settingsPath
	dns.InactivityIdentity = provider
	m.runtimeSources = newRuntimeInactivitySourceReview(m, nfq, dns, source, settingsPath)
	dns.inactivitySources = m.runtimeSources
	return ctx.Err()
}

type runtimeInactivityBindingFailure struct {
	stage string
	cause error
}

func (e *runtimeInactivityBindingFailure) Error() string {
	return "runtime inactivity binding refused at " + e.stage
}
func (e *runtimeInactivityBindingFailure) Unwrap() error { return e.cause }

func runtimeInactivityBindingAt(stage string, ctx context.Context) error {
	cause := ErrRuntimeInactivity
	if ctx != nil {
		cause = errors.Join(cause, ctx.Err())
	}
	return &runtimeInactivityBindingFailure{stage: stage, cause: cause}
}

// RuntimeInactivityBindingStage exposes only closed startup refusal coordinates.
// It never reads arbitrary error text or issues source, absence or cleanup proof.
func RuntimeInactivityBindingStage(err error) string {
	stage, remaining := "", 64
	var visit func(error)
	visit = func(err error) {
		if err == nil || remaining == 0 || stage != "" {
			return
		}
		remaining--
		if failure, ok := err.(*runtimeInactivityBindingFailure); ok && failure != nil {
			switch failure.stage {
			case "binding-context", "binding-inputs", "binding-settings", "binding-participants", "binding-roots", "binding-already-bound", "binding-dns-settings":
				stage = failure.stage
				return
			}
		}
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			for _, cause := range wrapped.Unwrap() {
				visit(cause)
			}
		case interface{ Unwrap() error }:
			visit(wrapped.Unwrap())
		}
	}
	visit(err)
	return stage
}
