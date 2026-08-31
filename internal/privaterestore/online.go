package privaterestore

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// Stores are trusted live instances, not selected by the imported payload.
// The caller MUST exclude all API/worker/collector operations until return and
// permanently fence their admission on Blocked, before releasing exclusion.
type Stores struct {
	Config   *config.Store
	Custom   *customservices.Manager
	Devices  *devices.Manager
	Engines  *engineconfig.Manager
	Provider *cloudflareprovider.Store
}

func (Stores) String() string   { return "[private restore stores]" }
func (Stores) GoString() string { return "[private restore stores]" }

// RestoreOnline uses the startup coordinator's lifetime journal lease. Every
// live session binding is checked against that same trusted layout BEFORE the
// first write. The recovery record survives through cache handover; a restart
// can finish recovery before reopening any Store. No routes are activated.
func (c *Coordinator) RestoreOnline(ctx context.Context, payload privatebackup.Payload, builtIn map[string]bool, stores Stores) (out restorejournal.Outcome, err error) {
	if !c.mu.TryLock() {
		return restorejournal.Clean, restorejournal.ErrBusy
	}
	defer c.mu.Unlock()
	if c.closed || c.blocked {
		return restorejournal.Blocked, restorejournal.ErrRecovery
	}
	if !c.runtimeStarted || privatebackup.Validate(payload) != nil || stores.Config == nil || stores.Custom == nil || stores.Devices == nil || stores.Engines == nil || len(payload.ProviderSnapshots) > 0 && stores.Provider == nil {
		return restorejournal.Clean, restorejournal.ErrInvalid
	}
	if ctx.Err() != nil {
		return restorejournal.Clean, restorejournal.ErrAborted
	}
	refs := make([]engineconfig.DraftRef, 0, len(payload.EngineFiles))
	for _, file := range payload.EngineFiles {
		if !engineconfig.ValidatePrivateContent(file.EngineID, file.FileID, file.Content).OK {
			return restorejournal.Clean, restorejournal.ErrInvalid
		}
		refs = append(refs, engineconfig.DraftRef{EngineID: file.EngineID, FileID: file.FileID})
	}
	var closers []func() error
	var bound []string
	closed := false
	closeAll := func() error {
		if closed {
			return nil
		}
		closed = true
		var failure error
		for i := len(closers) - 1; i >= 0; i-- {
			if closers[i]() != nil {
				failure = restorejournal.ErrRecovery
			}
		}
		for _, id := range bound {
			c.slots[id].target = nil
		}
		return failure
	}
	// A panic must never leave this coordinator reusable with a pending journal.
	// Normal returns below always assign their explicit outcome.
	out = restorejournal.Blocked
	defer func() {
		if out == restorejournal.Blocked {
			c.blocked = true
		}
		if closeAll() != nil || errors.Is(err, restorejournal.ErrRecovery) {
			out, err = restorejournal.Blocked, restorejournal.ErrRecovery
		}
		if out == restorejournal.Blocked {
			c.blocked = true
		}
	}()
	bind := func(id string, target managedTarget, actual, expected string, bindingErr error) error {
		if bindingErr != nil || expected == "" || actual != expected || c.slots[id] == nil {
			return restorejournal.ErrInvalid
		}
		c.slots[id].target = target
		bound = append(bound, id)
		return nil
	}
	configuration, err := stores.Config.BeginRestore(ctx)
	if err != nil {
		return restorejournal.Clean, err
	}
	closers = append(closers, configuration.Close)
	want, bindingErr := config.RestoreBinding(c.layout.Config)
	if err := bind("config", configuration, configuration.Binding(), want, bindingErr); err != nil {
		return restorejournal.Clean, err
	}
	custom, err := stores.Custom.BeginRestore(ctx)
	if err != nil {
		return restorejournal.Clean, err
	}
	closers = append(closers, custom.Close)
	want, bindingErr = customservices.RestoreBinding(c.layout.CustomServices)
	if err := bind("custom_services", custom, custom.Binding(), want, bindingErr); err != nil {
		return restorejournal.Clean, err
	}
	registry, err := stores.Devices.BeginRestore(ctx)
	if err != nil {
		return restorejournal.Clean, err
	}
	closers = append(closers, registry.Close)
	want, bindingErr = devices.RestoreBinding(c.layout.Devices)
	if err := bind("devices", registry, registry.Binding(), want, bindingErr); err != nil {
		return restorejournal.Clean, err
	}
	if len(refs) > 0 {
		staging, err := stores.Engines.BeginRestore(ctx, refs)
		if err != nil {
			return restorejournal.Clean, err
		}
		closers = append(closers, staging.Close)
		targets, bindings := staging.Targets(), staging.TargetBindings()
		for _, ref := range refs {
			localID := ref.EngineID + "_" + ref.FileID
			target := &onlineDraft{Target: targets[localID], session: staging, ref: ref}
			want, bindingErr = engineconfig.RestoreBinding(c.layout.StageRoot, ref)
			if err := bind(draftID(ref.EngineID, ref.FileID), target, bindings[localID], want, bindingErr); err != nil {
				return restorejournal.Clean, err
			}
		}
	}
	if len(payload.ProviderSnapshots) > 0 {
		provider, err := stores.Provider.BeginRestore(ctx)
		if err != nil {
			return restorejournal.Clean, err
		}
		closers = append(closers, provider.Close)
		want, bindingErr = cloudflareprovider.RestoreBinding(c.layout.ProviderRoot)
		if err := bind("provider_cloudflare", provider, provider.Binding(), want, bindingErr); err != nil {
			return restorejournal.Clean, err
		}
	}
	changes, err := c.build(ctx, payload, builtIn)
	if err != nil {
		return restorejournal.Clean, err
	}
	return c.journal.ExecuteWithHandover(ctx, changes, func() error {
		if c.beforeHandover != nil {
			if err := c.beforeHandover(); err != nil {
				return err
			}
		}
		return closeAll()
	})
}

// One Manager session owns all staging slots; individual wrappers never unlock
// it. closeAll closes the shared session exactly once after the journal result.
type onlineDraft struct {
	restorejournal.Target
	session *engineconfig.RestoreSession
	ref     engineconfig.DraftRef
}

func (*onlineDraft) Close() error { return nil }
func (d *onlineDraft) Image(content string) (restorejournal.Image, error) {
	images, err := d.session.Images([]engineconfig.StageItem{{EngineID: d.ref.EngineID, FileID: d.ref.FileID, Content: content}})
	return images[d.ref.EngineID+"_"+d.ref.FileID], err
}
