package privaterestore

import (
	"context"
	"encoding/json"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/devices"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// RestoreOffline is an internal pre-Load operation, NOT an HTTP or live restore
// API. Config/catalog/devices must already exist; it never bootstraps unknown
// state. Full payload and merged catalog references are checked under leases.
// Built-in IDs must come from the trusted deployment catalog, never the archive.
// It restores desired drafts and copied accounts only. EngineOrder, applied
// state, credentials, DNS and runtimes are deliberately not changed.
func (c *Coordinator) RestoreOffline(ctx context.Context, payload privatebackup.Payload, builtIn map[string]bool) (out restorejournal.Outcome, err error) {
	if !c.mu.TryLock() {
		return restorejournal.Blocked, restorejournal.ErrBusy
	}
	defer c.mu.Unlock()
	if c.closed || c.blocked {
		return restorejournal.Blocked, restorejournal.ErrRecovery
	}
	if c.runtimeStarted {
		return restorejournal.Clean, ErrRuntimeStarted
	}
	defer func() {
		if out == restorejournal.Blocked && err != nil {
			c.blocked = true
		}
		if closeErr := c.releaseTargets(); closeErr != nil {
			out = restorejournal.Blocked
			err = restorejournal.ErrRecovery
			c.blocked = true
		}
	}()
	changes, err := c.build(ctx, payload, builtIn)
	if err != nil {
		return restorejournal.Clean, err
	}
	return c.journal.Execute(ctx, changes)
}

func (c *Coordinator) build(ctx context.Context, payload privatebackup.Payload, builtIn map[string]bool) (map[string]restorejournal.Image, error) {
	if ctx.Err() != nil {
		return nil, restorejournal.ErrAborted
	}
	if privatebackup.Validate(payload) != nil {
		return nil, restorejournal.ErrInvalid
	}
	ids := []string{"config", "custom_services", "devices"}
	if len(payload.ProviderSnapshots) > 0 {
		ids = append(ids, "provider_cloudflare")
	}
	for _, file := range payload.EngineFiles {
		if !engineconfig.ValidatePrivateContent(file.EngineID, file.FileID, file.Content).OK {
			return nil, restorejournal.ErrInvalid
		}
		ids = append(ids, draftID(file.EngineID, file.FileID))
	}
	if err := c.acquireAll(ctx, ids); err != nil {
		return nil, err
	}
	changes := map[string]restorejournal.Image{}
	custom := c.slots["custom_services"].target.(*customservices.RestoreTarget)
	customImage, err := custom.MergeImage(ctx, payload.CustomServices, builtIn, true)
	if err != nil {
		return nil, err
	}
	// Decode only the already typed/validated merged catalog, never raw archive
	// JSON. Check references against the exact state which this plan will commit.
	var merged struct {
		Services []catalog.Service `json:"services"`
	}
	if json.Unmarshal(customImage.Data, &merged) != nil {
		return nil, restorejournal.ErrInvalid
	}
	known := map[string]bool{}
	for id, enabled := range builtIn {
		if enabled {
			known[id] = true
		}
	}
	for _, service := range merged.Services {
		known[service.ID] = true
	}
	for id := range payload.Services {
		if !known[id] {
			return nil, restorejournal.ErrInvalid
		}
	}
	changes["custom_services"] = customImage
	changes["config"], err = c.slots["config"].target.(*config.RestoreTarget).DraftImage(ctx, payload.Services)
	if err != nil {
		return nil, err
	}
	changes["devices"], err = c.slots["devices"].target.(*devices.RestoreTarget).MergeImage(ctx, payload.Devices)
	if err != nil {
		return nil, err
	}
	for _, file := range payload.EngineFiles {
		id := draftID(file.EngineID, file.FileID)
		changes[id], err = c.slots[id].target.(*engineconfig.RestoreTarget).Image(file.Content)
		if err != nil {
			return nil, err
		}
	}
	if len(payload.ProviderSnapshots) > 0 {
		changes["provider_cloudflare"], _, err = c.slots["provider_cloudflare"].target.(*cloudflareprovider.RestoreTarget).MergeImage(ctx, payload.ProviderSnapshots)
		if err != nil {
			return nil, err
		}
	}
	return changes, nil
}
