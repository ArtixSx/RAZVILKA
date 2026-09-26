package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

type applyReview struct {
	Revision uint64 `json:"expected_revision"`
	Digest   string `json:"reviewed_digest"`
}

type applyReviewRequest struct {
	Revision *uint64 `json:"expected_revision"`
	Digest   string  `json:"reviewed_digest"`
}

type applyReviewDraft struct {
	Ref  string `json:"ref"`
	Hash string `json:"hash"`
}

type applyReviewBinding struct {
	review            applyReview
	cfg               config.Config
	catalogHash       string
	generation        uint64
	nodes             bool
	routes            []dataplane.Route
	profile           string
	drafts            []applyReviewDraft
	dnsProfiles       map[string]string
	dnsSelections     []dnscontrol.ServiceSelectionReview
	committedAdapters map[string]bool
}

func applyReviewHash(value any) string {
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func decodeApplyReview(w http.ResponseWriter, r *http.Request) (applyReviewRequest, bool) {
	var request applyReviewRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	err := decoder.Decode(&request)
	if errors.Is(err, io.EOF) {
		return request, true
	} // Legacy clients send an empty body.
	if err == nil {
		var extra any
		if !errors.Is(decoder.Decode(&extra), io.EOF) {
			err = errors.New("trailing data")
		}
	}
	if err == nil && request.Revision == nil && request.Digest == "" {
		return request, true
	}
	decoded, hashErr := hex.DecodeString(request.Digest)
	if err != nil || request.Revision == nil || hashErr != nil || len(decoded) != sha256.Size || request.Digest != strings.ToLower(request.Digest) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": "APPLY_REVIEW_INVALID", "error": "Подтверждение плана неполное. Откройте план заново.", "review_required": true, "live_applied": false})
		return request, false
	}
	return request, true
}

func (a *App) bindApplyReview(ctx context.Context, cfg config.Config, plan dataplane.Plan, scope changeScope, engineID string) (*applyReviewBinding, error) {
	b := &applyReviewBinding{cfg: cfg, catalogHash: applyReviewHash(a.catalogSnapshot()), routes: plan.Routes, profile: plan.NetworkProfileID, committedAdapters: map[string]bool{}}
	// Network authority also covers scoped DNS. Only exact registry routes
	// require node credentials/generation; a DNS-only plan has no node owner.
	for _, route := range plan.Routes {
		b.nodes = b.nodes || strings.HasPrefix(route.Resolved, "sing-box:node-")
	}
	if plan.DNS != nil {
		b.dnsProfiles = map[string]string{}
		for _, binding := range plan.DNS.Bindings {
			if previous, ok := b.dnsProfiles[binding.ProfileID]; ok && previous != binding.ProfileDigest {
				return nil, dataplane.ErrReviewChanged
			}
			b.dnsProfiles[binding.ProfileID] = binding.ProfileDigest
		}
		if len(b.dnsProfiles) == 0 {
			return nil, dataplane.ErrReviewChanged
		}
	}
	if plan.DNS != nil || slices.Contains(plan.RetiringAdapters, "dns-scoped") {
		if a.DNS == nil {
			return nil, dataplane.ErrReviewChanged
		}
		targets := map[string]string{}
		if a.Dataplane != nil {
			previous, exists, err := a.Dataplane.Committed()
			if err != nil {
				return nil, err
			}
			if exists && previous.DNS != nil {
				for _, binding := range previous.DNS.Bindings {
					targets[binding.ServiceID] = ""
					if plan.SuspendDNS {
						targets[binding.ServiceID] = binding.ProfileID
					}
				}
			}
		}
		if plan.DNS != nil {
			for _, binding := range plan.DNS.Bindings {
				targets[binding.ServiceID] = binding.ProfileID
			}
		}
		ids := make([]string, 0, len(targets))
		for id := range targets {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			review, err := a.DNS.ReviewServiceSelection(id, targets[id])
			if err != nil {
				return nil, dataplane.ErrReviewChanged
			}
			b.dnsSelections = append(b.dnsSelections, review)
		}
	}
	if b.nodes {
		if a.Nodes == nil {
			return nil, dataplane.ErrReviewChanged
		}
		snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
		if err != nil {
			return nil, dataplane.ErrReviewChanged
		}
		b.generation = snapshot.Generation
	}
	for _, ref := range plan.EngineDrafts {
		parts := strings.SplitN(ref, "/", 2)
		if len(parts) != 2 || a.EngineConfigs == nil {
			return nil, dataplane.ErrReviewChanged
		}
		view, err := a.EngineConfigs.ReadExpert(parts[0], parts[1])
		if err != nil || view.Source != "staged" {
			return nil, dataplane.ErrReviewChanged
		}
		b.drafts = append(b.drafts, applyReviewDraft{Ref: ref, Hash: applyReviewHash(view.Content)})
	}
	b.review = applyReview{Revision: cfg.Revision, Digest: applyReviewHash(struct {
		Scope                         changeScope
		Engine, Plan, Config, Catalog string
		Generation                    uint64
		Drafts                        []applyReviewDraft
		DNS                           []dnscontrol.ServiceSelectionReview
	}{scope, engineID, plan.Digest, applyReviewHash(cfg), b.catalogHash, b.generation, b.drafts, b.dnsSelections})}
	if err := b.guard(a, ctx); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *applyReviewBinding) guard(a *App, ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !reflect.DeepEqual(a.Store.Get(), b.cfg) || applyReviewHash(a.catalogSnapshot()) != b.catalogHash {
		return dataplane.ErrReviewChanged
	}
	committing := dataplane.ReviewCommittedAdapter(ctx)
	for profile, digest := range b.dnsProfiles {
		if a.DNS == nil {
			return dataplane.ErrReviewChanged
		}
		current, err := a.DNS.ScopedProfileIdentity(profile)
		if err != nil || current != digest {
			return dataplane.ErrReviewChanged
		}
	}
	for _, review := range b.dnsSelections {
		if a.DNS == nil {
			return dataplane.ErrReviewChanged
		}
		var err error
		if b.committedAdapters["dns-scoped"] || committing == "dns-scoped" {
			err = a.DNS.CheckCommittedServiceSelection(review.Receipt())
		} else {
			err = a.DNS.CheckServiceSelection(review)
		}
		if err != nil {
			return dataplane.ErrReviewChanged
		}
	}
	if b.nodes {
		if a.Nodes == nil {
			return dataplane.ErrReviewChanged
		}
		snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
		if err != nil || snapshot.Generation != b.generation {
			return dataplane.ErrReviewChanged
		}
		for _, route := range b.routes {
			if !strings.HasPrefix(route.Resolved, "sing-box:node-") {
				continue
			}
			proof, err := a.Nodes.ResolveRoute(ctx, strings.TrimPrefix(route.Resolved, "sing-box:"), route.ServiceID, b.profile, "", time.Time{}, time.Now())
			if err != nil || proof.Route != route.Resolved {
				return dataplane.ErrReviewChanged
			}
		}
	}
	for _, draft := range b.drafts {
		parts := strings.SplitN(draft.Ref, "/", 2)
		view, err := a.EngineConfigs.ReadExpert(parts[0], parts[1])
		if err != nil {
			return dataplane.ErrReviewChanged
		}
		if view.Source == "staged" {
			if applyReviewHash(view.Content) != draft.Hash {
				return dataplane.ErrReviewChanged
			}
		} else if !b.committedAdapters[parts[0]] && committing != parts[0] {
			return dataplane.ErrReviewChanged
		}
	}
	if committing != "" {
		b.committedAdapters[committing] = true
	}
	return nil
}

func (b *applyReviewBinding) commit(a *App, ctx context.Context, scope changeScope) (func() error, error) {
	if err := b.guard(a, ctx); err != nil {
		return nil, err
	}
	configScope := config.DraftScopeAll
	if scope == changeScopeServices {
		configScope = config.DraftScopeServices
	}
	if scope == changeScopeDevices {
		configScope = config.DraftScopeDevices
	}
	undo, err := a.Store.ApplyDraftScopeAtRevisionWithRollback(configScope, b.cfg.Revision)
	if errors.Is(err, config.ErrRevisionChanged) {
		err = dataplane.ErrReviewChanged
	}
	if err == nil {
		current := a.Store.Get()
		if current.Revision != b.cfg.Revision {
			return undo, dataplane.ErrReviewChanged
		}
		b.cfg = current
	}
	return undo, err
}

func writeApplyReviewChanged(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "APPLY_REVIEW_CHANGED", "error": "Настройки или файлы изменились после просмотра. Откройте новый план.", "review_required": true, "live_applied": false, "working_routes_changed": false})
}
