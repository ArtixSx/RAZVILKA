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
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
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
	b := &applyReviewBinding{cfg: cfg, catalogHash: applyReviewHash(a.catalogSnapshot()), nodes: plan.RequiresNetworkProof(), routes: plan.Routes, profile: plan.NetworkProfileID, committedAdapters: map[string]bool{}}
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
	}{scope, engineID, plan.Digest, applyReviewHash(cfg), b.catalogHash, b.generation, b.drafts})}
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
	if b.nodes {
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
	committing := dataplane.ReviewCommittedAdapter(ctx)
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
