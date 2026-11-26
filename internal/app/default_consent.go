package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
)

const networkPolicyReviewPath = "/api/v1/networkpolicy/review"

type defaultConsentState struct {
	mu                                sync.Mutex
	configPath, nodeRoot, controlRoot string
	files                             *SelfUpdateFiles
	owner                             *defaultconsent.Owner
}

// ConfigureDefaultConsent records actual startup deployment bindings. It
// creates no approval or authority. The explicit authenticated review constructs
// the retained reader under original operation admission.
func (a *App) ConfigureDefaultConsent(configPath, nodeRoot string) error {
	if a == nil || a.Store == nil || a.SelfUpdateFiles == nil {
		return defaultconsent.ErrChanged
	}
	cfg, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	nodes := ""
	if a.Nodes != nil {
		nodes, err = filepath.Abs(nodeRoot)
		if err != nil {
			return err
		}
		nodes = filepath.Clean(nodes)
	}
	a.defaultConsent.mu.Lock()
	defer a.defaultConsent.mu.Unlock()
	if a.defaultConsent.configPath != "" {
		return defaultconsent.ErrChanged
	}
	a.defaultConsent.configPath, a.defaultConsent.nodeRoot = filepath.Clean(cfg), nodes
	a.defaultConsent.controlRoot, a.defaultConsent.files = a.SelfUpdateFiles.ControlRoot, a.SelfUpdateFiles
	return nil
}

func (a *App) defaultConsentOwner(ctx context.Context) (*defaultconsent.Owner, error) {
	a.defaultConsent.mu.Lock()
	defer a.defaultConsent.mu.Unlock()
	s := &a.defaultConsent
	if s.configPath == "" || s.controlRoot == "" || a.SelfUpdateFiles != s.files || s.files.ControlRoot != s.controlRoot {
		return nil, defaultconsent.ErrChanged
	}
	if s.owner != nil {
		return s.owner, nil
	}
	store, nodes, files, root := a.Store, a.Nodes, s.files, s.controlRoot
	owner, err := defaultconsent.NewOwner(ctx, &a.Operations, &a.Store, &a.Nodes, s.configPath, s.nodeRoot, root, func() bool {
		return a.Store == store && a.Nodes == nodes && a.SelfUpdateFiles == files && files.ControlRoot == root
	})
	if err != nil {
		return nil, err
	}
	s.owner = owner
	return owner, nil
}

func (a *App) CloseDefaultConsent() error {
	a.defaultConsent.mu.Lock()
	defer a.defaultConsent.mu.Unlock()
	if a.defaultConsent.owner == nil {
		return nil
	}
	return a.defaultConsent.owner.Close()
}

// ReviewDefaultConsent supplies the concrete private handle to the trusted
// compiler/transport owner under SAME original operation admission.
func (a *App) ReviewDefaultConsent(ctx context.Context, resolved string) (*defaultconsent.Review, error) {
	owner, err := a.defaultConsentOwner(ctx)
	if err != nil {
		return nil, err
	}
	return owner.Review(ctx, resolved)
}

// ReviewListScope retains the actual approved client scope, current full config
// and original control owner. It grants no engine, strategy, provider or effect;
// the trusted compiler must retain those separate concrete source owners.
func (a *App) ReviewListScope(ctx context.Context) (*defaultconsent.ScopeReview, error) {
	owner, err := a.defaultConsentOwner(ctx)
	if err != nil {
		return nil, err
	}
	return owner.ReviewScope(ctx)
}

func (a *App) networkPolicyReview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Security == nil || !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"error": "Требуется авторизация."})
		return
	}
	if a.Store == nil {
		writeJSON(w, 503, map[string]any{"code": "NETWORK_POLICY_CONSENT_UNAVAILABLE"})
		return
	}
	if r.Method == http.MethodGet {
		cfg := a.Store.Get()
		writeJSON(w, 200, map[string]any{"revision": cfg.Revision, "policy": cfg.NetworkPolicy, "consent": cfg.DefaultRouteConsent, "live_applied": false})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request struct {
		ExpectedRevision       uint64                     `json:"expected_revision"`
		ExpectedPolicyRevision uint64                     `json:"expected_policy_revision"`
		Policy                 *config.NetworkPolicy      `json:"policy"`
		Grants                 []config.DefaultRouteGrant `json:"grants"`
		Confirm                string                     `json:"confirm"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.Confirm != "APPROVE_NETWORK_POLICY" || request.Policy == nil {
		writeJSON(w, 400, map[string]any{"error": "Подтвердите выбранную область, пути и источники."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	ctx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	defer release()
	before := a.Store.Get()
	policyRevision := uint64(0)
	if before.NetworkPolicy != nil {
		policyRevision = before.NetworkPolicy.Revision
	}
	if before.Revision != request.ExpectedRevision || policyRevision != request.ExpectedPolicyRevision || policyRevision >= ^uint64(0)-1 {
		writeJSON(w, 409, map[string]any{"code": "NETWORK_POLICY_REVIEW_CHANGED"})
		return
	}
	policy := config.CloneNetworkPolicy(request.Policy)
	policy.Revision = policyRevision + 1
	policy, err = config.NetworkPolicyWithRetainedExclusions(before, policy)
	if err != nil {
		writeJSON(w, 409, map[string]any{"code": "NETWORK_POLICY_EXCLUSIONS_SEPARATE", "live_applied": false})
		return
	}
	if config.ValidateListNetworkPolicy(policy) != nil {
		writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_LIST_REQUIRED", "live_applied": false})
		return
	}
	for _, grant := range request.Grants {
		if config.ValidateDefaultRouteGrant(grant) != nil {
			writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_SOURCE_UNKNOWN"})
			return
		}
		if grant.ProviderClass == "private_profile" {
			if a.Dataplane == nil || grant.Resolved != "wireguard" && !strings.HasPrefix(grant.Resolved, "wireguard:") {
				writeJSON(w, 503, map[string]any{"code": "NETWORK_POLICY_PROFILE_OWNER_REQUIRED"})
				return
			}
			profiles, err := a.Dataplane.WireGuardProfileCatalog()
			if err != nil {
				writeJSON(w, 503, map[string]any{"code": "NETWORK_POLICY_PROFILE_OWNER_REQUIRED"})
				return
			}
			if _, err := profiles.Get(ctx, grant.ProviderID); err != nil {
				writeJSON(w, 400, map[string]any{"code": "NETWORK_POLICY_SOURCE_UNKNOWN"})
				return
			}
		}
	}
	owner, err := a.defaultConsentOwner(ctx)
	if err == nil {
		_, err = owner.Approve(ctx, before, policy, request.Grants)
	}
	if err != nil {
		status := 503
		if errors.Is(err, config.ErrRevisionChanged) {
			status = 409
		}
		writeJSON(w, status, map[string]any{"code": "NETWORK_POLICY_CONSENT_UNAVAILABLE", "live_applied": false})
		return
	}
	after := a.Store.Get()
	writeJSON(w, 200, map[string]any{"ok": true, "approved": true, "revision": after.Revision, "policy": after.NetworkPolicy, "consent": after.DefaultRouteConsent, "live_applied": false})
}
