package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/defaultconsent"
)

func defaultRouteOriginalScopeFixture(t *testing.T) (*App, *defaultconsent.ScopeReview, context.Context) {
	t.Helper()
	fixture, body := defaultConsentHTTPFixture(t)
	// Retain the real config/control deployment, with a genuinely absent local
	// NodeStore. Scope approval cannot invent a remote node/provider permission.
	a := &App{Store: fixture.Store, Security: fixture.Security, SelfUpdateFiles: fixture.SelfUpdateFiles}
	if err := a.ConfigureDefaultConsent(fixture.defaultConsent.configPath, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.CloseDefaultConsent() })
	body["grants"] = []config.DefaultRouteGrant{}
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	if status, data := componentHTTP(t, server, "POST", networkPolicyReviewPath, body, componentRecoveryToken, server.URL); status != 200 {
		t.Fatal("actual authenticated scope approval", status, string(data))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ctx, release, err := a.privateExclusiveOperation(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	scope, err := a.ReviewListScope(ctx)
	if err != nil {
		release()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scope.Close(); release(); cancel() })
	return a, scope, ctx
}

func TestDefaultRouteScopeAuthorityRequiresOriginalCurrentStoreOwner(t *testing.T) {
	a, scope, ctx := defaultRouteOriginalScopeFixture(t)
	ref, err := defaultRouteScopeAuthority(ctx, a.Store, scope)
	if err != nil || ref != scope.Reference() || !defaultRouteScopeReferenceValid(a.Store.Get(), ref) {
		t.Fatal("original scope reference was not retained", ref, err)
	}
	if len(a.Store.Get().DefaultRouteConsent.Grants) != 0 || ref.Resolved != "" || ref.EngineID != "" {
		t.Fatal("client scope acquired a provider path")
	}
	_, snapshot, now := defaultRouteFixture()
	snapshot.Authority = ref
	compiled, err := CompileDefaultRoutePolicy(a.Store.Get(), snapshot, nil, now)
	if err != nil || len(compiled.Rules()) != 0 || compiled.LAN() != nil {
		t.Fatal("scope-only empty list acquired native effects", err)
	}
	foreign, err := config.Load(filepath.Join(t.TempDir(), "foreign.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, reader := range map[string]*defaultconsent.ScopeReview{"nil": nil, "zero": {}} {
		if _, err := defaultRouteScopeAuthority(ctx, a.Store, reader); !errors.Is(err, defaultconsent.ErrChanged) {
			t.Fatal("unissued scope supplied a comparison", name, err)
		}
	}
	if _, err := defaultRouteScopeAuthority(ctx, foreign, scope); !errors.Is(err, defaultconsent.ErrChanged) {
		t.Fatal("foreign Store borrowed original scope", err)
	}
	if _, err := defaultRouteScopeAuthority(context.Background(), a.Store, scope); err == nil {
		t.Fatal("raw context borrowed original admission")
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultRouteScopeAuthority(ctx, a.Store, scope); !errors.Is(err, defaultconsent.ErrChanged) {
		t.Fatal("closed original scope remained usable", err)
	}
}

func TestDefaultRouteScopeAuthorityRejectsOldReviewAfterOrdinaryExclusionEdit(t *testing.T) {
	a, old, ctx := defaultRouteOriginalScopeFixture(t)
	before, err := defaultRouteScopeAuthority(ctx, a.Store, old)
	if err != nil {
		t.Fatal(err)
	}
	manual := []config.ResourceMatch{{Kind: "cidr", Value: "203.0.113.0/24"}}
	if _, err := a.Store.UpdateResourceExclusions(ctx, a.Store.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultRouteScopeAuthority(ctx, a.Store, old); !errors.Is(err, defaultconsent.ErrChanged) {
		t.Fatal("old full-config scope review survived exclusion change", err)
	}
	fresh, err := a.ReviewListScope(ctx)
	if err != nil {
		t.Fatal("unchanged approved clients required another unlock", err)
	}
	defer fresh.Close()
	after, err := defaultRouteScopeAuthority(ctx, a.Store, fresh)
	if err != nil || after.ConsentDigest != before.ConsentDigest || after.ApprovalRevision != before.ApprovalRevision || after.PolicyRevision <= before.PolicyRevision || defaultRouteScopeReferenceValid(a.Store.Get(), before) {
		t.Fatal("fresh scope lost approval or retained old policy revision", before, after, err)
	}
}
