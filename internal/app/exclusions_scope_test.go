package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// "Применить исключения" re-applies the applied services at the applied
// revision with no Store or engine draft, so the committed plan never runs
// ahead of AppliedRevision; the scope has nothing to discard.
func TestExclusionsScopeBuildsAtAppliedRevision(t *testing.T) {
	cfg := config.Default()
	cfg.SafeMode = false
	cfg.Revision, cfg.AppliedRevision = 9, 7
	cfg.AppliedServices = map[string]config.ServiceState{"telegram": {Enabled: true, Route: "nfqws2"}}
	cfg.Services = map[string]config.ServiceState{"telegram": {Enabled: true, Route: "nfqws2"}, "video": {Enabled: true, Route: "nfqws2"}}
	a := &App{Catalog: catalog.Catalog{Services: []catalog.Service{
		{ID: "telegram", Name: "Telegram", Domains: []string{"telegram.org"}},
		{ID: "video", Name: "Видео", Domains: []string{"video.example"}},
	}}}
	options := []routecatalog.Option{{ID: "nfqws2", Installed: true, Selectable: true}}
	cfg.InactiveResourceExclusions = &config.ResourceExclusions{Schema: 1, Revision: 2, Manual: []config.ResourceMatch{{Kind: "suffix", Value: "example.com"}}}
	plan, err := a.buildDataplanePlanForScope(cfg, options, changeScopeExclusions, "")
	if err != nil || plan.Revision != 7 || len(plan.Routes) != 1 || plan.Routes[0].ServiceID != "telegram" || len(plan.EngineDrafts) != 0 || plan.SiteExclusions == nil {
		t.Fatalf("exclusions scope plan: %v rev=%d routes=%+v drafts=%v", err, plan.Revision, plan.Routes, plan.EngineDrafts)
	}
	if all, err := a.buildDataplanePlanForScope(cfg, options, changeScopeAll, ""); err != nil || all.Revision != 9 {
		t.Fatalf("an ordinary Apply plan is not at the saved revision: %v %d", err, all.Revision)
	}
	recorder := httptest.NewRecorder()
	(&App{}).discard(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/discard?scope=exclusions", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("discard accepted the exclusions scope: %d", recorder.Code)
	}
}
