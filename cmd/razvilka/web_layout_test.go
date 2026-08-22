package main

import (
	"strings"
	"testing"
)

func TestEmbeddedWebLayoutDoesNotOffsetPanelHeaders(t *testing.T) {
	t.Parallel()

	data, err := embedded.ReadFile("web/style.css")
	if err != nil {
		t.Fatalf("read embedded stylesheet: %v", err)
	}
	css := string(data)

	for _, forbidden := range []string{
		".sticky-title{position:sticky",
		".full-panel{min-height:calc(100vh",
		".engine-workspace{display:grid;grid-template-columns:270px minmax(0,1fr);min-height:650px",
	} {
		if strings.Contains(css, forbidden) {
			t.Fatalf("layout regression: stylesheet contains %q", forbidden)
		}
	}

	for _, required := range []string{
		".full-panel{min-height:0}",
		".sticky-title{position:relative;top:auto",
		".engine-workspace{display:grid;grid-template-columns:270px minmax(0,1fr);min-height:0}",
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("layout guard missing %q", required)
		}
	}
}

func TestEmbeddedWebAssetsUseCurrentCacheKey(t *testing.T) {
	t.Parallel()

	data, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index: %v", err)
	}
	html := string(data)
	for _, asset := range []string{
		"/style.css?v=0.12.1",
		"/v010.css?v=0.12.1",
		"/v011.css?v=0.12.1",
		"/v011-theme.css?v=0.12.1",
		"/v012.css?v=0.12.1",
		"/app.js?v=0.12.1",
		"/favicon.ico?v=0.12.1",
	} {
		if !strings.Contains(html, asset) {
			t.Fatalf("cache-busted asset missing %q", asset)
		}
	}
}

func TestWarpSettingsExplainTransactionalApply(t *testing.T) {
	t.Parallel()
	indexData, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index: %v", err)
	}
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded app: %v", err)
	}
	html, app := string(indexData), string(appData)
	for _, required := range []string{`id="warpApplyHint"`, `class="warp-steps"`, `id="warpPolicyFeedback"`, `Проверить и применить`} {
		if !strings.Contains(html, required) {
			t.Fatalf("WARP guidance missing %q", required)
		}
	}
	for _, required := range []string{"ENGINE_DRAFT_UNUSED", "warpPolicyDirty", "Сначала назначьте сервис"} {
		if !strings.Contains(app, required) {
			t.Fatalf("WARP apply guard missing %q", required)
		}
	}
}

func TestBypassViewsAndModeControlStaySeparated(t *testing.T) {
	t.Parallel()

	data, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index: %v", err)
	}
	html := string(data)
	for _, required := range []string{
		`id="view-engines"`,
		`id="view-engineconfig"`,
		`data-view="engineconfig"`,
		`id="topModeControl"`,
		`id="topToggleSafeMode"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("usability control missing %q", required)
		}
	}
	for _, duplicate := range []string{`id="topSafeMode"`, `class="status-chip"`} {
		if strings.Contains(html, duplicate) {
			t.Fatalf("duplicate top status returned: %q", duplicate)
		}
	}
}

func TestTopbarUsesLiveRAMAndDetailsAreHumanReadable(t *testing.T) {
	t.Parallel()

	indexData, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatalf("read embedded index: %v", err)
	}
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded app: %v", err)
	}
	html := string(indexData)
	app := string(appData)
	for _, required := range []string{`id="topRAM"`, `class="details-content" id="details"`, `id="detailsSubtitle"`} {
		if !strings.Contains(html, required) {
			t.Fatalf("current usability element missing %q", required)
		}
	}
	for _, required := range []string{"latest.memory_used_percent", "renderRouteComparisonDetails", "Показать технические данные"} {
		if !strings.Contains(app, required) {
			t.Fatalf("current details renderer missing %q", required)
		}
	}
	for _, forbidden := range []string{`id="topTemp"`, `<pre id="details">`} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("legacy UI returned: %q", forbidden)
		}
	}
}

func TestUnifiedThemeCoversAllLegacyWorkspaces(t *testing.T) {
	t.Parallel()

	data, err := embedded.ReadFile("web/v011-theme.css")
	if err != nil {
		t.Fatalf("read current theme: %v", err)
	}
	css := string(data)
	for _, required := range []string{
		".diagnostics-overview",
		".transaction-flow{grid-template-columns:repeat(2",
		".isolated-probe-panel{grid-template-columns:",
		".device-grid{grid-template-columns:repeat(auto-fill",
		".warp-status-grid>div",
		".profile-meta input",
	} {
		if !strings.Contains(css, required) {
			t.Fatalf("current theme does not cover legacy workspace %q", required)
		}
	}
}
