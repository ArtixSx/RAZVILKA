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
		"/style.css?v=0.18.1",
		"/v010.css?v=0.18.1",
		"/v011.css?v=0.18.1",
		"/v011-theme.css?v=0.18.1",
		"/v012.css?v=0.18.1",
		"/app.js?v=0.18.1",
		"/favicon.ico?v=0.18.1",
	} {
		if !strings.Contains(html, asset) {
			t.Fatalf("cache-busted asset missing %q", asset)
		}
	}
}

func TestSettingsExposeBuildProvenance(t *testing.T) {
	t.Parallel()
	html, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	js, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"id=\"settingBuild\"", "build_commit", "build_dirty_known", "build_time"} {
		if !strings.Contains(string(html)+string(js), required) {
			t.Fatalf("build provenance marker %q is missing", required)
		}
	}
}

func TestLoginScreenRendersPublicRuntimeStatus(t *testing.T) {
	t.Parallel()
	data, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(data)
	statusIndex := strings.Index(app, "state.status = status;")
	if statusIndex < 0 {
		t.Fatal("public status assignment is missing")
	}
	renderIndex := strings.Index(app[statusIndex:], "renderStatus();")
	authIndex := strings.Index(app[statusIndex:], "if (status.setup_required")
	if renderIndex < 0 || authIndex < 0 || renderIndex > authIndex {
		t.Fatal("public runtime status must render before the login/setup early return")
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
	for _, required := range []string{`id="warpInstallHint"`, `id="warpInstallComponent"`, `id="warpApplyHint"`, `class="warp-steps"`, `id="warpPolicyFeedback"`, `id="warpConnectivity"`, `id="warpCanaryService"`, `id="warpCanary"`, `Проверить Cloudflare`, `Проверить без применения`, `Проверить и применить`} {
		if !strings.Contains(html, required) {
			t.Fatalf("WARP guidance missing %q", required)
		}
	}
	for _, required := range []string{"ENGINE_DRAFT_UNUSED", "warpPolicyDirty", "Сначала назначьте сервис", "компонент не установлен", "сначала создайте или импортируйте профиль", "openRouteInstallation('warp-wg')", "/api/v1/warp/connectivity", "/api/v1/warp/canary", "checkWarpCanary"} {
		if !strings.Contains(app, required) {
			t.Fatalf("WARP apply guard missing %q", required)
		}
	}
}

func TestServiceCatalogExposesAddressListsAndSourceFreshness(t *testing.T) {
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
	for _, required := range []string{`id="openBypassSetup"`, `+ Установить обход`} {
		if !strings.Contains(html, required) {
			t.Fatalf("service setup control missing %q", required)
		}
	}
	for _, required := range []string{"Домены, IP-сети и актуальность источников", "renderServiceListsDetails", "detail_kind: 'service-lists'", "ip_and_cidr", "source_updates", "list_status"} {
		if !strings.Contains(app, required) {
			t.Fatalf("service address details missing %q", required)
		}
	}
}

func TestDNSUIExplainsEndpointSafetyAndADBit(t *testing.T) {
	t.Parallel()
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssData, err := embedded.ReadFile("web/v012.css")
	if err != nil {
		t.Fatal(err)
	}
	app, css := string(appData), string(cssData)
	for _, required := range []string{"dnsCustomTrustedLocal", "resolver-reported-ad", "резолвер сообщил AD-флаг", "migration_warnings", "Проверяемые endpoint"} {
		if !strings.Contains(app, required) {
			t.Fatalf("DNS safety explanation missing %q", required)
		}
	}
	if !strings.Contains(css, ".dns-trusted-local") {
		t.Fatal("trusted-local control is not styled")
	}
}

func TestEvidenceV2OutcomeAndAgeAreVisible(t *testing.T) {
	t.Parallel()
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(appData)
	for _, required := range []string{"evidenceOutcomeLabel", "service_blocked", "content_mismatch", "evidence_v2?.finished_at", "факт:"} {
		if !strings.Contains(app, required) {
			t.Fatalf("Evidence v2 UI marker missing %q", required)
		}
	}
}

func TestRouteAndServiceProbeOutcomesAreExplainedSeparately(t *testing.T) {
	t.Parallel()
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	cssData, err := embedded.ReadFile("web/v012.css")
	if err != nil {
		t.Fatal(err)
	}
	app, css := string(appData), string(cssData)
	for _, required := range []string{"probeVerdict", "Маршрут использован, сервис не ответил", "Сервис работает через этот маршрут", "Сам путь трафика проверяется отдельно"} {
		if !strings.Contains(app, required) {
			t.Fatalf("probe outcome explanation missing %q", required)
		}
	}
	if !strings.Contains(css, ".probe-verdict") {
		t.Fatal("probe verdict is not styled")
	}
}

func TestUnavailableRoutesExplainInstallationAndProfileSeparately(t *testing.T) {
	t.Parallel()
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(appData)
	for _, required := range []string{"компонент не установлен", "сначала создайте или импортируйте профиль", "route.selectable", "disabled"} {
		if !strings.Contains(app, required) {
			t.Fatalf("route readiness guidance missing %q", required)
		}
	}
}

func TestComponentLifecycleAndEngineDraftRecoveryAreVisible(t *testing.T) {
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
	for _, required := range []string{`id="engineDraftDependency"`, `id="engineDiscardAllDrafts"`, `id="engineAssignService"`} {
		if !strings.Contains(html, required) {
			t.Fatalf("engine draft recovery control missing %q", required)
		}
	}
	for _, required := range []string{"operation_status", "БЫЛО ПРЕРВАНО", "openRouteInstallation", "discardSelectedEngineDrafts"} {
		if !strings.Contains(app, required) {
			t.Fatalf("component lifecycle guidance missing %q", required)
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

func TestWebUIRemainsUsableOnPartialFailure(t *testing.T) {
	t.Parallel()

	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatalf("read embedded app: %v", err)
	}
	cssData, err := embedded.ReadFile("web/v012.css")
	if err != nil {
		t.Fatalf("read embedded accessibility stylesheet: %v", err)
	}
	app, css := string(appData), string(cssData)
	for _, required := range []string{
		"Promise.allSettled",
		"friendlyErrorMessage",
		"beforeunload",
		"Часть данных временно недоступна",
		"Безопасный режим",
		"Подбор NFQWS2",
	} {
		if !strings.Contains(app, required) {
			t.Fatalf("resilient UX guard missing %q", required)
		}
	}
	for _, required := range []string{"button:focus-visible", "cursor: not-allowed"} {
		if !strings.Contains(css, required) {
			t.Fatalf("accessibility style missing %q", required)
		}
	}
}

func TestServicesUseOneExplicitApplyWithoutRoutineReviewModal(t *testing.T) {
	t.Parallel()
	indexData, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	html, app := string(indexData), string(appData)
	for _, required := range []string{`id="applyServiceChanges"`, "Сохранить и проверить", "function needsApplyReview", "sectionOwnsDraft", "Автопилот (AUTO)"} {
		if !strings.Contains(html+app, required) {
			t.Fatalf("streamlined service apply marker missing %q", required)
		}
	}
	if strings.Contains(app, "askConfirmation('Создать черновик Sing-box'") {
		t.Fatal("draft-only Sing-box import still asks for a redundant confirmation")
	}
}
