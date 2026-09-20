package main

import (
	"net/url"
	"os"
	"regexp"
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
	versionData, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	version := strings.TrimSpace(string(versionData))
	for _, asset := range []string{
		"/interface.css?v=" + version,
		"/interface-model.js?v=" + version,
		"/interface.js?v=" + version,
		"/app.js?v=" + version,
		"/favicon.ico?v=" + version,
	} {
		if !strings.Contains(html, asset+`"`) {
			t.Fatalf("cache-busted asset missing %q", asset)
		}
	}
	for _, match := range regexp.MustCompile(`(?:src|href)="(/[^"?#]+\.(?:js|css|png|ico)(?:\?[^"#]*)?)"`).FindAllStringSubmatch(html, -1) {
		asset, err := url.Parse(match[1])
		if err != nil || asset.Query().Get("v") != version {
			t.Errorf("asset %q must use full VERSION %q", match[1], version)
		}
	}
	if strings.Count(html, `rel="stylesheet"`) != 1 {
		t.Fatal("router UI must load the one compiled interface stylesheet")
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
	for _, required := range []string{"ENGINE_DRAFT_UNUSED", "warpPolicyDirty", "Выберите сервис для подключения", "компонент не установлен", "сначала создайте или импортируйте профиль", "openEngineInstallation('warp-wg')", "/api/v1/warp/connectivity", "/api/v1/warp/canary", "checkWarpCanary"} {
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
	for _, required := range []string{`id="openBypassSetup"`, `Установить обход`} {
		if !strings.Contains(html, required) {
			t.Fatalf("service setup control missing %q", required)
		}
	}
	for _, required := range []string{"Домены и IP-сети сервиса", "Актуальность списков", "renderServiceListsDetails", "detail_kind: 'service-lists'", "ip_and_cidr", "source_updates", "list_status"} {
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
	for _, required := range []string{"probeVerdict", "probeStatusLabel", "MISROUTED", "INCONCLUSIVE", "Ошибка проверки — это не доказательство неработающего обхода", "Маршрут использован, сервис не ответил", "Сервис работает через этот маршрут", "Сам путь трафика проверяется отдельно"} {
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
		`id="contextNavigation"`,
		`id="topModeControl"`,
		`id="projectModeAuto"`,
		`id="projectModeManual"`,
		`id="projectPower"`,
		`id="toggleSafeMode"`,
	} {
		if !strings.Contains(html, required) {
			t.Fatalf("usability control missing %q", required)
		}
	}
	for _, duplicate := range []string{`id="topSafeMode"`, `id="topToggleSafeMode"`, `class="status-chip"`} {
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
	for _, required := range []string{`id="applyServiceChanges"`, "Проверить и применить", "function needsApplyReview", "pendingChangeViews", "Автопилот (AUTO)"} {
		if !strings.Contains(html+app, required) {
			t.Fatalf("streamlined service apply marker missing %q", required)
		}
	}
	if strings.Contains(app, "askConfirmation('Создать черновик Sing-box'") {
		t.Fatal("draft-only Sing-box import still asks for a redundant confirmation")
	}
}

func TestNodeInventoryIsVisibleWithoutClaimingRouteReadiness(t *testing.T) {
	t.Parallel()
	indexData, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	browserData, err := embedded.ReadFile("web/node-browser.js")
	if err != nil {
		t.Fatalf("read embedded node browser: %v", err)
	}
	content := string(indexData) + string(appData) + string(browserData)
	for _, required := range []string{
		`data-view="nodes"`,
		`id="view-nodes"`,
		`id="nodeSearch"`,
		`id="nodeStateFilter"`,
		`/api/v1/nodes`,
		`Пинг — время соединения с сервером`,
		`nodeServiceHealth`,
		`nodePassivePing`,
		`id="nodeBatchCancel"`,
		`id="nodeOpenImport"`,
		`id="nodeEditDialog"`,
		`id="nodeRevealDialog"`,
		`id="nodeCheckDialog"`,
		`data-node-check=`,
		`/check`,
		`CHECK_NODE`,
		`Пинг · TCP`,
		`Массовая проверка не меняет маршруты`,
		`STORE_REMOTE_NODES`,
		`REVEAL_NODE`,
		`DELETE_NODE`,
		`id="nodeOpenGroup"`,
		`id="nodeGroupDialog"`,
		`/api/v1/node-groups`,
		`CREATE_NODE_GROUP`,
		`Автоматический резерв`,
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("truthful node inventory marker missing %q", required)
		}
	}
	for _, forbidden := range []string{"private_key", "security=tls"} {
		if strings.Contains(string(indexData), forbidden) {
			t.Fatalf("node inventory markup contains private or unsupported field %q", forbidden)
		}
	}
}

func TestUSQUESafeRepairIsExplicitAndDoesNotPromiseRestart(t *testing.T) {
	t.Parallel()
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	indexData, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	content := string(appData) + string(indexData)
	for _, required := range []string{
		"repair.needed && repair.eligible",
		"Безопасно исправить ndmc",
		"REPAIR_USQUE_NDMC",
		"/api/v1/diagnostics/usque/repair",
		"Служба USQUE не перезапускается",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("USQUE safe repair guidance missing %q", required)
		}
	}
}

func TestUSQUEDNSCandidateExplainsReadOnlyScope(t *testing.T) {
	t.Parallel()
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	content := string(appData)
	for _, required := range []string{
		"Проверить другой DNS без применения",
		"DNS роутера, службы и черновики не изменятся",
		"/api/v1/diagnostics/usque/dns-candidate",
		"Он не доказывает TLS, регистрацию, WARP или доступность Telegram",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("USQUE DNS candidate guidance missing %q", required)
		}
	}
}

func TestServiceRouteUISeparatesAppliedStateAndExpandableSettings(t *testing.T) {
	t.Parallel()
	appData, err := embedded.ReadFile("web/service-dashboard-ui.js")
	if err != nil {
		t.Fatal(err)
	}
	indexData, err := embedded.ReadFile("web/index.html")
	if err != nil {
		t.Fatal(err)
	}
	content := string(appData) + string(indexData)
	for _, required := range []string{
		"data-sd-expand",
		"aria-expanded",
		"sd-details",
		"Применённый маршрут",
		"Есть неприменённые изменения",
		"Рекомендация пока не проверена",
		"serviceDashboardFresh",
		"Выбрано: вкл.",
		"Проверить сервис",
		"Подобрать подключение",
		"это не пинг",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("service truth UI marker missing %q", required)
		}
	}
}

func TestNFQWS2ServiceResultOpensOwnershipDrawer(t *testing.T) {
	t.Parallel()
	appData, err := embedded.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := embedded.ReadFile("web/service-dashboard-ui.js")
	if err != nil {
		t.Fatal(err)
	}
	content := string(appData) + string(dashboard)
	for _, required := range []string{
		"renderNFQWS2ServiceDetails",
		"data-sd-nfqws",
		"Внешний владелец",
		"RAZVILKA не будет запускать второй NFQWS2",
		"data-open-strategy-lab",
		"Открыть подбор NFQWS2",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("NFQWS2 drawer marker missing %q", required)
		}
	}
}
