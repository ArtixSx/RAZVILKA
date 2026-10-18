package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

const nodeImportTTL = 30 * 24 * time.Hour

// All authority-bearing operations must bypass the passive WAN cache.
func (a *App) freshNetworkProfile(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var profile string
	var err error
	if a.FreshProfile != nil {
		profile, err = a.FreshProfile(ctx)
	} else {
		var observed systemprobe.WANProfile
		observed, err = systemprobe.FreshWANProfile(ctx)
		profile = observed.ID
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return "", contextErr
	}
	if err != nil || !systemprobe.ValidWANProfileID(profile) {
		return "", dataplane.ErrExactNodeNetworkChanged
	}
	return profile, nil
}

func (a *App) nodeList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if a.Nodes == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false, "nodes": []any{}, "sources": []any{},
			"note": "Приватное хранилище узлов недоступно. Рабочие маршруты не изменены.",
		})
		return
	}
	snapshot, err := a.Nodes.Snapshot(r.Context(), time.Now())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"available": false, "nodes": []any{}, "sources": []any{},
			"error": "Не удалось прочитать приватное хранилище узлов. Рабочие маршруты не изменены.",
		})
		return
	}
	a.capturePanelNodeBrowse(snapshot, time.Now())
	quarantined, expired, disabled, verified, degraded, stale := 0, 0, 0, 0, 0, 0
	profile := systemprobe.DetectWANProfile().ID
	for index := range snapshot.Nodes {
		node := &snapshot.Nodes[index]
		if !node.Health.CheckedAt.IsZero() && !node.Disabled && (!systemprobe.ValidWANProfileID(profile) || !systemprobe.ValidWANProfileID(node.Health.NetworkProfile) || node.Health.NetworkProfile != profile) {
			node.Health.State = "different_network"
			// A network change invalidates health, not the source expiry. Keep
			// the catalogue selection consistent with durable job admission.
			if node.State != "expired" {
				node.State = "stale"
			}
			node.Health.Message = "Результат получен в другой сети. Повторите проверку на текущем подключении."
		}
		if node.Disabled {
			disabled++
		} else if node.State == "expired" {
			expired++
		} else if node.State == "available" {
			verified++
		} else if node.State == "degraded" {
			degraded++
		} else if node.State == "stale" {
			stale++
		} else {
			quarantined++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available": true, "generation": snapshot.Generation,
		"check_catalog_digest": allVLESSCheckDigest(snapshot),
		"nodes":                snapshot.Nodes, "sources": snapshot.Sources, "groups": snapshot.Groups,
		"counts":           map[string]int{"total": len(snapshot.Nodes), "quarantined": quarantined, "expired": expired, "disabled": disabled, "verified": verified, "degraded": degraded, "stale": stale, "selectable": verified},
		"network_profile":  profile,
		"network_epoch":    systemprobe.NetworkEpochStatus(),
		"node_recovery":    a.nodeRecoverySnapshot(),
		"country_metadata": a.NodeFeeds.CountryMetadata(),
		"note":             "Узел появляется в выборе маршрута только у того сервиса, который успешно прошёл точную проверку в текущей сети.",
	})
}

type nodeGroupRequest struct {
	Name            string   `json:"name"`
	Mode            string   `json:"mode"`
	NodeIDs         []string `json:"node_ids"`
	PreferredNodeID string   `json:"preferred_node_id"`
	HoldDownSeconds int      `json:"hold_down_seconds"`
	Confirm         string   `json:"confirm"`
}

func (a *App) nodeGroups(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Nodes == nil {
		http.Error(w, "node store unavailable", http.StatusServiceUnavailable)
		return
	}
	var request nodeGroupRequest
	if !decodeNodeMutation(w, r, &request) {
		return
	}
	if request.Confirm != "CREATE_NODE_GROUP" {
		http.Error(w, "явно подтвердите создание группы", http.StatusPreconditionRequired)
		return
	}
	group, err := a.Nodes.CreateGroup(r.Context(), request.Name, request.Mode, request.NodeIDs, request.PreferredNodeID, time.Duration(request.HoldDownSeconds)*time.Second, time.Now())
	if err != nil {
		writeNodeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "group": group, "working_routes_changed": false})
}

func (a *App) nodeGroupAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Nodes == nil {
		http.Error(w, "node store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/node-groups/"), "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	var request nodeGroupRequest
	if !decodeNodeMutation(w, r, &request) {
		return
	}
	switch r.Method {
	case http.MethodPut:
		if request.Confirm != "UPDATE_NODE_GROUP" {
			http.Error(w, "явно подтвердите изменение группы", http.StatusPreconditionRequired)
			return
		}
		if a.nodeRouteReferenceExists(id) {
			writeNodeError(w, nodestore.ErrInUse)
			return
		}
		group, err := a.Nodes.UpdateGroup(r.Context(), nodestore.NodeGroup{ID: id, Name: request.Name, Mode: request.Mode, NodeIDs: request.NodeIDs, PreferredNodeID: request.PreferredNodeID, HoldDownSeconds: request.HoldDownSeconds}, time.Now())
		if err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "group": group, "working_routes_changed": false})
	case http.MethodDelete:
		if request.Confirm != "DELETE_NODE_GROUP" {
			http.Error(w, "явно подтвердите удаление группы", http.StatusPreconditionRequired)
			return
		}
		if a.nodeRouteReferenceExists(id) {
			writeNodeError(w, nodestore.ErrInUse)
			return
		}
		if err := a.Nodes.DeleteGroup(r.Context(), id, time.Now()); err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "working_routes_changed": false})
	default:
		methodNotAllowed(w)
	}
}

type nodeMutationRequest struct {
	Alias    *string `json:"alias"`
	Disabled *bool   `json:"disabled"`
	Confirm  string  `json:"confirm"`
}

type nodeCheckRequest struct {
	Engine    string `json:"engine,omitempty"`
	ServiceID string `json:"service_id"`
	Confirm   string `json:"confirm"`
}

func (a *App) nodeAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if a.Nodes == nil {
		http.Error(w, "node store unavailable", http.StatusServiceUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/nodes/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	if action == "reveal" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		var request nodeMutationRequest
		if !decodeNodeMutation(w, r, &request) {
			return
		}
		if request.Confirm != "REVEAL_NODE" || request.Alias != nil || request.Disabled != nil {
			http.Error(w, "явно подтвердите просмотр приватной конфигурации", http.StatusPreconditionRequired)
			return
		}
		err := a.Nodes.WithSecret(r.Context(), id, func(material []byte) error {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok": true, "config": json.RawMessage(material), "ui_clears_on_close": true,
				"note": "Закройте окно после копирования. RAZVILKA не сохраняет открытый текст в журнале.",
			})
			return nil
		})
		if err != nil {
			writeNodeError(w, err)
		}
		return
	}
	if action == "check" {
		a.nodeCheck(w, r, id)
		return
	}
	if action == "preview" {
		a.nodeRoutePreview(w, r, id)
		return
	}
	if action == "apply" {
		a.nodeRouteApply(w, r, id)
		return
	}
	if action != "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		var request nodeMutationRequest
		if !decodeNodeMutation(w, r, &request) {
			return
		}
		if request.Confirm != "" || (request.Alias == nil) == (request.Disabled == nil) {
			http.Error(w, "измените ровно одно поле узла", http.StatusBadRequest)
			return
		}
		var err error
		if request.Alias != nil {
			_, err = a.Nodes.SetAlias(r.Context(), id, *request.Alias, time.Now())
		} else {
			_, err = a.Nodes.SetDisabled(r.Context(), id, *request.Disabled, time.Now())
		}
		if err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "working_routes_changed": false})
	case http.MethodDelete:
		var request nodeMutationRequest
		if !decodeNodeMutation(w, r, &request) {
			return
		}
		if request.Confirm != "DELETE_NODE" || request.Alias != nil || request.Disabled != nil {
			http.Error(w, "явно подтвердите удаление сохранённого узла", http.StatusPreconditionRequired)
			return
		}
		if a.nodeRouteReferenceExists(id) {
			writeNodeError(w, nodestore.ErrInUse)
			return
		}
		// The legacy single-node action must protect the same autonomous reserves,
		// suspended routes and rollback references as the batch operation.
		release, err := a.privateRestoreAdmission(r.Context())
		if err != nil {
			a.writeOperationFailure(w, err)
			return
		}
		defer release()
		snapshot, err := a.Nodes.Snapshot(r.Context(), time.Now())
		if err != nil {
			writeNodeError(w, err)
			return
		}
		protected, err := a.protectedCleanupNodes(r.Context(), snapshot)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Состояние восстановления не подтверждено. Узел сохранён."})
			return
		}
		if protected[id] != "" {
			writeNodeError(w, nodestore.ErrInUse)
			return
		}
		if _, err := a.Nodes.Delete(r.Context(), id, time.Now()); err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "working_routes_changed": false})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) nodeRouteReferenceExists(id string) bool {
	return a.routeReferenceExists("sing-box:"+id) || a.routeReferenceExists("xray:"+id)
}

func (a *App) routeReferenceExists(route string) bool {
	if a.Store == nil {
		return false
	}
	cfg := a.Store.Get()
	for _, states := range []map[string]config.ServiceState{cfg.Services, cfg.AppliedServices} {
		for _, state := range states {
			if selectedRoute(state) == route {
				return true
			}
		}
	}
	return false
}

func (a *App) nodeCheck(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request nodeCheckRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.Confirm != "CHECK_NODE" || request.ServiceID == "" {
		http.Error(w, "выберите сервис и явно подтвердите точную проверку", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "некорректный запрос проверки", http.StatusBadRequest)
		return
	}
	engine, err := nodeCheckEngine(request.Engine)
	if err != nil {
		http.Error(w, "неподдерживаемый движок проверки", http.StatusBadRequest)
		return
	}
	var serviceFound bool
	var service catalog.Service
	for _, candidate := range a.catalogSnapshot().Services {
		if candidate.ID == request.ServiceID && serviceHasNodeProbe(candidate) {
			service = candidate
			serviceFound = true
			break
		}
	}
	if !serviceFound {
		http.Error(w, "для сервиса нет безопасного контрольного сценария", http.StatusBadRequest)
		return
	}
	result, _, err := a.checkAndRecordNodeForEngine(r.Context(), engine, id, service, "", 0)
	if err != nil {
		switch {
		case errors.Is(err, errNodeHistoryAdmission):
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "code": "NODE_HISTORY_ADMISSION_REQUIRED", "engine": engine, "recorded": false, "working_routes_changed": false, "error": "Совместимость сохранённой истории при откате ещё не подтверждена. Проверка выбранным движком приостановлена."})
		case result.ErrorCode == "node-cleanup-failed":
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "code": "NODE_CLEANUP_REQUIRED", "error": "Очистка временного процесса не подтверждена. Проверки остановлены до восстановления.", "result": result, "recorded": false, "working_routes_changed": false})
		case errors.Is(err, dataplane.ErrNodeResourceDenied):
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "NODE_RESOURCE_REFUSED", "recorded": false, "working_routes_changed": false, "error": "Ресурс исключён, не включён в активный список или условия проверки изменились."})
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			status, code, message := http.StatusGatewayTimeout, "NODE_CHECK_DEADLINE", "Истекло общее время проверки. Повторите проверку узла."
			if errors.Is(err, context.Canceled) {
				status, code, message = http.StatusRequestTimeout, "NODE_CHECK_CANCELED", "Проверка отменена. Результат не сохранён."
			}
			body := map[string]any{"ok": false, "code": code, "error": message, "recorded": false, "working_routes_changed": false}
			if result.ProbeID != "" {
				// An interrupted operation cannot expose a usable proof, including
				// cancellation between the checker returning and Store validation.
				result.Available = false
				result.Verdict = evidence.VerdictInconclusive
				result.EgressIP = ""
				result.Stage, result.ErrorCode, result.Message = "deadline", "node-check-deadline", message
				if errors.Is(err, context.Canceled) {
					result.Stage, result.ErrorCode = "canceled", "node-check-canceled"
				}
				result.Evidence.Verdict = evidence.VerdictInconclusive
				result.Evidence.Outcome = evidence.OutcomeUnknown
				result.Evidence.EgressIP = ""
				result.Evidence.ErrorCode = result.ErrorCode
				body["result"] = result
			}
			writeJSON(w, status, body)
		case errors.Is(err, dataplane.ErrExactNodeNetworkChanged):
			writeNodeNetworkError(w)
		case errors.Is(err, dataplane.ErrExactNodeBusy):
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Другая точная проверка уже выполняется. Повторите через несколько секунд."})
		case errors.Is(err, dataplane.ErrExactNodeRuntime):
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "code": "NODE_ENGINE_UNAVAILABLE", "engine": engine, "recorded": false, "working_routes_changed": false, "error": "Компонент выбранного движка проверки недоступен."})
		case errors.Is(err, dataplane.ErrExactNodeUnsupported):
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "NODE_ENGINE_UNSUPPORTED", "engine": engine, "recorded": false, "working_routes_changed": false, "error": "Выбранный движок не поддерживает профиль этого узла."})
		case errors.Is(err, dataplane.ErrExactNodeUnavailable):
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Проверка недоступна: входные данные или среда не прошли защитные ограничения."})
		default:
			writeNodeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": result.Available, "result": result, "working_routes_changed": false})
}

// Both explicit checks and applied-route recovery use this exact checker and
// Store path. A recovery supplies its immutable epoch and expected generation;
// its own RecordCheck is the only permitted generation increment.
func (a *App) checkAndRecordNode(ctx context.Context, id string, service catalog.Service, profile string, generation uint64) (dataplane.NodeCheckResult, nodestore.Snapshot, error) {
	return a.checkAndRecordNodeForEngine(ctx, "sing-box", id, service, profile, generation)
}

func (a *App) checkAndRecordNodeForEngine(ctx context.Context, engine, id string, service catalog.Service, profile string, generation uint64) (dataplane.NodeCheckResult, nodestore.Snapshot, error) {
	checker, err := a.nodeCheckerForEngine(engine)
	if err != nil {
		return dataplane.NodeCheckResult{}, nodestore.Snapshot{}, err
	}
	return a.runAndRecordNode(ctx, engine, id, service, profile, generation, func(checkCtx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, bool, error) {
		result, err := checker.Check(checkCtx, request)
		return result, true, err
	})
}

// screenAndRecordNode runs only the DNS and transport stages. A node that
// fails them is decided and recorded exactly as a full check would record it;
// otherwise nothing is recorded and a full check is still required.
func (a *App) screenAndRecordNode(ctx context.Context, id string, service catalog.Service, profile string) (dataplane.NodeCheckResult, bool, error) {
	return a.screenAndRecordNodeForEngine(ctx, "sing-box", id, service, profile)
}

func (a *App) screenAndRecordNodeForEngine(ctx context.Context, engine, id string, service catalog.Service, profile string) (dataplane.NodeCheckResult, bool, error) {
	checker, err := a.nodeCheckerForEngine(engine)
	if err != nil {
		return dataplane.NodeCheckResult{}, false, err
	}
	screener, ok := checker.(dataplane.TransportScreener)
	if !ok {
		return dataplane.NodeCheckResult{}, false, nil
	}
	decided := false
	result, _, err := a.runAndRecordNode(ctx, engine, id, service, profile, 0, func(checkCtx context.Context, request dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, bool, error) {
		result, screened, err := screener.ScreenTransport(checkCtx, request)
		decided = screened
		return result, screened, err
	})
	return result, decided && err == nil, err
}

// nodeCheckCapacity is how many checks the checker runs at once.
func (a *App) nodeCheckCapacity() int {
	if capacity, ok := a.NodeChecker.(dataplane.NodeCheckCapacity); ok && capacity.Capacity() > 1 {
		return capacity.Capacity()
	}
	return 1
}

// runAndRecordNode runs one check of a node and records its result when run
// reports it final. With a generation, the whole catalogue must be unchanged
// (a reviewed plan depends on it). Without one, only this node must still be
// present and enabled: node IDs are derived from their configuration, so
// other nodes or sources changing meanwhile, including parallel checks
// recording their results, do not change what was checked.
func (a *App) runAndRecordNode(ctx context.Context, engine, id string, service catalog.Service, profile string, generation uint64, run func(context.Context, dataplane.NodeCheckRequest) (dataplane.NodeCheckResult, bool, error)) (dataplane.NodeCheckResult, nodestore.Snapshot, error) {
	var result dataplane.NodeCheckResult
	if a.Nodes == nil || run == nil || !serviceHasNodeProbe(service) {
		return result, nodestore.Snapshot{}, dataplane.ErrExactNodeUnavailable
	}
	if err := a.nodeHistoryAdmission(ctx, engine); err != nil {
		return result, nodestore.Snapshot{}, err
	}
	if a.Store == nil {
		return result, nodestore.Snapshot{}, dataplane.ErrNodeResourceDenied
	}
	owner, cfg := a.Store, a.Store.Get()
	service = defaultRouteCloneCatalogService(service)
	definitions := a.catalogSnapshot()
	for i := range definitions.Services {
		definitions.Services[i] = defaultRouteCloneCatalogService(definitions.Services[i])
	}
	resourceGuard := func(checkCtx context.Context, host string, address netip.Addr) error {
		if a.Store != owner || !reflect.DeepEqual(definitions, a.catalogSnapshot()) {
			return dataplane.ErrNodeResourceDenied
		}
		return a.nodeResourceAdmission(checkCtx, cfg, service, host, address)
	}
	if err := resourceGuard(ctx, "", netip.Addr{}); err != nil {
		return result, nodestore.Snapshot{}, err
	}
	checkCtx := dataplane.WithNodeResourceGuard(ctx, resourceGuard)
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return result, snapshot, err
	}
	if generation != 0 && snapshot.Generation != generation {
		return result, snapshot, dataplane.ErrReviewChanged
	}
	found := false
	for _, node := range snapshot.Nodes {
		if node.ID == id {
			found = true
			if node.Disabled {
				return result, snapshot, nodestore.ErrDisabled
			}
			break
		}
	}
	if !found {
		return result, snapshot, nodestore.ErrNotFound
	}
	current, err := a.freshNetworkProfile(ctx)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return result, snapshot, err
	}
	if err != nil || profile != "" && current != profile {
		return result, snapshot, dataplane.ErrExactNodeNetworkChanged
	}
	profile = current
	record := false
	err = a.Nodes.WithSecret(ctx, id, func(material []byte) error {
		var checkErr error
		if err := resourceGuard(checkCtx, "", netip.Addr{}); err != nil {
			return err
		}
		result, record, checkErr = run(checkCtx, dataplane.NodeCheckRequest{NodeID: id, Outbound: material, Service: defaultRouteCloneCatalogService(service), NetworkProfile: profile})
		return checkErr
	})
	if err != nil {
		if errors.Is(err, dataplane.ErrNodeResourceDenied) && result.Stage != "cleanup" {
			dataplane.RefuseNodeResourceResult(&result)
		}
		return result, snapshot, err
	}
	if err := ctx.Err(); err != nil {
		return result, snapshot, err
	}
	if err := resourceGuard(checkCtx, "", netip.Addr{}); err != nil {
		dataplane.RefuseNodeResourceResult(&result)
		return result, snapshot, err
	}
	if !record {
		return result, snapshot, nil
	}
	if !exactNodeResultIdentity(result, engine, id, service.ID, profile) {
		return result, snapshot, dataplane.ErrExactNodeUnavailable
	}
	current, err = a.freshNetworkProfile(ctx)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return result, snapshot, err
	}
	if err != nil || current != profile {
		return result, snapshot, dataplane.ErrExactNodeNetworkChanged
	}
	a.nodeRecordMu.Lock()
	defer a.nodeRecordMu.Unlock()
	latest, err := a.Nodes.Snapshot(ctx, time.Now())
	if err != nil {
		return result, snapshot, err
	}
	if generation != 0 && latest.Generation != snapshot.Generation || generation == 0 && !nodeStillCheckable(latest, id) {
		return result, snapshot, dataplane.ErrReviewChanged
	}
	before := latest.Generation
	if err := a.nodeHistoryAdmission(ctx, engine); err != nil {
		return result, latest, err
	}
	state := "unavailable"
	if result.Available {
		state = "available"
	}
	err = owner.WithResourceExclusionObservation(ctx, cfg, func(config.EffectiveExclusionSet) error {
		var recordErr error
		latest, recordErr = a.Nodes.RecordCheck(ctx, id, nodestore.CheckRecord{
			ProbeID: result.ProbeID, ServiceID: result.ServiceID, NetworkProfile: result.NetworkProfile,
			RoutePathID: result.RoutePathID, TestLevel: result.TestLevel, Verdict: string(result.Verdict), State: state,
			Stage: result.Stage, CheckedAt: result.FinishedAt, ExpiresAt: result.ExpiresAt, LatencyMS: result.LatencyMS,
			EgressIP: result.EgressIP, HTTPStatus: result.HTTPStatus, ErrorCode: result.ErrorCode, Message: result.Message, DirectLeak: result.DirectLeak,
		}, time.Now())
		return recordErr
	})
	if err == nil && latest.Generation != before+1 {
		err = dataplane.ErrReviewChanged
	}
	if err == nil {
		a.rememberNodeMeasurement(result)
	} else if errors.Is(err, config.ErrRevisionChanged) {
		dataplane.RefuseNodeResourceResult(&result)
		err = errors.Join(dataplane.ErrNodeResourceDenied, err)
	}
	return result, latest, err
}

func nodeStillCheckable(snapshot nodestore.Snapshot, id string) bool {
	for _, node := range snapshot.Nodes {
		if node.ID == id {
			return !node.Disabled
		}
	}
	return false
}

func writeNodeNetworkError(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "NODE_NETWORK_CHANGED", "error": "Сеть изменилась или не подтверждена. Повторите проверку на текущем подключении.", "working_routes_changed": false})
}

func serviceHasNodeProbe(service catalog.Service) bool {
	if service.ProbeURL != "" {
		return true
	}
	for _, probe := range service.Probes {
		if probe.Required && probe.URL != "" {
			return true
		}
	}
	return false
}

func (a *App) nodeImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Nodes == nil {
		http.Error(w, "node store unavailable", http.StatusServiceUnavailable)
		return
	}
	request, ok := decodeProviderProfileRequest(w, r)
	if !ok {
		return
	}
	if request.Confirm != "STORE_REMOTE_NODES" {
		http.Error(w, "явно подтвердите сохранение узлов", http.StatusPreconditionRequired)
		return
	}
	parsed, err := providerprofile.ParseCanonicalProfile(request.Profile)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "code": providerprofile.ErrorCode(err), "error": "Пакет узлов не принят.", "preview": parsed.Preview})
		return
	}
	if len(parsed.Preview.Rejected) > 0 && !request.AcceptPartial {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{
			"ok": false, "code": "PARTIAL_IMPORT_CONFIRMATION_REQUIRED", "error": "Проверьте отклонённые записи и явно сохраните только принятые.", "preview": parsed.Preview,
		})
		return
	}
	required, err := nodestore.RequiredImportReadVersion(request.Profile, request.AcceptPartial)
	if err == nil {
		err = a.nodeHistoryMaterialAdmission(r.Context(), required)
	}
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "code": "NODE_HISTORY_ADMISSION_REQUIRED", "error": "Не удалось подтвердить совместимость сохранённой истории узлов. Данные не записаны.", "working_routes_changed": false})
		return
	}
	snapshot, err := a.Nodes.Import(r.Context(), nodestore.Source{ID: "manual", Kind: "manual"}, request.Profile, time.Now(), nodeImportTTL, request.AcceptPartial)
	if err != nil {
		writeNodeError(w, err)
		return
	}
	countryErr := a.NodeFeeds.RecordManualImportCountries(r.Context(), request.Profile)
	note := "Принятые узлы сохранены локально и ожидают проверки. Sing-box и маршруты не изменены."
	if countryErr != nil {
		note += " Отметку страны сохранить не удалось; принятые узлы сохранены."
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "accepted_nodes": parsed.Preview.NodeCount, "total_nodes": len(snapshot.Nodes), "generation": snapshot.Generation,
		"working_routes_changed": false,
		"note":                   note,
	})
}

func decodeNodeMutation(w http.ResponseWriter, r *http.Request, out any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		http.Error(w, "некорректный запрос узла", http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "некорректный запрос узла", http.StatusBadRequest)
		return false
	}
	return true
}

func writeNodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, nodestore.ErrNotFound):
		http.Error(w, "узел не найден", http.StatusNotFound)
	case errors.Is(err, nodestore.ErrAlias):
		http.Error(w, "название должно содержать не более 64 обычных символов", http.StatusBadRequest)
	case errors.Is(err, nodestore.ErrDisabled):
		http.Error(w, "сначала включите узел, затем повторите проверку", http.StatusConflict)
	case errors.Is(err, nodestore.ErrGroup):
		http.Error(w, "проверьте название, режим, состав и выбранный основной узел группы", http.StatusBadRequest)
	case errors.Is(err, nodestore.ErrInUse):
		http.Error(w, "узел или группа ещё используются сервисом либо входят в группу; сначала уберите соответствующее назначение", http.StatusConflict)
	case errors.Is(err, nodestore.ErrRouteProof):
		http.Error(w, "для узла нет свежей точной проверки этого сервиса в текущей сети", http.StatusConflict)
	case errors.Is(err, nodestore.ErrRecovery):
		http.Error(w, "результат записи не определён; хранилище заблокировано до безопасного восстановления", http.StatusServiceUnavailable)
	default:
		http.Error(w, "операция с узлом не выполнена", http.StatusServiceUnavailable)
	}
}
