package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

const nodeImportTTL = 30 * 24 * time.Hour

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
	quarantined, expired, disabled, verified, degraded, stale := 0, 0, 0, 0, 0, 0
	profile := systemprobe.DetectWANProfile().ID
	for index := range snapshot.Nodes {
		node := &snapshot.Nodes[index]
		if !node.Health.CheckedAt.IsZero() && node.Health.NetworkProfile != "" && node.Health.NetworkProfile != profile && !node.Disabled {
			node.Health.State = "different_network"
			node.State = "stale"
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
		"nodes": snapshot.Nodes, "sources": snapshot.Sources,
		"counts":          map[string]int{"total": len(snapshot.Nodes), "quarantined": quarantined, "expired": expired, "disabled": disabled, "verified": verified, "degraded": degraded, "stale": stale, "selectable": 0},
		"network_profile": profile,
		"note":            "Проверенные узлы пока не назначаются маршрутам: безопасная привязка будет подключена следующим этапом.",
	})
}

type nodeMutationRequest struct {
	Alias    *string `json:"alias"`
	Disabled *bool   `json:"disabled"`
	Confirm  string  `json:"confirm"`
}

type nodeCheckRequest struct {
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
		if _, err := a.Nodes.Delete(r.Context(), id, time.Now()); err != nil {
			writeNodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "working_routes_changed": false})
	default:
		methodNotAllowed(w)
	}
}

func (a *App) nodeCheck(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.NodeChecker == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Точная проверка узлов сейчас недоступна. Убедитесь, что Sing-box установлен."})
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
	snapshot, err := a.Nodes.Snapshot(r.Context(), time.Now())
	if err != nil {
		writeNodeError(w, err)
		return
	}
	nodeFound := false
	for _, node := range snapshot.Nodes {
		if node.ID != id {
			continue
		}
		nodeFound = true
		if node.Disabled {
			writeNodeError(w, nodestore.ErrDisabled)
			return
		}
		break
	}
	if !nodeFound {
		writeNodeError(w, nodestore.ErrNotFound)
		return
	}
	profile := systemprobe.DetectWANProfile().ID
	var result dataplane.NodeCheckResult
	err = a.Nodes.WithSecret(r.Context(), id, func(material []byte) error {
		var checkErr error
		result, checkErr = a.NodeChecker.Check(r.Context(), dataplane.NodeCheckRequest{NodeID: id, Outbound: material, Service: service, NetworkProfile: profile})
		return checkErr
	})
	if err != nil {
		switch {
		case errors.Is(err, dataplane.ErrExactNodeBusy):
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "Другая точная проверка уже выполняется. Повторите через несколько секунд."})
		case errors.Is(err, dataplane.ErrExactNodeRuntime):
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Для точной проверки сначала установите компонент Sing-box в разделе «Обходы»."})
		case errors.Is(err, dataplane.ErrExactNodeUnavailable):
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Проверка недоступна: входные данные или среда не прошли защитные ограничения."})
		default:
			writeNodeError(w, err)
		}
		return
	}
	if result.NodeID != id || result.ServiceID != service.ID || result.NetworkProfile != profile || result.RoutePathID != "sing-box:"+id {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "Проверка вернула несогласованный результат; он не был сохранён."})
		return
	}
	state := "unavailable"
	if result.Available {
		state = "available"
	}
	_, err = a.Nodes.RecordCheck(r.Context(), id, nodestore.CheckRecord{
		ProbeID: result.ProbeID, ServiceID: result.ServiceID, NetworkProfile: result.NetworkProfile,
		RoutePathID: result.RoutePathID, TestLevel: result.TestLevel, Verdict: string(result.Verdict), State: state,
		Stage: result.Stage, CheckedAt: result.FinishedAt, ExpiresAt: result.ExpiresAt, LatencyMS: result.LatencyMS,
		EgressIP: result.EgressIP, HTTPStatus: result.HTTPStatus, ErrorCode: result.ErrorCode, Message: result.Message, DirectLeak: result.DirectLeak,
	}, time.Now())
	if err != nil {
		writeNodeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": result.Available, "result": result, "working_routes_changed": false})
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
	parsed, err := providerprofile.ParseProfile(request.Profile)
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
	snapshot, err := a.Nodes.Import(r.Context(), nodestore.Source{ID: "manual", Kind: "manual"}, request.Profile, time.Now(), nodeImportTTL, request.AcceptPartial)
	if err != nil {
		writeNodeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "accepted_nodes": parsed.Preview.NodeCount, "total_nodes": len(snapshot.Nodes), "generation": snapshot.Generation,
		"working_routes_changed": false,
		"note":                   "Принятые узлы сохранены локально и ожидают проверки. Sing-box и маршруты не изменены.",
	})
}

func decodeNodeMutation(w http.ResponseWriter, r *http.Request, out *nodeMutationRequest) bool {
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
	case errors.Is(err, nodestore.ErrRecovery):
		http.Error(w, "результат записи не определён; хранилище заблокировано до безопасного восстановления", http.StatusServiceUnavailable)
	default:
		http.Error(w, "операция с узлом не выполнена", http.StatusServiceUnavailable)
	}
}
