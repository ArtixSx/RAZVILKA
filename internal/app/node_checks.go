package app

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

const maxNodeCheckBatch = 64

type nodeCheckJobRequest struct {
	NodeIDs   []string `json:"node_ids"`
	ServiceID string   `json:"service_id"`
	Mode      string   `json:"mode"`
}

type nodeCheckItem struct {
	NodeID         string    `json:"node_id"`
	NetworkProfile string    `json:"network_profile"`
	CheckedAt      time.Time `json:"checked_at"`
	Reachable      bool      `json:"reachable"`
	Available      bool      `json:"available"`
	LatencyMS      int64     `json:"latency_ms,omitempty"`
	DurationMS     int64     `json:"duration_ms,omitempty"`
	Message        string    `json:"message"`
}

type nodeCheckJob struct {
	ID             uint64                 `json:"id"`
	Mode           string                 `json:"mode"`
	ServiceID      string                 `json:"service_id,omitempty"`
	State          string                 `json:"state"`
	Total          int                    `json:"total"`
	Completed      int                    `json:"completed"`
	StartedAt      time.Time              `json:"started_at"`
	FinishedAt     *time.Time             `json:"finished_at,omitempty"`
	Message        string                 `json:"message"`
	Results        []nodeCheckItem        `json:"results"`
	ServiceResults []serviceControlResult `json:"service_results,omitempty"`
}

type nodeCheckState struct {
	mu              sync.Mutex
	root            context.Context
	closed          bool
	nextID          uint64
	job             *nodeCheckJob
	cancel          context.CancelFunc
	done            chan struct{}
	pings           map[string]nodeCheckItem
	serviceResults  map[string]serviceControlResult
	serviceAttempts map[string]time.Time
}

// StartNodeChecks attaches detached checks to application lifetime. Call before
// serving HTTP; every accepted job keeps its own operation admission until all
// network work and the exact checker's cleanup have finished.
func (a *App) StartNodeChecks(ctx context.Context) {
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	if a.nodeChecks.root == nil && !a.nodeChecks.closed {
		// Stay within JavaScript's exact integer range while preventing a stale
		// browser cancel from matching a new process's first job after restart.
		var seed [8]byte
		if _, err := rand.Read(seed[:]); err != nil {
			a.nodeChecks.closed = true
			return
		}
		a.nodeChecks.nextID = 1 + (binary.LittleEndian.Uint64(seed[:]) & ((1 << 48) - 1))
		a.nodeChecks.root = ctx
	}
}

// WaitNodeChecks stops admission, cancels the current job and joins it.
func (a *App) WaitNodeChecks(ctx context.Context) error {
	a.nodeChecks.mu.Lock()
	a.nodeChecks.closed = true
	if a.nodeChecks.cancel != nil {
		a.nodeChecks.cancel()
	}
	done := a.nodeChecks.done
	a.nodeChecks.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *App) nodeCheckSnapshot() map[string]any {
	a.nodeChecks.mu.Lock()
	defer a.nodeChecks.mu.Unlock()
	var job *nodeCheckJob
	if a.nodeChecks.job != nil {
		copy := *a.nodeChecks.job
		copy.Results = append([]nodeCheckItem{}, copy.Results...)
		copy.ServiceResults = append([]serviceControlResult{}, copy.ServiceResults...)
		for i := range copy.ServiceResults {
			copy.ServiceResults[i].Scope.Sources = append([]string{}, copy.ServiceResults[i].Scope.Sources...)
		}
		job = &copy
	}
	pings := make([]nodeCheckItem, 0, len(a.nodeChecks.pings))
	for _, ping := range a.nodeChecks.pings {
		pings = append(pings, ping)
	}
	sort.Slice(pings, func(i, j int) bool { return pings[i].NodeID < pings[j].NodeID })
	return map[string]any{"job": job, "pings": pings, "working_routes_changed": false}
}

func (a *App) nodeCheckJobCurrent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	switch r.Method {
	case http.MethodGet:
	case http.MethodDelete:
		a.nodeChecks.mu.Lock()
		if a.nodeChecks.cancel != nil && a.nodeChecks.job != nil {
			a.nodeChecks.job.State = "canceling"
			a.nodeChecks.job.Message = "Завершаем текущую проверку и очищаем временные ресурсы."
			a.nodeChecks.cancel()
		}
		a.nodeChecks.mu.Unlock()
	default:
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, a.nodeCheckSnapshot())
}

func (a *App) nodeCheckJobs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if a.Nodes == nil {
		http.Error(w, "Хранилище узлов недоступно.", http.StatusServiceUnavailable)
		return
	}
	var request nodeCheckJobRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(request.NodeIDs) == 0 || len(request.NodeIDs) > maxNodeCheckBatch || request.Mode != "tcp" && request.Mode != "service" {
		http.Error(w, "Выберите от 1 до 64 узлов и тип проверки.", http.StatusBadRequest)
		return
	}
	enter := a.Operations.Enter
	if request.Mode == "service" {
		enter = a.Operations.Exclusive
	}
	release, err := enter(r.Context())
	if err != nil {
		a.writeOperationFailure(w, err)
		return
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	var service catalog.Service
	if request.Mode == "service" {
		if a.NodeChecker == nil {
			http.Error(w, "Для проверки сервиса нужен компонент Sing-box.", http.StatusServiceUnavailable)
			return
		}
		for _, candidate := range a.catalogSnapshot().Services {
			if candidate.ID == request.ServiceID && serviceHasNodeProbe(candidate) {
				service = candidate
				break
			}
		}
		if service.ID == "" {
			http.Error(w, "Выберите сервис с доступной проверкой.", http.StatusBadRequest)
			return
		}
	} else {
		request.ServiceID = ""
	}
	snapshot, err := a.Nodes.Snapshot(r.Context(), time.Now())
	if err != nil {
		writeNodeError(w, err)
		return
	}
	allowed := make(map[string]bool, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		allowed[node.ID] = !node.Disabled && node.State != "expired"
	}
	seen := make(map[string]bool, len(request.NodeIDs))
	for _, id := range request.NodeIDs {
		if !allowed[id] || seen[id] {
			http.Error(w, "Список содержит повторный, отключённый или недоступный узел.", http.StatusBadRequest)
			return
		}
		seen[id] = true
	}
	// The handler owns this independent admission; HTTP 202 does not release
	// it or allow restore/apply to overlap the checker and its cleanup.
	a.nodeChecks.mu.Lock()
	if a.nodeChecks.closed || a.nodeChecks.root == nil || a.nodeChecks.root.Err() != nil {
		a.nodeChecks.mu.Unlock()
		http.Error(w, "Приложение завершает работу. Повторите после запуска.", http.StatusServiceUnavailable)
		return
	}
	if a.nodeChecks.cancel != nil {
		a.nodeChecks.mu.Unlock()
		w.Header().Set("Retry-After", "2")
		http.Error(w, "Проверка уже выполняется. Дождитесь завершения или остановите её.", http.StatusConflict)
		return
	}
	// Service checks may take up to 45 seconds each. A job has a fixed upper
	// bound even when an injected or future checker has a larger default.
	budget := 5 * time.Minute
	if request.Mode == "service" {
		budget = time.Duration(len(request.NodeIDs))*time.Minute + time.Minute
	}
	ctx, cancel := context.WithTimeout(a.nodeChecks.root, budget)
	a.nodeChecks.nextID++
	id := a.nodeChecks.nextID
	a.nodeChecks.job = &nodeCheckJob{ID: id, Mode: request.Mode, ServiceID: request.ServiceID, State: "running", Total: len(request.NodeIDs), StartedAt: time.Now().UTC(), Message: "Проверяем выбранные узлы.", Results: []nodeCheckItem{}}
	a.nodeChecks.cancel = cancel
	done := make(chan struct{})
	a.nodeChecks.done = done
	pinger := a.NodePinger
	if pinger == nil {
		pinger = dataplane.NewTCPNodePinger()
	}
	a.nodeChecks.mu.Unlock()
	retained = true
	go a.runNodeChecks(ctx, cancel, done, release, id, request, service, pinger)
	writeJSON(w, http.StatusAccepted, a.nodeCheckSnapshot())
}

func (a *App) runNodeChecks(ctx context.Context, cancel context.CancelFunc, done chan struct{}, release func(), id uint64, request nodeCheckJobRequest, service catalog.Service, pinger dataplane.NodePinger) {
	defer close(done)
	defer release()
	defer cancel()
	profile, err := a.freshNetworkProfile(ctx)
	if err == nil {
		workers := 1
		if request.Mode == "tcp" {
			workers = 2
		}
		work := make(chan string)
		var joined sync.WaitGroup
		for worker := 0; worker < workers; worker++ {
			joined.Add(1)
			go func() {
				defer joined.Done()
				for nodeID := range work {
					if ctx.Err() != nil {
						return
					}
					item := a.runNodeCheckItem(ctx, request.Mode, nodeID, service, profile, pinger)
					a.nodeChecks.mu.Lock()
					if a.nodeChecks.job != nil && a.nodeChecks.job.ID == id {
						a.nodeChecks.job.Results = append(a.nodeChecks.job.Results, item)
						a.nodeChecks.job.Completed++
						if request.Mode == "tcp" {
							if a.nodeChecks.pings == nil {
								a.nodeChecks.pings = make(map[string]nodeCheckItem)
							}
							if len(a.nodeChecks.pings) >= nodestore.MaxNodes {
								var oldest string
								for key, value := range a.nodeChecks.pings {
									if oldest == "" || value.CheckedAt.Before(a.nodeChecks.pings[oldest].CheckedAt) {
										oldest = key
									}
								}
								delete(a.nodeChecks.pings, oldest)
							}
							a.nodeChecks.pings[nodeID] = item
						}
					}
					a.nodeChecks.mu.Unlock()
				}
			}()
		}
	send:
		for _, nodeID := range request.NodeIDs {
			select {
			case work <- nodeID:
			case <-ctx.Done():
				break send
			}
		}
		close(work)
		joined.Wait()
	}
	a.nodeChecks.mu.Lock()
	if a.nodeChecks.job != nil && a.nodeChecks.job.ID == id {
		job := a.nodeChecks.job
		finished := time.Now().UTC()
		job.FinishedAt = &finished
		job.State, job.Message = "completed", "Проверка завершена."
		if ctx.Err() != nil {
			job.State, job.Message = "canceled", "Проверка остановлена."
		} else if err != nil {
			job.State, job.Message = "failed", "Не удалось подтвердить текущую сеть. Повторите проверку."
		}
		a.nodeChecks.cancel = nil
	}
	a.nodeChecks.mu.Unlock()
}

func (a *App) runNodeCheckItem(ctx context.Context, mode, id string, service catalog.Service, profile string, pinger dataplane.NodePinger) nodeCheckItem {
	item := nodeCheckItem{NodeID: id, NetworkProfile: profile, Message: "Проверка не завершена."}
	if mode == "service" {
		checkContext, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		result, _, err := a.checkAndRecordNode(checkContext, id, service, profile, 0)
		item.CheckedAt = time.Now().UTC()
		if err == nil {
			item.Available, item.DurationMS, item.Message = result.Available, result.LatencyMS, result.Message
		} else {
			item.Message = nodeCheckFailureMessage(err)
		}
		return item
	}
	current, err := a.freshNetworkProfile(ctx)
	if err != nil || current != profile {
		item.CheckedAt = time.Now().UTC()
		item.Message = "Сеть изменилась. Повторите проверку."
		return item
	}
	snapshot, err := a.Nodes.Snapshot(ctx, time.Now())
	if err == nil {
		eligible := false
		for _, node := range snapshot.Nodes {
			if node.ID == id && !node.Disabled && node.State != "expired" {
				eligible = true
			}
		}
		if !eligible {
			err = nodestore.ErrDisabled
		}
	}
	if err == nil {
		err = a.Nodes.WithSecret(ctx, id, func(material []byte) error {
			ping := pinger.Ping(ctx, material)
			item.Reachable, item.LatencyMS, item.Message = ping.Reachable, ping.LatencyMS, ping.Message
			return nil
		})
	}
	if err != nil {
		item.Message = nodeCheckFailureMessage(err)
	}
	if current, networkErr := a.freshNetworkProfile(ctx); networkErr != nil || current != profile {
		item.Reachable, item.LatencyMS = false, 0
		item.Message = "Сеть изменилась или проверка отменена. Повторите проверку."
	}
	item.CheckedAt = time.Now().UTC()
	return item
}

func nodeCheckFailureMessage(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "Проверка остановлена."
	case errors.Is(err, dataplane.ErrExactNodeNetworkChanged):
		return "Сеть изменилась. Повторите проверку."
	case errors.Is(err, dataplane.ErrExactNodeBusy):
		return "Узел пропущен: выполняется другая точная проверка."
	case errors.Is(err, dataplane.ErrExactNodeRuntime):
		return "Для проверки сервиса нужен компонент Sing-box."
	case errors.Is(err, nodestore.ErrDisabled), errors.Is(err, nodestore.ErrNotFound):
		return "Узел отключён, удалён или срок его действия истёк."
	default:
		return "Проверка не завершена. Повторите после обновления списка."
	}
}
