package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/awgprofile"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/wireguardprofile"
)

const wireGuardProfilesPath = "/api/v1/wireguard/profiles"

type wireGuardProfileRequest struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Content          string `json:"content"`
	ExpectedRevision string `json:"expected_revision"`
}

type wireGuardProfileReference struct {
	Kind      string `json:"kind"`
	ServiceID string `json:"service_id,omitempty"`
}

type wireGuardProfileView struct {
	Profile    wireguardprofile.Metadata   `json:"profile"`
	Route      string                      `json:"route"`
	Reserve    bool                        `json:"reserve"`
	References []wireGuardProfileReference `json:"references"`
}

func (a *App) registerWireGuardProfileRoutes(mux *http.ServeMux) {
	mux.HandleFunc(wireGuardProfilesPath, a.wireGuardProfilesAPI)
	mux.HandleFunc(wireGuardProfilesPath+"/", a.wireGuardProfilesAPI)
}

func wireGuardProfileReferences(cfg config.Config, plans []dataplane.Plan, id string) []wireGuardProfileReference {
	route := "wireguard:" + id
	refs := []wireGuardProfileReference{}
	addServices := func(kind string, states map[string]config.ServiceState) {
		for service, state := range states {
			if state.Route == route {
				refs = append(refs, wireGuardProfileReference{Kind: kind, ServiceID: service})
			}
		}
	}
	addServices("draft", cfg.Services)
	addServices("applied", cfg.AppliedServices)
	addServices("suspended", cfg.ServiceControl.SuspendedServices)
	for service, selected := range cfg.ServiceControl.SuspendedRoutes {
		if selected == route {
			refs = append(refs, wireGuardProfileReference{Kind: "suspended-route", ServiceID: service})
		}
	}
	for _, policy := range []struct {
		kind  string
		value *config.NetworkPolicy
	}{{"network-draft", cfg.NetworkPolicy}, {"network-applied", cfg.AppliedNetworkPolicy}} {
		if policy.value != nil && policy.value.Traffic.DefaultRoute == route {
			refs = append(refs, wireGuardProfileReference{Kind: policy.kind})
		}
	}
	for index, plan := range plans {
		kind := "dataplane-pending"
		if index == 1 {
			kind = "dataplane-committed"
		}
		for _, selected := range plan.Routes {
			if selected.Resolved == route || selected.Selected == route || selected.AppliedRoute == route {
				refs = append(refs, wireGuardProfileReference{Kind: kind, ServiceID: selected.ServiceID})
			}
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Kind != refs[j].Kind {
			return refs[i].Kind < refs[j].Kind
		}
		return refs[i].ServiceID < refs[j].ServiceID
	})
	return refs
}

func (a *App) wireGuardProfilePlanViews(ctx context.Context) ([]dataplane.Plan, error) {
	if a.Dataplane == nil || a.Dataplane.StateRoot == "" {
		return nil, errors.New("WireGuard reference journal unavailable")
	}
	latest, _, err := a.Dataplane.Latest()
	if err != nil {
		return nil, err
	}
	committed, _, err := a.Dataplane.Committed()
	if err != nil {
		return nil, err
	}
	if err := a.Dataplane.CheckWireGuardProfileReferenceAuthority(ctx, committed); err != nil {
		return nil, err
	}
	return []dataplane.Plan{latest, committed}, nil
}

func (a *App) wireGuardProfilesAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if a.Security == nil || !a.Security.Authenticated(r) {
		writeJSON(w, 401, map[string]any{"error": "Требуется авторизация."})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, wireGuardProfilesPath)
	if id != "" {
		if !strings.HasPrefix(id, "/") {
			http.NotFound(w, r)
			return
		}
		id = strings.TrimPrefix(id, "/")
		if !wireguardprofile.ValidID(id) {
			http.NotFound(w, r)
			return
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		methodNotAllowed(w)
		return
	}
	if a.Store == nil || a.Dataplane == nil {
		writeJSON(w, 503, map[string]any{"error": "Каталог профилей или настройки недоступны."})
		return
	}
	catalog, err := a.Dataplane.WireGuardProfileCatalog()
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "Каталог WG не подключён к исполнителю."})
		return
	}
	var request wireGuardProfileRequest
	if r.Method != http.MethodGet {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeJSON(w, 400, map[string]any{"error": "Неверное тело запроса."})
			return
		}
		if r.Method == http.MethodPost && id == "" {
			id = request.ID
		} else if request.ID != "" && request.ID != id {
			writeJSON(w, 400, map[string]any{"error": "ID профиля не совпадает с адресом запроса."})
			return
		}
		if !wireguardprofile.ValidID(id) || r.Method == http.MethodPost && request.ExpectedRevision != "" || r.Method != http.MethodPost && request.ExpectedRevision == "" {
			writeJSON(w, 400, map[string]any{"error": "Укажите корректный профиль и его текущую редакцию."})
			return
		}
		if r.Method == http.MethodDelete && (request.Name != "" || request.Content != "") {
			writeJSON(w, 400, map[string]any{"error": "Удаление принимает только ID и редакцию профиля."})
			return
		}
		if r.Method != http.MethodDelete {
			name := strings.TrimSpace(request.Name)
			_, profileErr := awgprofile.ParsePlainWireGuard(request.Content)
			if name == "" || len(name) > 160 || strings.ContainsAny(name, "\x00\r\n") || profileErr != nil {
				writeJSON(w, 400, map[string]any{"error": "Неверное имя или содержимое профиля WG."})
				return
			}
		}
		release, err := a.privateRestoreAdmission(r.Context())
		if err != nil {
			a.writeOperationFailure(w, err)
			return
		}
		defer release()
	}
	// Hold the existing full-image writer/file lease throughout the catalog
	// mutation. Never call this Store's Get/Update while the lease owns its lock.
	session, err := a.Store.BeginRestore(r.Context())
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": "Полное состояние ссылок не подтверждено. Повторите чтение."})
		return
	}
	closed := false
	defer func() {
		if !closed {
			_ = session.Close()
		}
	}()
	image, err := session.Read(r.Context())
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": "Настройки изменились. Повторите чтение."})
		return
	}
	cfg, _, err := config.InspectBytes(image.Data)
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": "Полное состояние ссылок не подтверждено."})
		return
	}
	plans, err := a.wireGuardProfilePlanViews(r.Context())
	if err != nil {
		writeJSON(w, 409, map[string]any{"error": "Текущий или ожидающий план WG не подтверждён."})
		return
	}
	view := func(meta wireguardprofile.Metadata) wireGuardProfileView {
		refs := wireGuardProfileReferences(cfg, plans, meta.ID)
		return wireGuardProfileView{Profile: meta, Route: "wireguard:" + meta.ID, Reserve: len(refs) == 0, References: refs}
	}
	finish := func() error {
		current, err := a.wireGuardProfilePlanViews(r.Context())
		if err == nil && !reflect.DeepEqual(current, plans) {
			err = errors.New("WireGuard plan changed")
		}
		closeErr := session.Close()
		closed = true
		return errors.Join(err, closeErr)
	}
	if r.Method == http.MethodGet {
		if id == "" {
			profiles, err := catalog.List(r.Context())
			if err != nil {
				writeJSON(w, 503, map[string]any{"error": "Каталог профилей недоступен."})
				return
			}
			out := make([]wireGuardProfileView, 0, len(profiles))
			for _, meta := range profiles {
				out = append(out, view(meta))
			}
			if finish() != nil {
				writeJSON(w, 409, map[string]any{"error": "Ссылки изменились. Повторите чтение."})
				return
			}
			writeJSON(w, 200, map[string]any{"profiles": out, "config_revision": cfg.Revision})
			return
		}
		profile, err := catalog.Get(r.Context(), id)
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			writeJSON(w, 409, map[string]any{"error": "Профиль не принадлежит этому каталогу или повреждён."})
			return
		}
		out := view(profile.Public())
		if finish() != nil {
			writeJSON(w, 409, map[string]any{"error": "Ссылки изменились. Повторите чтение."})
			return
		}
		writeJSON(w, 200, out)
		return
	}
	old, oldErr := catalog.Get(r.Context(), id)
	if oldErr != nil && !errors.Is(oldErr, os.ErrNotExist) {
		writeJSON(w, 409, map[string]any{"error": "Существующий профиль не подтверждён."})
		return
	}
	var undo func(context.Context) error
	if r.Method == http.MethodDelete {
		refs := wireGuardProfileReferences(cfg, plans, id)
		if len(refs) != 0 {
			writeJSON(w, 409, map[string]any{"error": "Профиль используется в настройках или сохранённом плане. Сначала снимите ссылки.", "references": refs})
			return
		}
		if err = catalog.Delete(r.Context(), id, request.ExpectedRevision); err != nil {
			if errors.Is(err, wireguardprofile.ErrRevision) || errors.Is(err, wireguardprofile.ErrForeign) || errors.Is(err, os.ErrNotExist) {
				writeJSON(w, 409, map[string]any{"error": "Редакция профиля изменилась; удаление отклонено."})
			} else {
				writeJSON(w, 503, map[string]any{"error": "Удаление не подтверждено. Повторите чтение профиля.", "outcome": "unconfirmed"})
			}
			return
		}
		undo = func(c context.Context) error {
			_, err := catalog.Put(c, id, old.Public().Name, old.Config(), "")
			return err
		}
	} else {
		meta, err := catalog.Put(r.Context(), id, request.Name, request.Content, request.ExpectedRevision)
		if err != nil {
			if errors.Is(err, wireguardprofile.ErrRevision) || errors.Is(err, wireguardprofile.ErrForeign) {
				writeJSON(w, 409, map[string]any{"error": "Профиль отклонён или его редакция изменилась."})
			} else {
				writeJSON(w, 503, map[string]any{"error": "Запись не подтверждена. Повторите чтение профиля.", "outcome": "unconfirmed"})
			}
			return
		}
		undo = func(c context.Context) error {
			if oldErr == nil {
				_, err := catalog.Put(c, id, old.Public().Name, old.Config(), meta.Revision)
				return err
			}
			return catalog.Delete(c, id, meta.Revision)
		}
		if finish() == nil {
			writeJSON(w, 200, map[string]any{"saved": true, "live_applied": false, "profile": view(meta)})
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 4*time.Second)
		defer cancel()
		undoErr := undo(cleanup)
		writeJSON(w, 409, map[string]any{"error": "Ссылки изменились после записи. Результат не подтверждён; повторите чтение профиля.", "outcome": "unconfirmed", "restoration_confirmed": undoErr == nil})
		return
	}
	if finish() != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 4*time.Second)
		defer cancel()
		undoErr := undo(cleanup)
		writeJSON(w, 409, map[string]any{"error": "Ссылки изменились после удаления. Результат не подтверждён; повторите чтение профиля.", "outcome": "unconfirmed", "restoration_confirmed": undoErr == nil})
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "live_applied": false})
}
