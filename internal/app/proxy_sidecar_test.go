package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
)

type proxySidecarInactiveModel struct {
	nodeApplyAdapter
	calls  int
	refuse bool
	hook   func()
}

func (a *proxySidecarInactiveModel) VerifyRuntimeInactive(context.Context) error {
	a.calls++
	if a.hook != nil {
		a.hook()
	}
	if a.refuse {
		return dataplane.ErrRuntimeInactivity
	}
	return nil
}

func TestProxySidecarAPIFreshInactiveAndClosingRevision(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	a.Dataplane = dataplane.New(t.TempDir())
	observer := &proxySidecarInactiveModel{}
	if err := a.Dataplane.Register(observer); err != nil {
		t.Fatal(err)
	}
	put := func() *httptest.ResponseRecorder {
		cfg := a.Store.Get()
		body, _ := json.Marshal(map[string]any{"backend": "sing-box", "expected_revision": cfg.Revision})
		w := httptest.NewRecorder()
		a.proxySidecar(w, httptest.NewRequest(http.MethodPut, "/api/v1/runtime/proxy-sidecar", strings.NewReader(string(body))))
		return w
	}
	observer.hook = func() {
		if err := a.Store.UpdateService("youtube", config.ServiceState{Enabled: false, Route: "direct"}); err != nil {
			t.Fatal(err)
		}
	}
	if w := put(); w.Code != 409 || a.Store.Get().ProxySidecar != "" {
		t.Fatal("closing revision raced boot choice", w.Code, w.Body.String())
	}
	observer.hook = nil
	if w := put(); w.Code != 200 || observer.calls < 2 {
		t.Fatal("genuinely unused intent unnecessarily required first Apply", w.Code, w.Body.String())
	}
	if a.Store.Get().ServiceControl.Stopped {
		t.Fatal("selection implicitly stopped services")
	}
}

func TestProxySidecarAPIReadNeverGrantsLiveReadiness(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	before := a.Store.Get()
	w := httptest.NewRecorder()
	a.proxySidecar(w, httptest.NewRequest(http.MethodGet, "/api/v1/runtime/proxy-sidecar", nil))
	var view map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	if view["available"] != nil || view["live_applied"] != false || view["backend"] != "sing-box" || view["restart_required"] != false {
		t.Fatal(view)
	}
	if a.Store.Get().Revision != before.Revision {
		t.Fatal("GET persisted state")
	}
}
func TestProxySidecarAPIPreservesStoppedOwnerAdmission(t *testing.T) {
	a, _ := privateRestoreTestApp(t)
	a.Dataplane = dataplane.New(t.TempDir())
	observer := &proxySidecarInactiveModel{}
	if err := a.Dataplane.Register(observer); err != nil {
		t.Fatal(err)
	}
	send := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.proxySidecar(w, httptest.NewRequest(http.MethodPut, "/api/v1/runtime/proxy-sidecar", strings.NewReader(body)))
		return w
	}
	if err := a.Store.UpdateService("telegram", config.ServiceState{Enabled: true, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	cfg := a.Store.Get()
	body := func(backend string) string {
		b, _ := json.Marshal(map[string]any{"backend": backend, "expected_revision": a.Store.Get().Revision})
		return string(b)
	}
	if w := send(body("sing-box")); w.Code != 409 || observer.calls != 0 {
		t.Fatal("running selection admitted", w.Code, observer.calls)
	}
	if _, err := a.Store.CommitServiceRuntime(true, map[string]string{"telegram": "direct", "youtube": "nfqws2"}, cfg.Revision); err != nil {
		t.Fatal(err)
	}
	observer.refuse = true
	if w := send(body("sing-box")); w.Code != 409 || observer.calls == 0 {
		t.Fatal("unknown owner promoted", w.Code, observer.calls)
	}
	observer.refuse = false
	if w := send(body("hev")); w.Code != 409 {
		t.Fatal("HEV without original component receipt admitted", w.Code, w.Body.String())
	}
	// The only model-positive path saves an explicit standard backend choice;
	// actual Linux process/kernel admission is covered by existing native owners.
	if w := send(body("sing-box")); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if a.ProxySidecarBoot != "" || a.Store.Get().ProxySidecar != "sing-box" {
		t.Fatal("PUT mutated boot adapter")
	}
	if w := send(`{"backend":"auto","expected_revision":0}`); w.Code != 400 {
		t.Fatal("unknown enum accepted", w.Code)
	}
}
