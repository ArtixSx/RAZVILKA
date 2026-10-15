package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engine"
)

func doctorFixture(t *testing.T, online, nfqRunning bool) *App {
	t.Helper()
	a := &App{}
	store, err := config.Load(t.TempDir() + "/config.json")
	if err != nil {
		t.Fatal(err)
	}
	a.Store = store
	if err := store.UpdateService("youtube", config.ServiceState{Enabled: true, Route: "nfqws2"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	a.autonomy.doc.Policy = autonomy.Default()
	a.autonomy.doc.Policy.SetupComplete, a.autonomy.doc.Policy.Enabled = true, true
	a.autonomy.doc.Services = map[string]autonomy.Service{"youtube": {ID: "youtube", Enabled: true}, "discord": {ID: "discord", Enabled: true}}
	a.autonomy.doc.Runtime = map[string]autonomy.Runtime{"youtube": {State: "healthy"}, "discord": {State: "apply-refused", Message: "Не удалось включить."}}
	a.autonomy.loaded = true
	fail := errors.New("no route")
	a.doctorProbes = doctorProbes{
		dial: func(context.Context, string) error {
			if online {
				return nil
			}
			return fail
		},
		resolve: func(context.Context, string) error {
			if online {
				return nil
			}
			return fail
		},
		engines: func() []engine.Status { return []engine.Status{{ID: "nfqws2", Name: "NFQWS2", Running: nfqRunning}} },
	}
	return a
}

func TestPanelDoctorNamesTheFirstProblemInPlainGroups(t *testing.T) {
	a := doctorFixture(t, true, true)
	w := httptest.NewRecorder()
	a.panelDoctor(w, httptest.NewRequest(http.MethodGet, panelDoctorPath, nil))
	var report doctorReport
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &report) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	got := map[string]string{}
	for _, c := range report.Checks {
		got[c.ID] = c.Status
	}
	want := map[string]string{"internet": "ok", "dns": "ok", "razvilka": "ok", "engines": "ok", "services": "fail"}
	for id, status := range want {
		if got[id] != status {
			t.Fatalf("%s: %s, want %s (%+v)", id, got[id], status, report.Checks)
		}
	}
	if report.Status != "fail" {
		t.Fatal(report.Status)
	}
	offline := doctorFixture(t, false, false).doctorAt(context.Background(), doctorFixture(t, false, false).doctorProbes, time.Now())
	if offline.Checks[0].Status != "fail" || offline.Checks[1].Status != "fail" || offline.Checks[3].Status != "fail" {
		t.Fatalf("offline router: %+v", offline.Checks)
	}
	if w := httptest.NewRecorder(); true {
		a.panelDoctor(w, httptest.NewRequest(http.MethodPost, panelDoctorPath, nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatal("doctor accepted a write", w.Code)
		}
	}
}
