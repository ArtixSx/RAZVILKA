package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/devices"
)

func TestDeviceListReportsPersistenceFailureWithoutBreakingArrayAPI(t *testing.T) {
	base := t.TempDir()
	cfg, err := config.Load(filepath.Join(base, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "devices.json")
	m, err := devices.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m.IPCommand = "ip"
	m.Runner = deviceRunner{output: "192.168.1.25 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"}
	m.ARPPaths = nil
	m.LeasePaths = nil
	a := &App{Store: cfg, Devices: m}
	target, err := devices.OpenRestoreTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	rec := httptest.NewRecorder()
	a.deviceList(rec, httptest.NewRequest(http.MethodGet, "/api/v1/devices?view=status", nil))
	var result struct {
		Devices []deviceView `json:"devices"`
		Warning string       `json:"persistence_warning"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
		t.Fatal("status envelope invalid")
	}
	if len(result.Devices) != 1 || !result.Devices[0].Discovered || !strings.Contains(result.Warning, "не подтверждено") {
		t.Fatal("persistence failure hidden")
	}
	if strings.Contains(rec.Body.String(), base) || len(m.Known()) != 0 {
		t.Fatal("private path leaked or unsaved cache confirmed")
	}
	rec = httptest.NewRecorder()
	a.deviceList(rec, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))
	var legacy []deviceView
	if json.Unmarshal(rec.Body.Bytes(), &legacy) != nil || len(legacy) != 1 {
		t.Fatal("legacy array API broken")
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	a.deviceList(rec, httptest.NewRequest(http.MethodGet, "/api/v1/devices?view=status", nil))
	if json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Warning != "" {
		t.Fatal("warning not cleared after retry")
	}
	if rows, err := m.ListWithStatus(context.Background()); err != nil || len(rows) != 1 {
		t.Fatal("retry did not persist")
	}
}
