package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/devices"
)

type deviceBrowseNoCommands struct{}

func (deviceBrowseNoCommands) Run(context.Context, string, ...string) ([]byte, error) {
	panic("device browse invoked discovery")
}

func deviceBrowseFixture(t *testing.T) *App {
	t.Helper()
	a := savedPanelFixture(t)
	m, err := devices.Load(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Establish one real manager observation using only the fixture runner.
	m.IPCommand, m.ARPPaths, m.LeasePaths = "ip", nil, nil
	m.Runner = deviceRunner{output: "192.168.1.25 dev br0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"}
	rows, err := m.ListWithStatus(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatal("fixture discovery failed", err)
	}
	if _, err := m.Update(rows[0].ID, "Living room", "Home"); err != nil {
		t.Fatal(err)
	}
	m.Runner = deviceBrowseNoCommands{}
	a.Devices = m
	return a
}

func TestPanelDeviceBrowseKnownOnlyDetachedAllowlist(t *testing.T) {
	a := deviceBrowseFixture(t)
	m := a.Devices
	before, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	// Publishing must work even while the persistent target is held by someone
	// else: Known is not a private-file read, discovery, or persistence attempt.
	locked, err := devices.OpenRestoreTarget(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	now := time.Now()
	if !a.publishPanelDeviceBrowse(context.Background(), strings.Repeat("a", 32), now) {
		t.Fatal("memory publication failed")
	}
	first := a.panelDeviceBrowseAt(now)
	var data panelDeviceBrowseData
	if json.Unmarshal(first.Data, &data) != nil || len(data.Devices) != 1 {
		t.Fatal("missing saved device")
	}
	row := data.Devices[0]
	if row.Name != "Living room" || row.Group != "Home" || row.Interface != "br0" ||
		len(row.KnownAddresses) != 1 || row.KnownAddresses[0] != "192.168.1.25" || row.LastSeenAt == "" {
		t.Fatal("saved metadata lost", row)
	}
	var fields map[string][]map[string]json.RawMessage
	if json.Unmarshal(first.Data, &fields) != nil {
		t.Fatal("invalid DTO")
	}
	allowed := map[string]bool{"id": true, "name": true, "group": true, "hostname": true,
		"known_addresses": true, "interface": true, "last_seen_at": true}
	for field := range fields["devices"][0] {
		if !allowed[field] {
			t.Fatal("unexpected device/proof/authority field", field)
		}
	}
	if strings.Contains(string(first.Data), "aa:bb:cc:dd:ee:ff") {
		t.Fatal("unrequested MAC exposed")
	}
	after, err := os.ReadFile(m.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("publication persisted metadata", err)
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	// A later legitimate metadata save cannot mutate the already encoded image.
	known := m.Known()
	known[0].IPs[0] = "192.168.1.99"
	if _, err := m.Update(row.ID, "Renamed", "Other"); err != nil {
		t.Fatal(err)
	}
	var retained panelDeviceBrowseData
	if json.Unmarshal(a.panelDeviceBrowseAt(now).Data, &retained) != nil || retained.Devices[0].Name != "Living room" || retained.Devices[0].KnownAddresses[0] != "192.168.1.25" {
		t.Fatal("mutable saved image")
	}
	// Even the publication path has no dependency on a readable registry path.
	m.Path = filepath.Join(t.TempDir(), "missing", "devices.json")
	if !a.publishPanelDeviceBrowse(context.Background(), strings.Repeat("a", 32), now.Add(time.Second)) || a.panelDeviceBrowseAt(now.Add(time.Second)).Revision != 2 {
		t.Fatal("publication depended on disk")
	}
	if _, err := os.Stat(filepath.Dir(m.Path)); !os.IsNotExist(err) {
		t.Fatal("publication created a directory", err)
	}
}

func TestPanelDeviceBrowseBusyFailureExpiryAndLimits(t *testing.T) {
	a := deviceBrowseFixture(t)
	now := time.Now()
	if !a.publishPanelDeviceBrowse(context.Background(), strings.Repeat("a", 32), now) {
		t.Fatal("initial publication")
	}
	first := a.panelSnapshots.devices.Load()
	for _, tc := range []struct {
		offset time.Duration
		state  string
		data   bool
	}{{0, "available", true}, {10 * time.Second, "retained", true}, {panelDeviceBrowseLifetime, "expired", false}, {-2 * time.Second, "expired", false}} {
		value := a.panelDeviceBrowseAt(now.Add(tc.offset))
		if value.State != tc.state || (len(value.Data) > 0) != tc.data || value.MaxAgeSeconds != 900 || value.DataAgeMS < 0 || value.Dataplane != "not-checked" {
			t.Fatal("invalid freshness envelope", tc, value)
		}
	}
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if a.publishPanelDeviceBrowse(context.Background(), "replacement", now) || a.panelDeviceBrowseAt(now).State != "retained" || a.panelSnapshots.devices.Load() != first {
		t.Fatal("busy publisher replaced the saved image")
	}
	release()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if a.publishPanelDeviceBrowse(canceled, "replacement", now) {
		t.Fatal("canceled capture published")
	}
	m := a.Devices
	a.Devices = nil
	if a.publishPanelDeviceBrowse(context.Background(), "replacement", now) || a.panelSnapshots.devices.Load() != first {
		t.Fatal("missing manager replaced saved registry with empty list")
	}
	a.Devices = m
	large := make([]devices.Device, 512)
	for i := range large {
		large[i] = devices.Device{ID: fmt.Sprintf("device-%03d", i), Name: strings.Repeat("n", 80),
			Group: strings.Repeat("g", 64), Hostname: strings.Repeat("h", 253), Interface: strings.Repeat("i", 32)}
	}
	if err := m.ReplaceAll(large); err != nil {
		t.Fatal(err)
	}
	if a.publishPanelDeviceBrowse(context.Background(), "replacement", now) || a.panelSnapshots.devices.Load() != first {
		t.Fatal("oversized image replaced last usable publication")
	}
	a.Operations.FenceJournal()
	if a.publishPanelDeviceBrowse(context.Background(), "replacement", now) || a.panelDeviceBrowseAt(now).State != "retained" || a.panelSnapshots.devices.Load() != first {
		t.Fatal("fenced publication changed")
	}
	empty := (&App{}).panelDeviceBrowseAt(now)
	encoded, _ := json.Marshal(empty)
	if empty.State != "empty" || empty.GeneratedAt != nil || len(empty.Data) != 0 || strings.Contains(string(encoded), `"data":`) {
		t.Fatal("missing publication pretends registry is empty")
	}
}

func TestPanelDeviceBrowseHTTPOnlyAtomicImageDuringBusyAndFence(t *testing.T) {
	a := deviceBrowseFixture(t)
	if !a.publishPanelDeviceBrowse(context.Background(), strings.Repeat("b", 32), time.Now()) {
		t.Fatal("initial publication")
	}
	// The HTTP handler must remain usable without any Store or device manager.
	a.Store, a.Devices = nil, nil
	release, err := a.Operations.Exclusive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	for _, fenced := range []bool{false, true} {
		if fenced {
			a.Operations.FenceJournal()
		}
		for _, method := range []string{"GET", "HEAD", "POST", "DELETE"} {
			for _, auth := range []bool{false, true} {
				request, _ := http.NewRequest(method, server.URL+panelDeviceBrowsePath, nil)
				request.Header.Set("Content-Type", "application/json")
				if auth {
					request.Header.Set("Authorization", "Bearer "+panelTestToken)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(response.Body)
				response.Body.Close()
				want := http.StatusOK
				if method != "GET" && method != "HEAD" {
					want = http.StatusMethodNotAllowed
				}
				if !auth {
					want = http.StatusUnauthorized
				}
				if response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal(method, auth, response.StatusCode, string(body))
				}
				if auth && method == "GET" {
					var value panelDeviceBrowseResponse
					if json.Unmarshal(body, &value) != nil || value.State != "retained" || value.Dataplane != "not-checked" || len(value.Data) == 0 || value.GeneratedAt == nil || value.ObservedAt.IsZero() {
						t.Fatal("saved image unavailable", string(body))
					}
				}
				if method == "HEAD" && len(body) != 0 {
					t.Fatal("HEAD returned a body")
				}
			}
		}
		for _, path := range []string{"/api/v1/devices", "/api/v1/devices?view=status", panelDeviceBrowsePath + "/", panelDeviceBrowsePath + "/extra"} {
			response := httptest.NewRecorder()
			a.Handler(http.NotFoundHandler()).ServeHTTP(response, panelTestRequest("GET", path))
			want := http.StatusConflict
			if fenced {
				want = http.StatusServiceUnavailable
			}
			if response.Code != want {
				t.Fatal("unexpected admission bypass", path, response.Code)
			}
		}
		if !a.Operations.Snapshot().Exclusive || a.Operations.Snapshot().Active != 1 {
			t.Fatal("browse request released the original owner")
		}
	}
	foreign := panelTestRequest("POST", panelDeviceBrowsePath)
	foreign.Header.Set("Content-Type", "application/json")
	foreign.Header.Set("Origin", "https://foreign.invalid")
	response := httptest.NewRecorder()
	a.Handler(http.NotFoundHandler()).ServeHTTP(response, foreign)
	if response.Code != http.StatusForbidden {
		t.Fatal("security middleware bypassed")
	}
	a.Security = nil
	response = httptest.NewRecorder()
	a.operationMiddleware(http.NotFoundHandler()).ServeHTTP(response, httptest.NewRequest("GET", panelDeviceBrowsePath, nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatal("unconfigured authentication exposed saved metadata")
	}
}

func TestPanelDeviceBrowseStartupWakeAndShutdown(t *testing.T) {
	a := deviceBrowseFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.StartPanelSnapshots(ctx)
	first := a.panelDeviceBrowseAt(time.Now())
	if first.Revision != 1 || first.InstanceID == "" || len(first.Data) == 0 {
		t.Fatal("startup did not seed device image synchronously")
	}
	// The ordinary panel wake must update this independent image too.
	deadline := time.Now().Add(time.Second)
	for a.panelDeviceBrowseAt(time.Now()).Revision <= first.Revision && time.Now().Before(deadline) {
		// Another short observer may win one attempt; wake again while it
		// finishes, rather than depending on the periodic two-second tick.
		a.wakePanelSnapshot()
		time.Sleep(time.Millisecond)
	}
	if a.panelDeviceBrowseAt(time.Now()).Revision <= first.Revision {
		t.Fatal("normal wake did not publish devices")
	}
	cancel()
	stop, cancelStop := context.WithTimeout(context.Background(), time.Second)
	defer cancelStop()
	if err := a.WaitPanelSnapshots(stop); err != nil {
		t.Fatal("publisher did not join", err)
	}
}
